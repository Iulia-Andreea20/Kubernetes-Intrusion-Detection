#!/usr/bin/env python3
"""Build the reference dataset: kube-audit events from Log Analytics -> 20-event windows -> features.

Every window is tagged with the tool that produced it (synthetic, stratus, rakkess, peirates, ...)
so the evaluation can hold out a whole tool rather than a random slice - the only split that shows
whether the model learned the technique or the script that ran it.

Session boundaries come from sessions.txt, which the collection scripts append to as they run.
The feature code below is mirrored in service/audit/audit_xgb_service.py; the two must not drift.
"""
import subprocess, json, csv, sys, os
from collections import defaultdict, deque
OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reference"))
# A rebuilt cluster gets a brand new workspace id, so this is read from the environment;
# setup_aks.sh writes the current one into cluster/aks/env.generated.
CID = os.environ.get("LA_WORKSPACE_ID", "39628155-ae16-4624-90d3-41d58489f713")
SELF_REVIEW = {"selfsubjectaccessreviews","selfsubjectrulesreviews"}
RBAC = {"clusterroles","clusterrolebindings","roles","rolebindings"}
SEQ = 20
ATTACK_SYN = ["victim-sa","adversary-external","adversary-insider","recon-sa"]
# Identity naming carries the label. Synthetic attackers are prefixed adversary-*, real
# third-party tools redteam-*, and the tool name decides which side of the split a window
# lands on: synthetic tactics train, the external tools stay held out.
def tool_of(u):
    if "redteam-stratus" in u or "stratus-red-team" in u: return "stratus"
    if "redteam-rakkess" in u: return "rakkess"
    if "redteam-peirates" in u or "peirates" in u: return "peirates"
    if "adversary-stealth" in u: return "lowslow"       # escalation, paced out thin
    if "adversary-creddump" in u: return "credsyn"      # credential access, pairs with Stratus dump
    if "adversary-persistsyn" in u: return "persistsyn" # persistence via CSR/token/CRB
    if "adversary-imp" in u: return "impact"
    if "adversary-eva" in u: return "evasion"
    if "adversary-lat" in u: return "lateral"           # impersonation
    if "redteam-persist" in u: return "persistence"
    if "redteam-lat-ext" in u: return "lateralext"      # token reuse
    if "adversary-escv" in u: return "escv"             # escalation, behaviourally varied
    if "compromised-ctrl" in u: return "compromised"    # a kube-system identity gone bad
    return "synthetic"
def is_attack(u):
    return tool_of(u) in ("stratus","rakkess","peirates","lowslow","impact","evasion","lateral","persistence","lateralext","escv","compromised","credsyn","persistsyn") or any(k in u for k in ATTACK_SYN)

def q_window(start, end):
    KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
           f"| where TimeGenerated between (datetime({start})..datetime({end})) "
           f"| project TimeGenerated, log_s | order by TimeGenerated asc")
    for _ in range(4):
        r = subprocess.run(["az","rest","--method","post","--url",
            f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
            "--headers","Content-Type=application/json","--body", json.dumps({"query": KQL})],
            capture_output=True, text=True)
        if r.returncode==0 and r.stdout.strip():
            try: return json.loads(r.stdout)["tables"][0]["rows"]
            except Exception: pass
        import time; time.sleep(5)
    print("  !! query failed:", (r.stderr or "")[-150:]); return []

# sessions.txt holds one "SESSION <i> START|END <ts>" line per collection run.
spans = []
sf = open(OUT + "/sessions.txt").read().splitlines() if __import__("os").path.exists(OUT+"/sessions.txt") else []
cur = {}
for ln in sf:
    p = ln.split()
    if len(p)>=4 and p[0]=="SESSION":
        i=int(p[1])
        if p[2]=="START": cur[i]=[p[3]]
        elif p[2]=="END" and i in cur: cur[i].append(p[3]); spans.append((i,cur[i][0],cur[i][1]))
print(f">> {len(spans)} sessions in sessions.txt")
def which_session(ts):
    for i,s,e in spans:
        if s<=ts<=e: return i
    return None

rows=[]
for i,s,e in spans:
    rr=q_window(s,e); rows.extend(rr); print(f"  session {i}: {len(rr)} events")
print(f">> {len(rows)} raw events")

seen=set(); streams=defaultdict(list)
for ts,log in rows:
    try: ev=json.loads(log)
    except: continue
    aid=ev.get("auditID")
    if aid and aid in seen: continue
    if aid: seen.add(aid)
    si=which_session(ts)
    if si is None: continue
    real=(ev.get("user") or {}).get("username","")
    imp=((ev.get("impersonatedUser") or {}).get("username") or "")
    is_imp=1 if (imp and imp!=real) else 0
    # Window on the authenticated identity, not the impersonated one. Keying on the victim
    # would scatter an impersonation attack across the identities it borrows and hide it.
    a=real or imp
    o=ev.get("objectRef") or {}; ann=ev.get("annotations") or {}
    streams[(si,a)].append({"verb":ev.get("verb",""),"resource":o.get("resource",""),"sub":o.get("subresource",""),
        "ns":o.get("namespace",""),"code":(ev.get("responseStatus") or {}).get("code",0),
        "decision":ann.get("authorization.k8s.io/decision",""),"imp":imp if is_imp else "","is_imp":is_imp})

WORKLOAD={"deployments","daemonsets","replicasets","statefulsets","jobs","cronjobs","pods","replicationcontrollers"}
def sec_read(x): return x["resource"]=="secrets" and x["verb"] in ("get","list","watch")
def rbac_w(x): return x["resource"] in RBAC and x["verb"] in ("create","update","patch","delete")
def crb_c(x): return x["resource"] in ("clusterrolebindings","clusterroles") and x["verb"]=="create"
def wl_create(x): return x["verb"]=="create" and x["resource"] in WORKLOAD
def is_csr(x): return x["resource"]=="certificatesigningrequests"
def is_tokenreq(x): return x["verb"]=="create" and x["resource"]=="serviceaccounts" and x["sub"]=="token"
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
def featurize(evs):
    h=deque(maxlen=SEQ); cum=dict(sec=0,rbw=0,exe=0,crb=0); out=[]
    for x in evs:
        h.append(x)
        cum["sec"]+=sec_read(x); cum["rbw"]+=rbac_w(x); cum["exe"]+=(x["sub"]=="exec"); cum["crb"]+=crb_c(x)
        n=len(h); nf=sum(1 for y in h if y["decision"]=="forbid")
        nsec=sum(1 for y in h if y["resource"]=="secrets"); nrb=sum(1 for y in h if y["resource"] in RBAC)
        ncr=sum(1 for y in h if y["verb"]=="create"); nsr=sum(1 for y in h if y["verb"]=="create" and y["resource"] in SELF_REVIEW)
        nexe=sum(1 for y in h if y["sub"]=="exec")
        sns=len({y["ns"] for y in h if sec_read(y)})
        old=[round(nf/n,3),nf,n,len(set(y["resource"] for y in h)),len(set(y["verb"] for y in h)),len(set(y["ns"] for y in h)),
             nsec,nexe,nrb,ncr,sum(1 for y in h if y["verb"]=="delete"),sum(1 for y in h if y["verb"]=="list"),
             sum(1 for y in h if isinstance(y["code"],int) and y["code"]>=400),nsr,round(nsr/n,3) if n>=SEQ else 0.0]
        hcrb=int(any(crb_c(y) for y in h)); hexe=int(nexe>0); hrw=int(any(rbac_w(y) for y in h))
        himp=int(any(y["is_imp"] for y in h)); nimp=len({y["imp"] for y in h if y["is_imp"]})
        ncw=sum(1 for y in h if wl_create(y))
        hcsr=int(any(is_csr(y) for y in h)); htok=int(any(is_tokenreq(y) for y in h))
        new=[int(any(sec_read(y) for y in h)),hexe,hrw,hcrb,int(nf>0),round(nsec/n,3),round(nrb/n,3),round(ncr/n,3),
             sns,3*hcrb+2*hexe+2*(sns>=2)+hrw+2*himp,cum["sec"],cum["rbw"],cum["exe"],cum["crb"],himp,nimp,ncw,hcsr,htok]
        out.append(old+new)
    return out

__import__("os").makedirs(OUT, exist_ok=True)
with open(OUT+"/ref_v2_all.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["label"]+OLD+NEW+["user","tool","session"])
    n_rows=0; by_tool=defaultdict(int)
    for (si,a),evs in streams.items():
        lab=1 if is_attack(a) else 0; t=tool_of(a)
        for fv in featurize(evs):
            w.writerow([lab]+fv+[a,t,si]); n_rows+=1; by_tool[t]+=1
print(f">> wrote {OUT}/ref_v2_all.csv: {n_rows} windows | by tool: {dict(by_tool)}")
print(f">> {len(OLD)+len(NEW)} features per window")
