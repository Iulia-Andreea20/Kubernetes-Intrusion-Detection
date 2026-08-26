#!/usr/bin/env python3
"""Export multi-sesiune cu split SESIUNE-DISJOINT (sesiuni întregi în test, nevăzute la train).
Include low-and-slow (adversary-insider) în train -> întărire vs evaziune. Scrie ref_train.csv + ref_test.csv.
"""
import json, os, subprocess, sys, csv
from collections import deque, defaultdict
from pathlib import Path

HERE = Path(__file__).parent; DS = HERE.parents[2] / "data/legacy/reference_dataset"
CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = 20
ATTACK = {"system:serviceaccount:default:victim-sa", "adversary-external", "adversary-insider",
          "system:serviceaccount:default:recon-sa"}
RBAC = {"clusterroles", "clusterrolebindings", "roles", "rolebindings"}
# SELF permission-probing = semnal de recon. EXCLUDE deliberat subjectaccessreviews/localsubjectaccessreviews
# (acelea = authz DELEGAT de apiserver pt metrics-server/node = benign, alt actor/cale).
SELF_REVIEW = {"selfsubjectaccessreviews", "selfsubjectrulesreviews"}
# NOTĂ: am ELIMINAT (după verificare adversarială) n_distinct_srcip (leakage: artefact de fereastră/concurență,
# toate atacurile srcip=1; ablație = metrici identice) și selfreview_burst_max (confound de tip-client: kubectl
# can-i intercalează un GET de discovery -> burst=1 la TOȚI actorii kubectl, inutil pt recon).
FEATS = ["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns",
         "n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx",
         "n_selfreview","selfreview_ratio"]

# sesiuni
sess = {}
for line in open(DS / "sessions.txt"):
    p = line.split()
    if len(p) >= 4 and p[0] == "SESSION":
        sess.setdefault(p[1], {})[p[2].lower()] = p[3][:19]
ids = sorted(sess, key=int)
spans = [(i, sess[i]["start"], sess[i]["end"]) for i in ids if "start" in sess[i] and "end" in sess[i]]
gmin = min(s for _, s, _ in spans); gmax = max(e for _, _, e in spans)
cut = max(int(len(spans) * 0.7), 1)
train_ids = {i for i, _, _ in spans[:cut]}; test_ids = {i for i, _, _ in spans[cut:]}
print(f">> {len(spans)} sesiuni; train={sorted(train_ids,key=int)} test={sorted(test_ids,key=int)}")

def which_session(ts):
    t = ts[:19]
    for i, s, e in spans:
        if s <= t <= e: return i
    return None

def q_window(start, end):  # interogare LA pe o fereastră (CHUNK) — evită plafonul ~64MB/răspuns
    KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
           f"| where TimeGenerated between (datetime({start}Z) .. datetime({end}Z)) "
           f"| project TimeGenerated, log_s | order by TimeGenerated asc")
    r = subprocess.run(["az","rest","--method","post",
        "--url", f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
        "--headers","Content-Type=application/json","--body", json.dumps({"query": KQL})], capture_output=True, text=True)
    if r.returncode != 0: print("!! az rest:", r.stderr[-300:]); return []
    return json.loads(r.stdout)["tables"][0]["rows"]

rows = []  # CHUNK pe sesiune: 24 interogări mici în loc de una uriașă (care trunchia coada = test gol)
for i, st, en in spans:
    rr = q_window(st, en); rows.extend(rr)
print(f">> {len(rows)} evenimente brute (chunked pe {len(spans)} sesiuni)")

seen=set(); streams=defaultdict(list)  # (session, actor) -> events
for ts, log in rows:
    try: e=json.loads(log)
    except: continue
    aid=e.get("auditID")
    if aid and aid in seen: continue
    if aid: seen.add(aid)
    si=which_session(ts)
    if si is None: continue
    a=((e.get("impersonatedUser") or {}).get("username")) or (e.get("user") or {}).get("username","")
    o=e.get("objectRef") or {}; ann=e.get("annotations") or {}
    streams[(si,a)].append({"verb":e.get("verb",""),"resource":o.get("resource",""),"sub":o.get("subresource",""),
        "ns":o.get("namespace",""),"sourceIP":(e.get("sourceIPs") or [""])[0],
        "code":(e.get("responseStatus") or {}).get("code",0),"decision":ann.get("authorization.k8s.io/decision","")})

def feats(h):
    n=len(h); nf=sum(1 for x in h if x["decision"]=="forbid")
    nsr=sum(1 for x in h if x["verb"]=="create" and x["resource"] in SELF_REVIEW)  # volum probing self-permisiuni
    sr_ratio = round(nsr/n,3) if n>=SEQ_LEN else 0.0  # densitate; gardă: 0 pe ferestre neîntregi
    return [round(nf/n,3),nf,n,len(set(x["resource"] for x in h)),len(set(x["verb"] for x in h)),
        len(set(x["ns"] for x in h)),sum(1 for x in h if x["resource"]=="secrets"),
        sum(1 for x in h if x["sub"]=="exec"),sum(1 for x in h if x["resource"] in RBAC),
        sum(1 for x in h if x["verb"]=="create"),sum(1 for x in h if x["verb"]=="delete"),
        sum(1 for x in h if x["verb"]=="list"),sum(1 for x in h if isinstance(x["code"],int) and x["code"]>=400),
        nsr, sr_ratio]

def profile(a):  # maparea actor-atac -> profil TTP (pt stratificare)
    if "victim-sa" in a: return "stolen-token"
    if "recon-sa" in a: return "recon"
    if a == "adversary-external": return "valid-abuse"
    if a == "adversary-insider": return "low-and-slow"
    return None

train, test = [], []
ep_tr, ep_te = defaultdict(set), defaultdict(set)  # profil -> {(session,actor)} episoade de atac
for (si, a), evs in streams.items():
    hist=deque(maxlen=SEQ_LEN); rows_out=(train if si in train_ids else test)
    lab=1 if a in ATTACK else 0
    if lab==1:
        pr=profile(a); (ep_tr if si in train_ids else ep_te)[pr].add((si,a))
    for x in evs:
        hist.append(x); rows_out.append([lab]+feats(hist)+[a])

# AERȚIUNE STRATIFICARE (porță hard): fiecare profil în AMBELE jumătăți + recon >=4 episoade test
print(">> episoade atac TRAIN:", {k:len(v) for k,v in ep_tr.items()})
print(">> episoade atac TEST :", {k:len(v) for k,v in ep_te.items()})
PROFILES = {"stolen-token","recon","valid-abuse","low-and-slow"}
missing_tr = PROFILES - set(ep_tr); missing_te = PROFILES - set(ep_te)
assert not missing_tr, f"profil(e) lipsă din TRAIN: {missing_tr}"
assert not missing_te, f"profil(e) lipsă din TEST: {missing_te}"
assert len(ep_te.get("recon", set())) >= 4, f"recon test episoade < 4: {len(ep_te.get('recon',set()))}"
print(f">> stratificare OK: toate {len(PROFILES)} profilurile în train+test; recon test={len(ep_te['recon'])} episoade")

def dump(rows_out, name):
    with open(DS/name,"w",newline="") as f:
        w=csv.writer(f); w.writerow(["label"]+FEATS+["user"]); w.writerows(rows_out)
    n1=sum(r[0] for r in rows_out); print(f"   {name}: {len(rows_out)} (benign={len(rows_out)-n1}, atac={n1})")

print(">> scriu CSV-uri (split sesiune-disjoint):")
dump(train,"ref_train.csv"); dump(test,"ref_test.csv")
