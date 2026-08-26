#!/usr/bin/env python3
"""Why did real recon-sa windows fire (p up to 0.644-0.755) but my synthetic 20x selfreview scored 0?
Pull real recon-sa events for a FIRED session (s18) and dump the exact feature vector of the firing window."""
import json, subprocess, numpy as np, xgboost as xgb
from pathlib import Path
from collections import deque
HERE=Path(__file__).parent; MODEL=HERE.parents[2] / "data" / "models"/"audit_api_xgb"/"model.json"
CID=open("/tmp/ids_law_cid.txt").read().strip()
SEQ=20; RBAC={"clusterroles","clusterrolebindings","roles","rolebindings"}
SR={"selfsubjectaccessreviews","selfsubjectrulesreviews"}
clf=xgb.XGBClassifier(); clf.load_model(str(MODEL))
FEATNAMES=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns",
 "n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_distinct_srcip","n_selfreview","selfreview_ratio","selfreview_burst_max"]
def feats(h):
    n=len(h); nf=sum(1 for x in h if x["decision"]=="forbid")
    nsr=sum(1 for x in h if x["verb"]=="create" and x["resource"] in SR)
    run=best=0
    for x in h:
        if x["verb"]=="create" and x["resource"] in SR: run+=1; best=max(best,run)
        else: run=0
    srr=round(nsr/n,3) if n>=SEQ else 0.0
    return [round(nf/n,3),nf,n,len(set(x["resource"] for x in h)),len(set(x["verb"] for x in h)),len(set(x["ns"] for x in h)),
        sum(1 for x in h if x["resource"]=="secrets"),sum(1 for x in h if x["sub"]=="exec"),sum(1 for x in h if x["resource"] in RBAC),
        sum(1 for x in h if x["verb"]=="create"),sum(1 for x in h if x["verb"]=="delete"),sum(1 for x in h if x["verb"]=="list"),
        sum(1 for x in h if isinstance(x["code"],int) and x["code"]>=400),len(set(x["sourceIP"] for x in h)),nsr,srr,best]

def q(start,end,actor):
    KQL=(f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
         f"| where TimeGenerated between (datetime({start}) .. datetime({end})) "
         f"| order by TimeGenerated asc | project log_s")
    r=subprocess.run(["az","rest","--method","post","--url",
        f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
        "--headers","Content-Type=application/json","--body",json.dumps({"query":KQL})],capture_output=True,text=True)
    out=[]
    for (log,) in json.loads(r.stdout)["tables"][0]["rows"]:
        try: e=json.loads(log)
        except: continue
        a=((e.get("impersonatedUser") or {}).get("username")) or (e.get("user") or {}).get("username","")
        if actor not in a: continue
        o=e.get("objectRef") or {}; ann=e.get("annotations") or {}
        out.append({"verb":e.get("verb",""),"resource":o.get("resource",""),"sub":o.get("subresource",""),
            "ns":o.get("namespace",""),"sourceIP":(e.get("sourceIPs") or [""])[0],
            "code":(e.get("responseStatus") or {}).get("code",0),"decision":ann.get("authorization.k8s.io/decision","")})
    return out

# s18 recon-sa fired 1/99 window with pmax 0.644
evs=q("2026-06-04T14:31:50Z","2026-06-04T14:33:19Z","recon-sa")  # s18
print(f"s18 recon-sa: {len(evs)} events")
from collections import Counter
print("  verb:resource mix:", Counter((x['verb'],x['resource']) for x in evs).most_common(6))
hist=deque(maxlen=SEQ); best_p=-1; best_f=None
for x in evs:
    hist.append(x); f=feats(hist); p=clf.predict_proba(np.array([f],dtype=float))[0,1]
    if p>best_p: best_p=p; best_f=f[:]
print(f"  MAX firing window p={best_p:.3f}")
for nm,v in zip(FEATNAMES,best_f): print(f"     {nm:<22}={v}")
