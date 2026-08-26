#!/usr/bin/env python3
"""Eval held-out generic: rulează modelul XGBoost antrenat pe activitatea unui actor held-out.
  argv: <window_file> <START_KEY> <END_KEY> <actor_substring>
Toate ferestrele = atac -> recall = generalizare la pattern/unealtă nevăzut(ă).
"""
import json, subprocess, sys
from collections import deque
from pathlib import Path
import numpy as np, xgboost as xgb

HERE = Path(__file__).parent; DS = HERE.parents[2] / "data/legacy/reference_dataset"
MODEL = HERE.parents[2] / "data" / "models" / "audit_api_xgb" / "model.json"
CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = 20; RBAC = {"clusterroles","clusterrolebindings","roles","rolebindings"}
SELF_REVIEW = {"selfsubjectaccessreviews","selfsubjectrulesreviews"}
wf, ks, ke, actor = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
W = {}
for line in open(DS / wf):
    for k in (ks, ke):
        if line.startswith(k + "="): W[k] = line.strip().split("=", 1)[1]

KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
       f"| where TimeGenerated between (datetime({W[ks]}) .. datetime({W[ke]}) + 6m) "
       f"| extend u=tostring(parse_json(log_s).user.username) | where u contains '{actor}' "
       f"| project TimeGenerated, log_s | order by TimeGenerated asc")
res = subprocess.run(["az","rest","--method","post",
    "--url", f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
    "--headers","Content-Type=application/json","--body", json.dumps({"query": KQL})], capture_output=True, text=True)
rows = json.loads(res.stdout)["tables"][0]["rows"]
print(f">> {len(rows)} evenimente '{actor}' (held-out)")
if not rows: print("!! gol — ingestie incompletă"); sys.exit(2)
evs=[]
for ts, log in rows:
    try: e=json.loads(log)
    except: continue
    o=e.get("objectRef") or {}; ann=e.get("annotations") or {}
    evs.append({"verb":e.get("verb",""),"resource":o.get("resource",""),"sub":o.get("subresource",""),
        "ns":o.get("namespace",""),"sourceIP":(e.get("sourceIPs") or [""])[0],
        "code":(e.get("responseStatus") or {}).get("code",0),"decision":ann.get("authorization.k8s.io/decision","")})
def feats(h):
    n=len(h); nf=sum(1 for x in h if x["decision"]=="forbid")
    nsr=sum(1 for x in h if x["verb"]=="create" and x["resource"] in SELF_REVIEW)
    sr_ratio = round(nsr/n,3) if n>=SEQ_LEN else 0.0
    return [round(nf/n,3),nf,n,len(set(x["resource"] for x in h)),len(set(x["verb"] for x in h)),
        len(set(x["ns"] for x in h)),sum(1 for x in h if x["resource"]=="secrets"),
        sum(1 for x in h if x["sub"]=="exec"),sum(1 for x in h if x["resource"] in RBAC),
        sum(1 for x in h if x["verb"]=="create"),sum(1 for x in h if x["verb"]=="delete"),
        sum(1 for x in h if x["verb"]=="list"),sum(1 for x in h if isinstance(x["code"],int) and x["code"]>=400),
        nsr, sr_ratio]
hist=deque(maxlen=SEQ_LEN); X=[]
for x in evs: hist.append(x); X.append(feats(hist))
X=np.array(X,dtype=float)
clf=xgb.XGBClassifier(); clf.load_model(str(MODEL))
pred=(clf.predict_proba(X)[:,1]>=0.5).astype(int)
print("="*56)
print(f" HELD-OUT '{actor}' — model antrenat pe scripturile noastre")
print("="*56)
print(f"  ferestre (toate ATAC): {len(X)}")
print(f"  prinse (recall): {int(pred.sum())}/{len(X)} = {pred.mean()*100:.1f}%")
print(f"  features medii: forbid_ratio={X[:,0].mean():.2f} n_create={X[:,9].mean():.1f} n_list={X[:,11].mean():.1f} n_secrets={X[:,6].mean():.2f} n_rbac={X[:,8].mean():.2f}")
print(f"  recon-feats medii: n_selfreview={X[:,13].mean():.1f} selfreview_ratio={X[:,14].mean():.2f}")
