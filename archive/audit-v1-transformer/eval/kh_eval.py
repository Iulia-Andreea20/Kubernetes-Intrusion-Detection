#!/usr/bin/env python3
"""Held-out tool-disjoint: rulează modelul XGBoost antrenat (pe scripturile NOASTRE) pe activitatea
kube-hunter (unealtă reală). Toate ferestrele = atac -> recall = generalizare la o unealtă nevăzută.
"""
import json, subprocess, sys
from collections import deque
from pathlib import Path
import numpy as np, xgboost as xgb

HERE = Path(__file__).parent; DS = HERE.parents[2] / "data/legacy/reference_dataset"
MODEL = HERE.parents[2] / "data" / "models" / "audit_api_xgb" / "model.json"
CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = 20; RBAC = {"clusterroles","clusterrolebindings","roles","rolebindings"}
W = {}
for line in open(DS / "kh_window.txt"):
    for k in ("KH_START", "KH_END"):
        if line.startswith(k + "="): W[k] = line.strip().split("=", 1)[1]

KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
       f"| where TimeGenerated between (datetime({W['KH_START']}) .. datetime({W['KH_END']}) + 6m) "
       f"| extend u=tostring(parse_json(log_s).user.username) "
       f"| where u contains 'kube-hunter' or u=='system:anonymous' "
       f"| project TimeGenerated, log_s | order by TimeGenerated asc")
res = subprocess.run(["az","rest","--method","post",
    "--url", f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
    "--headers","Content-Type=application/json","--body", json.dumps({"query": KQL})], capture_output=True, text=True)
rows = json.loads(res.stdout)["tables"][0]["rows"]
print(f">> {len(rows)} evenimente kube-hunter (unealtă reală) în fereastră")
if not rows: print("!! gol — ingestia nu e gata SAU kube-hunter n-a atins API-ul ca SA"); sys.exit(2)

evs = []
for ts, log in rows:
    try: e = json.loads(log)
    except: continue
    o = e.get("objectRef") or {}; ann = e.get("annotations") or {}
    evs.append({"verb":e.get("verb",""),"resource":o.get("resource",""),"sub":o.get("subresource",""),
        "ns":o.get("namespace",""),"sourceIP":(e.get("sourceIPs") or [""])[0],
        "code":(e.get("responseStatus") or {}).get("code",0),"decision":ann.get("authorization.k8s.io/decision","")})

def feats(h):
    n=len(h); nf=sum(1 for x in h if x["decision"]=="forbid")
    return [round(nf/n,3),nf,n,len(set(x["resource"] for x in h)),len(set(x["verb"] for x in h)),
        len(set(x["ns"] for x in h)),sum(1 for x in h if x["resource"]=="secrets"),
        sum(1 for x in h if x["sub"]=="exec"),sum(1 for x in h if x["resource"] in RBAC),
        sum(1 for x in h if x["verb"]=="create"),sum(1 for x in h if x["verb"]=="delete"),
        sum(1 for x in h if x["verb"]=="list"),sum(1 for x in h if isinstance(x["code"],int) and x["code"]>=400),
        len(set(x["sourceIP"] for x in h))]

hist=deque(maxlen=SEQ_LEN); X=[feats((hist.append(x) or hist)) for x in evs]
X=np.array(X,dtype=float)
clf=xgb.XGBClassifier(); clf.load_model(str(MODEL))
pred=(clf.predict_proba(X)[:,1]>=0.5).astype(int)
print("="*56)
print(" HELD-OUT TOOL-DISJOINT (kube-hunter) — model antrenat pe scripturile noastre")
print("="*56)
print(f"  ferestre kube-hunter (toate ATAC): {len(X)}")
print(f"  prinse (recall): {int(pred.sum())}/{len(X)} = {pred.mean()*100:.1f}%")
print(f"  features medii: forbid_ratio={X[:,0].mean():.2f}  n_list={X[:,11].mean():.1f}  n_secrets={X[:,6].mean():.2f}  n_distinct_resource={X[:,3].mean():.1f}")
print("  >> recall MARE = generalizează la o unealtă reală nevăzută (NU artefact de script).")
