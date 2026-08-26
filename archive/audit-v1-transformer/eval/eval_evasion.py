#!/usr/bin/env python3
"""Testul de evaziune: rulează modelul XGBoost DEJA ANTRENAT pe atacul EVAZIV (held-out, low-and-slow).
Toate ferestrele sunt atac (adversary-external diluat) -> recall = câte prinde. Recall mic = model fragil la evaziune.
"""
import json, os, subprocess, sys
from collections import deque
from pathlib import Path
import numpy as np, xgboost as xgb

HERE = Path(__file__).parent; DS = HERE.parents[2] / "data/legacy/reference_dataset"
MODEL = HERE.parents[2] / "data" / "models" / "audit_api_xgb" / "model.json"
CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = 20
RBAC = {"clusterroles", "clusterrolebindings", "roles", "rolebindings"}
FEATS = ["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns",
         "n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_distinct_srcip"]

W = {}
for line in open(DS / "evasion_window.txt"):
    for k in ("EVASION_START", "EVASION_END"):
        if line.startswith(k + "="): W[k] = line.strip().split("=", 1)[1]
start, end = W["EVASION_START"], W["EVASION_END"]

KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
       f"| where TimeGenerated between (datetime({start}) .. datetime({end}) + 6m) "
       f"| extend u=tostring(parse_json(log_s).user.username) | where u=='adversary-external' "
       f"| project TimeGenerated, log_s | order by TimeGenerated asc")
res = subprocess.run(["az","rest","--method","post",
    "--url", f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
    "--headers","Content-Type=application/json","--body", json.dumps({"query": KQL})], capture_output=True, text=True)
rows = json.loads(res.stdout)["tables"][0]["rows"]
print(f">> {len(rows)} evenimente evazive (adversary-external) în fereastră")
if not rows: print("!! gol — ingestia nu e gata"); sys.exit(2)

evs = []
for ts, log in rows:
    try: e = json.loads(log)
    except: continue
    o = e.get("objectRef") or {}; ann = e.get("annotations") or {}
    evs.append({"verb": e.get("verb",""), "resource": o.get("resource",""), "sub": o.get("subresource",""),
        "ns": o.get("namespace",""), "sourceIP": (e.get("sourceIPs") or [""])[0],
        "code": (e.get("responseStatus") or {}).get("code",0), "decision": ann.get("authorization.k8s.io/decision","")})

def feats(h):
    n=len(h); nf=sum(1 for x in h if x["decision"]=="forbid")
    return [round(nf/n,3),nf,n,len(set(x["resource"] for x in h)),len(set(x["verb"] for x in h)),
        len(set(x["ns"] for x in h)),sum(1 for x in h if x["resource"]=="secrets"),
        sum(1 for x in h if x["sub"]=="exec"),sum(1 for x in h if x["resource"] in RBAC),
        sum(1 for x in h if x["verb"]=="create"),sum(1 for x in h if x["verb"]=="delete"),
        sum(1 for x in h if x["verb"]=="list"),sum(1 for x in h if isinstance(x["code"],int) and x["code"]>=400),
        len(set(x["sourceIP"] for x in h))]

hist=deque(maxlen=SEQ_LEN); X=[]
for x in evs:
    hist.append(x); X.append(feats(hist))
X=np.array(X,dtype=float)
clf=xgb.XGBClassifier(); clf.load_model(str(MODEL))
pred=(clf.predict_proba(X)[:,1]>=0.5).astype(int)
recall=pred.mean()
print("="*56)
print(" TEST EVAZIUNE (low-and-slow) — model antrenat pe rafale dense")
print("="*56)
print(f"  ferestre evazive (toate ATAC): {len(X)}")
print(f"  prinse (recall): {int(pred.sum())}/{len(X)} = {recall*100:.1f}%")
print(f"  ratate (evadate): {int((1-pred).sum())} = {(1-recall)*100:.1f}%")
print(f"  features medii pe fereastra evazivă: forbid_ratio={X[:,0].mean():.3f}  n_secrets={X[:,6].mean():.2f}  n_list={X[:,11].mean():.1f}")
print("  >> recall MARE = robust la evaziune; recall MIC = modelul prinde doar rafalele dense (limitare).")
