#!/usr/bin/env python3
"""Probe: is victim-sa s24 miss due to TRUNCATION (n<SEQ_LEN) or model blind spot?
Re-derive features for the s24 fragment, then test the SAME forbidden-RBAC events padded to a full window."""
import json, subprocess, numpy as np, xgboost as xgb
from pathlib import Path
from collections import deque
HERE=Path(__file__).parent; MODEL=HERE.parents[2] / "data" / "models"/"audit_api_xgb"/"model.json"
CID=open("/tmp/ids_law_cid.txt").read().strip()
SEQ=20; RBAC={"clusterroles","clusterrolebindings","roles","rolebindings"}
SR={"selfsubjectaccessreviews","selfsubjectrulesreviews"}
clf=xgb.XGBClassifier(); clf.load_model(str(MODEL))

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

# s24 victim-sa fragment: 6 forbidden RBAC/SA creates (from dump)
frag=[{"verb":"create","resource":"clusterrolebindings","sub":"","ns":"","sourceIP":"1.1.1.1","code":403,"decision":"forbid"}]*4 \
   + [{"verb":"create","resource":"serviceaccounts","sub":"","ns":"","sourceIP":"1.1.1.1","code":403,"decision":"forbid"}]*2

print("=== s24 victim-sa: sliding-window preds on the 6-event fragment (as ci_episode does) ===")
hist=deque(maxlen=SEQ)
for i,x in enumerate(frag):
    hist.append(x); f=feats(hist); p=clf.predict_proba(np.array([f],dtype=float))[0,1]
    print(f"  win{i+1} n={f[2]:>2} forbid_ratio={f[0]:.2f} n_rbac={f[8]} n_forbid={f[1]} -> p={p:.3f}")

print("\n=== COUNTERFACTUAL: same 6 forbidden events but n padded to 20 (full window) ===")
# what if the window were FULL (n>=SEQ) of these forbidden RBAC events?
full=frag*4  # 24 forbidden RBAC/SA creates
hist=deque(maxlen=SEQ)
for x in full: hist.append(x)
f=feats(hist); p=clf.predict_proba(np.array([f],dtype=float))[0,1]
print(f"  full window n={f[2]} forbid_ratio={f[0]:.2f} n_rbac={f[8]} n_forbid={f[1]} -> p={p:.3f}")

print("\n=== COUNTERFACTUAL: s23 recon-sa 4x selfreview padded to 20 selfreviews ===")
sr=[{"verb":"create","resource":"selfsubjectaccessreviews","sub":"","ns":"x","sourceIP":"1.1.1.1","code":201,"decision":"allow"}]*20
hist=deque(maxlen=SEQ)
for x in sr: hist.append(x)
f=feats(hist); p=clf.predict_proba(np.array([f],dtype=float))[0,1]
print(f"  full selfreview window n={f[2]} n_selfreview={f[14]} sr_ratio={f[15]} burst={f[16]} -> p={p:.3f}")
print("  (s23 actual: only 4 selfreviews, n<20 so sr_ratio forced to 0.0)")
