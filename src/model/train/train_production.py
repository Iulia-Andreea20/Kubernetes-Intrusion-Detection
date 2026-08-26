#!/usr/bin/env python3
"""Train and save the deployable model. This is not the model the reported numbers come from.

train_v2.py holds tools and identities out to measure generalisation. This one trains on
everything, held-out tools included, because a shipped detector should recognise every attack we
have seen. That makes its own scores meaningless - quote train_v2.py for generalisation.

Writes classifier.json, pipeline_config.json and feature_importance.json into the artifacts dir;
the deployment mounts that directory straight into the service.
"""
import csv, json, os
from collections import Counter
import numpy as np, xgboost as xgb
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
DS=str(REPO/"src/dataset/reference/ref_v2_all.csv")
OUTDIR=str(REPO/"src/model/artifacts/audit-xgb-v2.6"); os.makedirs(OUTDIR, exist_ok=True)
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload")]
K=2
# Kept out of scope: every tactic that has no external tool to validate it against, so its recall
# would only ever be measured against our own scripts. Recon is out for a different reason - at
# metadata level it is indistinguishable from benign automation (AUC 0.33).
SCOPE_DROP={"impact","evasion","compromised","lowslow","rakkess"}
rows=list(csv.DictReader(open(DS)))
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)

seen=set(); X=[]; y=[]; comp=Counter()
for r in rows:
    if is_recon(uid(r)): continue
    if r["tool"] in SCOPE_DROP and is_atk(r): continue
    k=(vec(r), r["label"])
    if k in seen: continue
    seen.add(k); X.append(fv(r)); y.append(1 if is_atk(r) else 0); comp[("attack" if is_atk(r) else "benign")]+=1
X=np.array(X); y=np.array(y)
# Same cap as the evaluation pipeline, for the same reason: incidental benign traffic collected
# alongside the attacks must not decide how trigger-happy the model is.
spw=min(11.0,max(1.0,(y==0).sum()/max(1,(y==1).sum())))
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0)
clf.fit(X,y)

clf.save_model(OUTDIR+"/classifier.json")
config={
  "version":"v2.6-xgb","features":FEAT,"n_features":len(FEAT),
  "model":"XGBoost (n_estimators=200, max_depth=4, lr=0.1, scale_pos_weight=%.2f)"%spw,
  "scope":"privilege escalation, lateral movement, credential access, persistence - each with a synthetic training class and an external tool held out",
  "classifier_handles":["privilege-escalation","lateral-movement","credential-access","persistence"],
  "excluded_from_classifier":["recon (inseparable at metadata level, AUC 0.33)","n_list (density crutch)","n_create_workload (vestigial, fed the old hijack rule)"],
  "not_covered":["impact, evasion, compromised, lowslow (synthetic only, no external tool to validate against)","recon (AUC 0.33)"],
  "alert_rule":"classifier only: prob>=%.2f on >=%d windows (hysteresis). No rules, no allowlist."%(0.5,K),
  "thresholds":{"prob":0.5,"K":K},
  "train_composition":{"windows":int(X.shape[0]),"attack":comp["attack"],"benign":comp["benign"]},
  "note":"Trained on the full dataset, held-out tools included, for coverage. Generalisation figures come from train_v2.py, not from this model.",
}
json.dump(config, open(OUTDIR+"/pipeline_config.json","w"), indent=2, ensure_ascii=False)
imp=sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:8]
json.dump({k:round(float(v),4) for k,v in imp}, open(OUTDIR+"/feature_importance.json","w"), indent=2)

print(f">> saved to {OUTDIR}/")
print(f"   classifier.json ({X.shape[0]} windows: {comp['attack']} attack / {comp['benign']} benign, deduplicated)")
print(f"   top importance: {dict((k,round(float(v),3)) for k,v in imp[:5])}")
clf2=xgb.XGBClassifier(); clf2.load_model(OUTDIR+"/classifier.json")
p=clf2.predict_proba(X[:5])[:,1]
print(f">> reload check: {[round(float(x),3) for x in p]}")
