#!/usr/bin/env python3
# train_production — antreneaza si SALVEAZA modelul de PRODUCTIE PUR XGBoost (deployabil), distinct de cel de EVALUARE.
# Diferenta cheie: productia se antreneaza pe TOATE datele de atac (held-out INCLUS) pt acoperire maxima; recon
# ramane EXCLUS din clasificator (inseparabil la nivel de metadata, AUC 0.33). Salveaza clasificatorul + config-ul
# (trasaturi + prag clasificator, FARA reguli/allowlist) ca artefacte deployabile. Numerele de generalizare se
# raporteaza din train_v2.py (held-out); ACEST model e pt serving, nu pt raportarea generalizarii.
import csv, json, os
from collections import Counter
import numpy as np, xgboost as xgb
HERE="/Users/iulia-andreeagrigore/Projects/Kubernetes-Intrusion-Detection/runtime_ids"
DS=HERE+"/deploy/azure/collect/reference_dataset_v2/ref_v2_all.csv"
OUTDIR=HERE+"/models/audit_hybrid_v2"; os.makedirs(OUTDIR, exist_ok=True)
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload","has_csr","has_tokenreq")]  # has_csr/has_tokenreq = regula persist
K=2  # histerezis: >=K ferestre peste prag pentru alerta la nivel de episod
SCOPE_DROP={"impact","evasion","compromised","lowslow","persistence","rakkess"}  # in afara scope-ului (escaladare+lateral): fara unealta externa / ML esueaza
rows=list(csv.DictReader(open(DS)))
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)

# PRODUCTIE: TOATE pozitivele non-recon + benign; dedup; exclude ferestrele de miner din impact (FP)
seen=set(); X=[]; y=[]; comp=Counter()
for r in rows:
    if is_recon(uid(r)): continue                 # recon: inseparabil la nivel de metadata (AUC 0.33) -> exclus
    if r["tool"] in SCOPE_DROP and is_atk(r): continue   # scope = escaladare + lateral (validate extern); restul scos
    k=(vec(r), r["label"])
    if k in seen: continue
    seen.add(k); X.append(fv(r)); y.append(1 if is_atk(r) else 0); comp[("atac" if is_atk(r) else "benign")]+=1
X=np.array(X); y=np.array(y); spw=min(11.0,max(1.0,(y==0).sum()/max(1,(y==1).sum())))  # CAP=11 (punct operare validat v2.0)
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0)
clf.fit(X,y)

# SALVEAZA artefactele
clf.save_model(OUTDIR+"/classifier.json")
config={
  "version":"v2.6-xgb","features":FEAT,"n_features":len(FEAT),
  "model":"XGBoost (n_estimators=200, max_depth=4, lr=0.1, scale_pos_weight=%.2f)"%spw,
  "scope":"escaladare + lateral (singurele tactici validate prin unealta externa: Stratus, Peirates)",
  "classifier_handles":["escaladare","lateral"],
  "excluded_from_classifier":["recon (inseparabil la nivel de metadata: AUC 0.33)","n_list (overfit densitate)","n_create_workload / has_csr / has_tokenreq (rare, semnal determinist)"],
  "not_covered":["impact / evasion / compromised / lowslow (sintetice, FARA unealta externa -> scoase din scope)","recon (AUC 0.33)","persistence (ML esueaza, PR-AUC 0.34)"],
  "alert_rule":"clasificator: prob>=%.2f pe >=%d ferestre (histerezis). FARA reguli, FARA allowlist."%(0.5,K),
  "thresholds":{"prob":0.5,"K":K},
  "train_composition":{"ferestre":int(X.shape[0]),"atac":comp["atac"],"benign":comp["benign"]},
  "note":"Model PUR XGBoost (fara reguli/allowlist). Antrenat pe TOATE datele (held-out inclus) pt acoperire. Generalizarea se raporteaza din train_v2.py (held-out). Tacticile din not_covered nu mai sunt detectate de sistem.",
}
json.dump(config, open(OUTDIR+"/pipeline_config.json","w"), indent=2, ensure_ascii=False)
imp=sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:8]
json.dump({k:round(float(v),4) for k,v in imp}, open(OUTDIR+"/feature_importance.json","w"), indent=2)

print(f">> MODEL DE PRODUCTIE salvat in {OUTDIR}/")
print(f"   classifier.json ({X.shape[0]} ferestre: {comp['atac']} atac / {comp['benign']} benign, dedup, recon+miner exclus)")
print(f"   pipeline_config.json (trasaturi + prag clasificator, FARA reguli/allowlist)")
print(f"   importanta top: {dict((k,round(float(v),3)) for k,v in imp[:5])}")
# sanity: reload + predict
clf2=xgb.XGBClassifier(); clf2.load_model(OUTDIR+"/classifier.json")
p=clf2.predict_proba(X[:5])[:,1]
print(f">> sanity reload OK: predict pe 5 ferestre = {[round(float(x),3) for x in p]}")
