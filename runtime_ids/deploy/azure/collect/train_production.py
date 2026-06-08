#!/usr/bin/env python3
# train_production — antreneaza si SALVEAZA modelul de PRODUCTIE (deployabil), distinct de modelul de EVALUARE.
# Diferenta cheie: productia se antreneaza pe TOATE datele de atac (held-out INCLUS) pt acoperire maxima; recon
# RAMANE regula (exclus din clasificator). Salveaza clasificatorul (model.json) + config-ul hibrid complet
# (trasaturi + praguri reguli + allowlist) ca artefacte deployabile. Numerele de generalizare se raporteaza din
# train_v2.py (held-out); ACEST model e pt serving, nu pt raportarea generalizarii.
import csv, json, os
from collections import Counter
import numpy as np, xgboost as xgb
HERE="/Users/iulia-andreeagrigore/Projects/Kubernetes-Intrusion-Detection/runtime_ids"
DS=HERE+"/deploy/azure/collect/reference_dataset_v2/ref_v2_all.csv"
OUTDIR=HERE+"/models/audit_hybrid_v2"; os.makedirs(OUTDIR, exist_ok=True)
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload","has_csr","has_tokenreq")]  # has_csr/has_tokenreq = regula persist
ALLOW_EXACT=["ci-deployer","sre-oncall","devops-pipeline","platform-engineer","security-auditor","platform-admin",
       "aksService","readinessChecker","masterclient","hcpService","system:apiserver",
       "system:serviceaccount:default:compliance-scanner-sa"]
ALLOW_PREFIX=["system:serviceaccount:kube-system:","system:serviceaccount:monitoring:",
       "system:serviceaccount:cert-manager:","system:serviceaccount:argocd:","system:node:",
       "system:serviceaccount:falco:"]   # falco = componenta runtime a IDS-ului (de încredere)
R_RECON=5; D_DEL=5; H_WL=1; K=2
rows=list(csv.DictReader(open(DS)))
def allowed(u): return u in set(ALLOW_EXACT) or u.startswith(tuple(ALLOW_PREFIX))
# KNOWN_ALLOW = identitati allowlistate OBSERVATE benign (controllerele reale). Regula `anom`: o identitate allowlistata-prin-prefix
# NECUNOSCUTA (ex. SA fabricat in kube-system) NU mai e exonerata de regulile de rata -> inchide gaura granitei de incredere.
KNOWN_ALLOW=sorted({r["user"] for r in rows if r["label"]=="0" and allowed(r["user"])})
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)

# PRODUCTIE: TOATE pozitivele non-recon + benign; dedup; exclude ferestrele de miner din impact (FP)
seen=set(); X=[]; y=[]; comp=Counter()
for r in rows:
    if is_recon(uid(r)): continue                 # recon = regula, nu ML
    # exclude workload-hijack/miner din pozitivele impact (regula hijack se ocupa) — evita FP pe creare benigna
    if r["tool"]=="impact" and is_atk(r) and not (float(r["n_delete"])>=1 and float(r["n_create"])==0): continue
    k=(vec(r), r["label"])
    if k in seen: continue
    seen.add(k); X.append(fv(r)); y.append(1 if is_atk(r) else 0); comp[("atac" if is_atk(r) else "benign")]+=1
X=np.array(X); y=np.array(y); spw=min(11.0,max(1.0,(y==0).sum()/max(1,(y==1).sum())))  # CAP=11 (punct operare validat v2.0)
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0)
clf.fit(X,y)

# SALVEAZA artefactele
clf.save_model(OUTDIR+"/classifier.json")
config={
  "version":"v2.2-hybrid","features":FEAT,"n_features":len(FEAT),
  "model":"XGBoost (n_estimators=200, max_depth=4, lr=0.1, scale_pos_weight=%.2f)"%spw,
  "classifier_handles":["escaladare","lateral","impact(stergere)","evasion","persistence (via has_crb)"],
  "excluded_from_classifier":["recon (regula allowlist+rata)","n_list (overfit densitate)","n_create_workload (doar regula hijack)","has_csr/has_tokenreq (doar regula persist)"],
  "rules":{
    "F_severity":"orice fereastra cu has_crb>=1 SAU has_exec>=1 SAU has_impersonation>=1 SAU (has_secret>=1 si secret_ns>=2)",
    "recon":"identitate NE-allowlistata cu n_selfreview>=%d pe fereastra"%R_RECON,
    "destruct":"identitate NE-allowlistata cu n_delete>=%d pe fereastra"%D_DEL,
    "hijack":"identitate NE-allowlistata cu n_create_workload>=%d pe fereastra"%H_WL,
    "persist":"identitate NE-allowlistata cu has_csr>=1 SAU has_tokenreq>=1 (CSR self-approve / TokenRequest abuse)",
    "anom":"identitate ALLOWLISTATA-prin-prefix dar NECUNOSCUTA (nu e in known_allow) cu rata privilegiata (n_delete>=%d SAU n_selfreview>=%d SAU n_create_workload>=%d SAU has_csr SAU has_tokenreq) -> SA fabricat in kube-system"%(D_DEL,R_RECON,H_WL),
  },
  "alert_rule":"clasificator(prob>=0.5, K=%d ferestre) SAU F SAU recon SAU destruct SAU hijack SAU persist SAU anom"%K,
  "known_allow":KNOWN_ALLOW,
  "anom_note":"Inchide gaura granitei de incredere (SA fabricat in kube-system). Reziduu: un controller EXISTENT compromis (token furat, in known_allow) ar cere profil comportamental per-identitate (lucru viitor).",
  "thresholds":{"prob":0.5,"K":K,"R_RECON":R_RECON,"D_DEL":D_DEL,"H_WL":H_WL},
  "allowlist_exact":ALLOW_EXACT, "allowlist_prefix":ALLOW_PREFIX,
  "allowlist_note":"match ANCORAT (exact SAU prefix de namespace), NU substring — previne bypass-ul prin nume",
  "train_composition":{"ferestre":int(X.shape[0]),"atac":comp["atac"],"benign":comp["benign"]},
  "note":"Model de PRODUCTIE antrenat pe TOATE datele (held-out inclus) pt acoperire. Generalizarea se raporteaza din train_v2.py (held-out).",
}
json.dump(config, open(OUTDIR+"/pipeline_config.json","w"), indent=2, ensure_ascii=False)
imp=sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:8]
json.dump({k:round(float(v),4) for k,v in imp}, open(OUTDIR+"/feature_importance.json","w"), indent=2)

print(f">> MODEL DE PRODUCTIE salvat in {OUTDIR}/")
print(f"   classifier.json ({X.shape[0]} ferestre: {comp['atac']} atac / {comp['benign']} benign, dedup, recon+miner exclus)")
print(f"   pipeline_config.json (trasaturi + praguri reguli + allowlist)")
print(f"   importanta top: {dict((k,round(float(v),3)) for k,v in imp[:5])}")
# sanity: reload + predict
clf2=xgb.XGBClassifier(); clf2.load_model(OUTDIR+"/classifier.json")
p=clf2.predict_proba(X[:5])[:,1]
print(f">> sanity reload OK: predict pe 5 ferestre = {[round(float(x),3) for x in p]}")
