#!/usr/bin/env python3
"""Threshold-free evaluation of the classifier on its own: ROC, PR, recall at fixed FPR, calibration.

Only the tactics an external tool can validate are in scope. The model trains on the synthetic
version and is scored against the real tool, so the number means something. Persistence and recon
are reported too, as honest negatives: a tool exists for both and the classifier misses both.

    source detection/bin/activate && python scripts/eval_model_only.py
"""
import csv, os
from collections import defaultdict
import numpy as np, xgboost as xgb
from sklearn.metrics import roc_auc_score, average_precision_score, brier_score_loss

BUNDLE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DS     = os.path.join(BUNDLE, "data", "ref_v2_all.csv")
FIGDIR = os.path.join(BUNDLE, "figures"); os.makedirs(FIGDIR, exist_ok=True)

OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload")]  # 32 trasaturi (has_csr/has_tokenreq INCLUSE pt persistence)

# Same split as train_v2.py; keep the two in sync or the numbers stop being comparable.
LAT_TR={"adversary-lateral","adversary-lat-1","adversary-lat-2"}
IMP_TR={"adversary-impv-1","adversary-impv-2","adversary-impv-3"}
ESCV_TR={"adversary-escv-1","adversary-escv-2","adversary-escv-3"}
EVA_TR={"adversary-evav-1","adversary-evav-2","adversary-evav-3"}
CRED_TR={"adversary-creddump-1","adversary-creddump-2"}        # creddump-3 is held out
PERSIST_TR={"adversary-persistsyn-1","adversary-persistsyn-2"} # persistsyn-3 is held out
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)
def part(r):
    t=r["tool"]; s=int(r["session"]); u=uid(r)
    if t=="credsyn":    return "train" if uid(r) in CRED_TR else "credsyn_eval"
    if t=="persistsyn": return "train" if uid(r) in PERSIST_TR else "persistsyn_eval"
    if t=="rakkess":  return "recon_eval"
    if t=="stratus":  return "stratus_eval"
    if t=="peirates": return "peirates_eval"
    if t=="lowslow":  return "lowslow_eval"
    if t=="lateral":  return "train" if u in LAT_TR else "lateral_eval"
    if t=="impact":   return "train" if u in IMP_TR else ("impact_eval" if "impv" in u else "drop")
    if t=="escv":     return "train" if u in ESCV_TR else "escv_eval"
    if t=="evasion":  return "train" if u in EVA_TR else ("evasion_eval" if "evav" in u else "drop")
    if t=="persistence": return "persistence_eval"
    if t=="lateralext":  return "lateralext_eval"
    if t=="compromised": return "compromised_eval"
    if is_recon(u):   return "recon_eval" if s in (5,6) else "train_recon_excl"
    if s in (1,2,3,4): return "train"
    if s in (5,6):     return "test"
    return "train"

rows=list(csv.DictReader(open(DS)))
EVALPARTS={"stratus_eval","peirates_eval","lowslow_eval","lateral_eval","impact_eval","evasion_eval",
           "recon_eval","persistence_eval","lateralext_eval","escv_eval","credsyn_eval","persistsyn_eval"}
EVALVECS={vec(r) for r in rows if part(r) in EVALPARTS and is_atk(r)}

# Train the classifier
SCOPE_DROP={"impact","evasion","compromised","lowslow"}  # sintetice FARA unealta externa -> in afara scope-ului
seen=set(); Xtr,ytr=[],[]; n_leak=0
for r in rows:
    if part(r)!="train" or is_recon(uid(r)): continue
    if r["tool"] in SCOPE_DROP and is_atk(r): continue
    if is_atk(r) and vec(r) in EVALVECS: n_leak+=1; continue
    key=(vec(r),r["label"])
    if key in seen: continue
    seen.add(key); Xtr.append(fv(r)); ytr.append(1 if is_atk(r) else 0)
Xtr=np.array(Xtr); ytr=np.array(ytr)
spw=min(11.0, max(1.0,(ytr==0).sum()/max(1,(ytr==1).sum())))
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,
                      eval_metric="logloss",random_state=0).fit(Xtr,ytr)
def proba(rs): return clf.predict_proba(np.array([fv(r) for r in rs]))[:,1] if rs else np.array([])

# Held-out benign pool for FPR and ROC, disjoint from training
benign_ho=[r for r in rows if part(r)=="test" and not is_atk(r)]
ben_scores=proba(benign_ho)
thr1=float(np.percentile(ben_scores,99)); thr5=float(np.percentile(ben_scores,95))  # FPR=1% / 5% pe benign held-out

# Attack groups, one per evaluation regime
def grp(pred): return [r for r in rows if pred(r)]
# EXTERNAL+ groups are validated by a real tool. EXTERNAL- ones are the honest negatives: a tool
# exists, and the classifier misses them.
GROUPS=[
 ("Synthetic attack (test)",             "SYNTHETIC", grp(lambda r: part(r)=="test" and is_atk(r) and not is_recon(uid(r)))),
 ("Escalation, varied (escv)",           "SYNTHETIC", grp(lambda r: part(r)=="escv_eval")),
 ("Lateral impersonare",                 "SYNTHETIC", grp(lambda r: part(r)=="lateral_eval")),
 ("Credential access, synthetic",       "SYNTHETIC", grp(lambda r: part(r)=="credsyn_eval")),
 ("Persistence, synthetic",             "SYNTHETIC", grp(lambda r: part(r)=="persistsyn_eval")),
 ("Peirates, escalation",               "EXTERNAL+",  grp(lambda r: part(r)=="peirates_eval")),
 ("Stratus, credential access",         "EXTERNAL+",  grp(lambda r: part(r)=="stratus_eval")),     
 ("Stratus, lateral token",    "EXTERNAL+",  grp(lambda r: part(r)=="lateralext_eval")),
 ("Stratus, persistence",               "EXTERNAL+",  grp(lambda r: part(r)=="persistence_eval")), 
 ("rakkess, recon (not trained on)",    "EXTERNAL-",  grp(lambda r: part(r)=="recon_eval" and is_atk(r))),
]

def metrics(atk_rows):
    sa=proba(atk_rows)
    if len(sa)==0: return None
    y=np.r_[np.ones(len(sa)), np.zeros(len(ben_scores))]; s=np.r_[sa, ben_scores]
    roc=roc_auc_score(y,s); pr=average_precision_score(y,s)
    def rp(thr):   # recall and precision at the given threshold, against the held-out benign pool
        tp=int((sa>=thr).sum()); fp=int((ben_scores>=thr).sum())
        return tp/len(sa), (tp/(tp+fp) if (tp+fp)>0 else 0.0)
    r1,p1=rp(thr1); r5,p5=rp(thr5)
    return dict(n=len(sa), roc=roc, pr=pr, r1=r1, p1=p1, r5=r5, p5=p5, scores=sa)

print(f">> train: {len(Xtr)} windows ({int(ytr.sum())} attack / {int((ytr==0).sum())} benign), spw={spw:.0f}, "
      f"{n_leak} excluded as duplicates of held-out. Benign held out: {len(benign_ho)}. "
      f"thr@FPR1%={thr1:.4f} thr@FPR5%={thr5:.4f}")
print("="*98)
print(f"{'Group':34}{'regime':8}{'N':>5}{'ROC':>6}{'PR':>6}{'R@1%':>7}{'P@1%':>7}{'R@5%':>7}{'P@5%':>7}")
print("-"*98)
res={}
for label,regim,atk in GROUPS:
    m=metrics(atk)
    if not m: print(f"{label:34}{regim:8}{'(no windows)':>36}"); continue
    res[label]=(regim,m)
    print(f"{label:34}{regim:8}{m['n']:>5}{m['roc']:>6.3f}{m['pr']:>6.3f}{100*m['r1']:>6.1f}%{100*m['p1']:>6.1f}%{100*m['r5']:>6.1f}%{100*m['p5']:>6.1f}%")

# Aggregate synthetic vs external. The honest negatives stay out of the pooled numbers.
print("-"*98)
for regim in ("SYNTHETIC","EXTERNAL+"):
    atk_rows=[r for (label,rg,atk) in GROUPS if rg==regim and label in res for r in atk]
    m=metrics(atk_rows)
    if m: print(f"{'POOLED '+regim:34}{regim:8}{m['n']:>5}{m['roc']:>6.3f}{m['pr']:>6.3f}{100*m['r1']:>6.1f}%{100*m['p1']:>6.1f}%{100*m['r5']:>6.1f}%{100*m['p5']:>6.1f}%")
print("Precision at a fixed FPR depends on the base rate, so it flatters small groups against a")
print("large benign pool. PR-AUC and recall@FPR are the robust numbers here.")

# Calibration over the held-out benign pool plus the in-scope attacks
all_atk=[r for (label,rg,atk) in GROUPS if rg in ("SYNTHETIC","EXTERNAL+") for r in atk]
sa=proba(all_atk); y=np.r_[np.ones(len(sa)),np.zeros(len(ben_scores))]; p=np.r_[sa,ben_scores]
brier=brier_score_loss(y,p)
bins=np.linspace(0,1,11); ece=0.0
for i in range(10):
    m=(p>=bins[i])&(p<bins[i+1] if i<9 else p<=bins[i+1])
    if m.sum()==0: continue
    ece+=abs(p[m].mean()-y[m].mean())*m.sum()/len(p)
print("="*98)
print(f"Calibration (spw={spw:.0f}): Brier={brier:.4f}  ECE={ece:.4f}")

# ROC and PR curves per regime
try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, precision_recall_curve
    for kind in ("roc","pr"):
        plt.figure(figsize=(5,5))
        for regim,c in (("SYNTHETIC","#1f77b4"),("EXTERNAL+","#d62728")):
            atk_rows=[r for (label,rg,atk) in GROUPS if rg==regim and label in res for r in atk]
            sa=proba(atk_rows); y=np.r_[np.ones(len(sa)),np.zeros(len(ben_scores))]; s=np.r_[sa,ben_scores]
            if kind=="roc":
                fpr,tpr,_=roc_curve(y,s); plt.plot(fpr,tpr,color=c,label=f"{regim} (AUC {roc_auc_score(y,s):.3f})")
            else:
                pr_,rc_,_=precision_recall_curve(y,s); plt.plot(rc_,pr_,color=c,label=f"{regim} (AP {average_precision_score(y,s):.3f})")
        if kind=="roc": plt.plot([0,1],[0,1],'k--',lw=.7); plt.xlabel("FPR"); plt.ylabel("TPR (recall)"); plt.title("ROC — XGBoost pur (audit)")
        else: plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title("Precision-Recall — XGBoost pur (audit)")
        plt.legend(loc="lower right" if kind=="roc" else "upper right"); plt.grid(alpha=.3); plt.tight_layout()
        fn=os.path.join(FIGDIR,f"{kind}_xgb_pur.png"); plt.savefig(fn,dpi=150); plt.close()
        print(f"   figure: {fn}")
except Exception as e:
    print(f"   (figuri sarite: {e})")
print(">> done")
