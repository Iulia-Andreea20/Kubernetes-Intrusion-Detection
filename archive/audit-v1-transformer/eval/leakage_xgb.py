#!/usr/bin/env python3
"""PORȚĂ HARD anti-artefact pe calea XGBoost (ref_test.csv). Compară modelul de audit cu baselines pe
UN SINGUR feature / prezență / identitate / formă-de-identitate, FOCALIZAT pe recon. Dacă modelul nu bate
clar baseline-urile (în special dacă FPR-ul prezenței e mare iar al modelului mic), feature-ul de recon NU e
artefactul keyword. Dacă modelul ≈ prezență, feature-ul E artefactul -> RESPINGE și re-acordează injectarea benign.
"""
import csv
from pathlib import Path
import numpy as np, xgboost as xgb

HERE = Path(__file__).parent; DS = HERE.parents[2] / "data/legacy/reference_dataset"
MODEL = HERE.parents[2] / "data" / "models" / "audit_api_xgb" / "model.json"
rows = list(csv.reader(open(DS / "ref_test.csv"))); head = rows[0]; data = rows[1:]
fcols = [i for i, c in enumerate(head) if c not in ("label", "user")]
ui = head.index("user")
X = np.array([[float(r[i]) for i in fcols] for r in data]); y = np.array([int(r[0]) for r in data])
users = [r[ui] for r in data]
idx = {c: fcols.index(head.index(c)) for c in ("n_selfreview", "selfreview_ratio")}

is_recon = np.array(["recon-sa" in u for u in users])         # ferestre recon (profil recon)
is_benign = (y == 0)
is_benign_cani = is_benign & (X[:, idx["n_selfreview"]] >= 1)  # BENIGN care emit can-i (confound-ul cheie)
clf = xgb.XGBClassifier(); clf.load_model(str(MODEL))
pred = (clf.predict_proba(X)[:, 1] >= 0.5).astype(int)

def rates(p):
    rec = p[is_recon].mean() if is_recon.any() else 0.0
    fpr = p[is_benign].mean() if is_benign.any() else 0.0
    fpr_c = p[is_benign_cani].mean() if is_benign_cani.any() else 0.0
    return rec, fpr, fpr_c

def best_threshold(col):
    v = X[:, idx[col]]; best = (-2.0, 0, 0, 0)
    for t in sorted(set(v)):
        p = (v >= t).astype(int); rec, fpr, _ = rates(p)
        if rec - fpr > best[0]: best = (rec - fpr, t, rec, fpr)
    return best

print("=" * 66); print(" PORȚĂ ANTI-ARTEFACT (recon) — model vs baselines pe ref_test.csv"); print("=" * 66)
print(f"  ferestre: recon={int(is_recon.sum())}  benign={int(is_benign.sum())}  benign-cu-can-i={int(is_benign_cani.sum())}")
mr, mf, mfc = rates(pred)
print(f"\n  MODEL (17 features) : recall_recon={mr*100:5.1f}%  FPR_benign={mf*100:5.2f}%  FPR_benign_canI={mfc*100:5.2f}%")
print("  --- baselines (ce poate face un SINGUR semnal) ---")
best_sf = 0.0
for c in ("n_selfreview", "selfreview_ratio"):
    _, thr, rec, fpr = best_threshold(c); best_sf = max(best_sf, rec)
    print(f"  single-feat {c:22s} (>={thr:g}): recall_recon={rec*100:5.1f}%  FPR_benign={fpr*100:5.2f}%")
p = (X[:, idx["n_selfreview"]] >= 1).astype(int); pr, pf, _ = rates(p)
print(f"  PREZENȚĂ n_selfreview>=1        : recall_recon={pr*100:5.1f}%  FPR_benign={pf*100:5.2f}%  (flag ORICE can-i)")
p = np.array([1 if "recon-sa" in u else 0 for u in users]); ir, iff, _ = rates(p)
print(f"  IDENTITATE 'recon-sa'           : recall_recon={ir*100:5.1f}%  FPR_benign={iff*100:5.2f}%  (proxy perfect = artefact)")
p = np.array([1 if u.startswith("system:serviceaccount") else 0 for u in users]); sr, sf, _ = rates(p)
print(f"  FORMĂ-IDENTITATE is-SA          : recall_recon={sr*100:5.1f}%  FPR_benign={sf*100:5.2f}%  (trebuie departe de proxy: compliance-scanner-sa e SA benign)")
agree = (pred == (X[:, idx["n_selfreview"]] >= 1).astype(int)).mean()
print(f"\n  acord MODEL vs PREZENȚĂ: {agree*100:.1f}%")
print("-" * 66)
# prezența marchează TOATE ferestrele benign-cu-can-i (prin definiție FPR_canI=100%); modelul scutește majoritatea.
spared = (1 - mfc) * 100
ok_fpr = mf < pf - 0.03      # FPR pe TOT benign-ul: model << prezență (apples-to-apples) => a învățat o graniță
ok_rec = mr >= best_sf - 0.02  # recall pe recon cel puțin cât cel mai bun single-feature
ok_agree = agree < 0.95      # NU e simplu lookup de prezență
verdict = "PASS " if (ok_fpr and ok_rec and ok_agree) else "FAIL  (re-acordează injectarea benign / regândește feature-ul)"
print(f"  model scutește {spared:.0f}% din ferestrele benign-can-i pe care PREZENȚA le-ar marca pe toate")
print(f"  PASS-uri: FPR_benign(model {mf*100:.1f}% << prezență {pf*100:.1f}%)={ok_fpr}  "
      f"recall(model>=single-feat)={ok_rec}  acord<95%={ok_agree}")
print(f"  VERDICT: {verdict}")
print(f"  NOTĂ onestă: detecția reconului are COST de FPR (benign-can-i {mfc*100:.0f}% la nivel de fereastră) — "
      f"redus de histerezisul pe episod (vezi ci_episode.py).")
