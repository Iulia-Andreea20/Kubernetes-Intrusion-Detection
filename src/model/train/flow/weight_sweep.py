#!/usr/bin/env python3
"""Sweep the fusion weight w in w*p_xgb + (1-w)*p_ae and report recall@FPR=1% and ROC-AUC.

Reproduces the calibration in hybrid_flow.py exactly: 50/50 split in row order, Platt on the raw
XGBoost score and on log1p(MSE) for the autoencoder, recall read off the ROC curve at FPR <= 1%.
"""
import sys
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve

def recall_at_fpr(y, s, target=0.01):
    fpr, tpr, _ = roc_curve(y, s)
    mask = fpr <= target
    if mask.any():
        i = int(np.where(mask)[0][np.argmax(tpr[mask])])
    else:
        i = int(np.argmin(fpr))
    return float(tpr[i]), float(fpr[i])

def sweep(name, xgb_path, ae_path, shuffle=False):
    try:
        xgb = pd.read_csv(xgb_path)
        ae = pd.read_csv(ae_path)
    except FileNotFoundError as e:
        print(f"\n[{name}] skipped, missing file: {e}")
        return
    if len(xgb) != len(ae):
        print(f"\n[{name}] SKIP — count diferit: xgb={len(xgb)} ae={len(ae)}")
        return
    y = xgb["actual"].astype(int).to_numpy()
    if not (y == ae["actual"].astype(int).to_numpy()).all():
        print(f"\n[{name}] skipped, labels are not aligned")
        return

    xgb_raw = xgb["probability"].astype(float).to_numpy()
    ae_raw = ae["ae_mse"].astype(float).to_numpy()
    if shuffle:
        # The rows arrive grouped by class, so a plain 50/50 cut would leave the calibration
        # half all-benign. Shuffle stratified, fixed seed.
        idx = np.random.default_rng(42).permutation(len(y))
        y, xgb_raw, ae_raw = y[idx], xgb_raw[idx], ae_raw[idx]
    half = len(y) // 2
    y_cal, y_eval = y[:half], y[half:]

    cx = LogisticRegression().fit(xgb_raw[:half].reshape(-1, 1), y_cal)
    ca = LogisticRegression().fit(np.log1p(ae_raw[:half]).reshape(-1, 1), y_cal)
    p_xgb = cx.predict_proba(xgb_raw[half:].reshape(-1, 1))[:, 1]
    p_ae = ca.predict_proba(np.log1p(ae_raw[half:]).reshape(-1, 1))[:, 1]

    print(f"\n[{name}]  eval n={len(y_eval):,} "
          f"({(y_eval==1).sum():,} attack, {(y_eval==0).sum():,} benign)")
    print(f"  {'w_xgb':>6} {'w_ae':>6} {'recall@FPR=1%':>14} {'ROC-AUC':>9}")
    print("  " + "-" * 40)

    best_w, best_r = None, -1.0
    rows = []
    for w in [round(x, 2) for x in np.arange(0.50, 1.001, 0.05)]:
        fused = w * p_xgb + (1 - w) * p_ae
        rec, _ = recall_at_fpr(y_eval, fused, 0.01)
        auc = roc_auc_score(y_eval, fused)
        rows.append((w, rec, auc))
        if rec > best_r:
            best_r, best_w = rec, w
    # autoencoder alone, for reference
    rec_ae, _ = recall_at_fpr(y_eval, p_ae, 0.01)

    for w, rec, auc in rows:
        mark = ""
        if w == best_w:
            mark = "  <== MAX"
        elif w == 0.70:
            mark = "  (0,7/0,3)"
        print(f"  {w:>6.2f} {1-w:>6.2f} {rec:>14.4f} {auc:>9.4f}{mark}")
    print(f"  (ref) AE pur                {rec_ae:>14.4f}")
    print(f"  => optim: w_xgb={best_w} (recall@FPR1%={best_r:.4f}); "
          f"0.7/0.3 gives {[r for w,r,a in rows if w==0.70][0]:.4f}")

REPO = str(Path(__file__).resolve().parents[4])
sweep("BCCC held-out day",
      f"{REPO}/data/models/flow-bccc/xgboost_bccc/predictions_test.csv",
      f"{REPO}/data/models/evaluation/autoencoder_predictions/ae_predictions_bccc_test_heldout_day.csv")
sweep("ITU val (random)",
      f"{REPO}/cluster/dizertatie/data/models/flow-bccc/xgboost_itu/predictions_val.csv",
      f"{REPO}/data/models/evaluation/autoencoder_predictions/ae_predictions_itu_val.csv")
sweep("ITU LHO (aligned)",
      f"{REPO}/cluster/dizertatie/data/models/evaluation/autoencoder_predictions/xgb_lho_aligned.csv",
      f"{REPO}/cluster/dizertatie/data/models/evaluation/autoencoder_predictions/ae_lho_aligned.csv",
      shuffle=True)
