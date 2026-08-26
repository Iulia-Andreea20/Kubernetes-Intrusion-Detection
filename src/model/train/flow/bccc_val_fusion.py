#!/usr/bin/env python3
"""Fill in the missing cell: XGBoost + autoencoder fusion on the BCCC validation split.

Rebuilds the exact validation split (train_test_split, random_state=42) so the rows line up with
predictions_val.csv, runs the autoencoder over them and applies the same fusion as hybrid_flow.py.
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(REPO / "src/model/train/flow"))
from tabular_data import load_tabular            # noqa: E402
from train_autoencoder import TinyAutoencoder, reconstruction_error  # noqa: E402

AE_DIR = REPO / "data/models/flow-bccc/autoencoder_bccc"
DATA = REPO / "data/bccc-retraining/holdout_split/train_without_holdout.csv"
XGB_VAL = REPO / "data/models/flow-bccc/xgboost_bccc/predictions_val.csv"

if not DATA.exists():
    print(f"missing: {DATA}"); sys.exit(1)

print("1) load_tabular pe train_without_holdout.csv ...", flush=True)
split = load_tabular(str(DATA))
X, y = split.X, split.y

print("2) reconstruiesc split-ul de val (random_state=42, test_size=0.2) ...", flush=True)
X_tr, X_val, y_tr, y_val = train_test_split(
    X.values, y, test_size=0.2, random_state=42, stratify=y)

# align columns with the ones the autoencoder was trained on
cfg = json.loads((AE_DIR / "config.json").read_text())
feat = cfg["feature_names"]
col_idx = [split.feature_names.index(c) for c in feat]
X_val_ae = X_val[:, col_idx]

print("3) running the autoencoder over the validation rows ...", flush=True)
with open(AE_DIR / "scaler.pkl", "rb") as fh:
    scaler = pickle.load(fh)
Xs = np.nan_to_num(scaler.transform(X_val_ae).astype(np.float32),
                   nan=0.0, posinf=0.0, neginf=0.0)
ae = TinyAutoencoder(input_dim=int(cfg["input_dim"]), bottleneck=int(cfg["bottleneck"]),
                     hidden1=int(cfg["hidden1"]), hidden2=int(cfg["hidden2"]))
ae.load_state_dict(torch.load(AE_DIR / "model.pt", map_location="cpu"))
ae.eval()
ae_mse = reconstruction_error(ae, Xs, batch_size=8192)

print("4) aligning with the XGBoost validation predictions ...", flush=True)
xgb = pd.read_csv(XGB_VAL)
assert len(xgb) == len(y_val), f"count: xgb={len(xgb)} val={len(y_val)}"
assert (xgb["actual"].to_numpy() == y_val).all(), "labels do not line up"
xgb_raw = xgb["probability"].astype(float).to_numpy()

print(f"   aligned: {len(y_val):,} rows "
      f"({int((y_val==1).sum()):,} attack, {int((y_val==0).sum()):,} benign)\n", flush=True)

# same fusion as hybrid_flow.py
def recall_at_fpr(yt, s, t=0.01):
    fpr, tpr, _ = roc_curve(yt, s)
    m = fpr <= t
    i = int(np.where(m)[0][np.argmax(tpr[m])]) if m.any() else int(np.argmin(fpr))
    return float(tpr[i])

half = len(y_val) // 2
ycal, yev = y_val[:half], y_val[half:]
cx = LogisticRegression().fit(xgb_raw[:half].reshape(-1, 1), ycal)
ca = LogisticRegression().fit(np.log1p(ae_mse[:half]).reshape(-1, 1), ycal)
p_xgb = cx.predict_proba(xgb_raw[half:].reshape(-1, 1))[:, 1]
p_ae = ca.predict_proba(np.log1p(ae_mse[half:]).reshape(-1, 1))[:, 1]

strat = {
    "xgb_only":       p_xgb,
    "ae_only":        p_ae,
    "score_mean":     (p_xgb + p_ae) / 2,
    "max_calibrated": np.maximum(p_xgb, p_ae),
    "weighted_70_30": 0.7 * p_xgb + 0.3 * p_ae,
}
print("=== BCCC val — fuziune (recall@FPR=1%, ROC-AUC) ===")
xgb_base = recall_at_fpr(yev, p_xgb)
for n, s in strat.items():
    r = recall_at_fpr(yev, s)
    auc = roc_auc_score(yev, s)
    d = "" if n in ("xgb_only", "ae_only") else f"  Δ vs XGB = {(r-xgb_base)*100:+.1f} pp"
    print(f"  {n:16s} recall@FPR1%={r:.4f}  ROC-AUC={auc:.4f}{d}")
