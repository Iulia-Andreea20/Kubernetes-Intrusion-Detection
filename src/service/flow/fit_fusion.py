#!/usr/bin/env python3
"""Fit the flow fusion once and save it, instead of recomputing it at every startup.

Writes fusion.json: the two Platt calibrators plus the decision threshold.

  - the held-out set is split in half: fit on the first half, report on the second;
  - Platt is a logistic regression over the raw XGBoost score and over log1p(MSE) for the AE;
  - the threshold is picked at FPR = 1% on the reporting half.
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, roc_curve

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(REPO / "src/model/train/flow"))
from tabular_data import load_tabular                       # noqa: E402
from train_autoencoder import TinyAutoencoder, reconstruction_error  # noqa: E402

XGB = REPO / "data/models/flow-bccc/xgboost_bccc/model.json"
AE_DIR = REPO / "data/models/flow-bccc/autoencoder_bccc"
DATA = REPO / "data/bccc-retraining/holdout_split/test_holdout.csv"
OUT = REPO / "src/service/flow"
OUT.mkdir(parents=True, exist_ok=True)

print("1) loading BCCC held-out and aligning features to the autoencoder ...", flush=True)
split = load_tabular(str(DATA))
cfg = json.loads((AE_DIR / "config.json").read_text())
feat = cfg["feature_names"]
X = split.X.copy()
for c in feat:
    if c not in X.columns:
        X[c] = 0
X = X[feat]
Xv = X.to_numpy(dtype=np.float32)
y = split.y.astype(int)
print(f"   {len(y):,} rows, {len(feat)} features ({int((y==1).sum()):,} attack / {int((y==0).sum()):,} benign)")

print("2) Scoruri XGBoost (Booster API, chunked) ...", flush=True)
bst = xgb.Booster()
bst.load_model(str(XGB))
bst.set_param({"nthread": 2})
CHUNK = 5000
_parts = []
for s in range(0, len(Xv), CHUNK):
    _parts.append(bst.predict(xgb.DMatrix(Xv[s:s + CHUNK])))
p_xgb = np.concatenate(_parts)

print("3) autoencoder reconstruction error ...", flush=True)
with open(AE_DIR / "scaler.pkl", "rb") as fh:
    scaler = pickle.load(fh)
Xs = np.nan_to_num(scaler.transform(Xv).astype(np.float32), nan=0.0, posinf=0.0, neginf=0.0)
ae = TinyAutoencoder(input_dim=int(cfg["input_dim"]), bottleneck=int(cfg["bottleneck"]),
                     hidden1=int(cfg["hidden1"]), hidden2=int(cfg["hidden2"]))
ae.load_state_dict(torch.load(AE_DIR / "model.pt", map_location="cpu"))
ae.eval()
mse = reconstruction_error(ae, Xs, batch_size=8192)

print("4) Fit Platt (jum. 1) + evaluare (jum. 2) ...", flush=True)
half = len(y) // 2
yc, ye = y[:half], y[half:]
cx = LogisticRegression().fit(p_xgb[:half].reshape(-1, 1), yc)
ca = LogisticRegression().fit(np.log1p(mse[:half]).reshape(-1, 1), yc)

def cal(c, x):
    return c.predict_proba(x.reshape(-1, 1))[:, 1]

pxe = cal(cx, p_xgb[half:])
pae = cal(ca, np.log1p(mse[half:]))
fused = 0.7 * pxe + 0.3 * pae

fpr, tpr, thr = roc_curve(ye, fused)
m = fpr <= 0.01
i = int(np.where(m)[0][np.argmax(tpr[m])]) if m.any() else int(np.argmin(fpr))
threshold = float(thr[i])

print(f"   XGB AUC={roc_auc_score(ye, pxe):.3f}  AE AUC={roc_auc_score(ye, pae):.3f}  "
      f"HYBRID AUC={roc_auc_score(ye, fused):.3f}")
print(f"   prag@FPR=1%={threshold:.4f}  recall acolo={tpr[i]:.3f}  FPR={fpr[i]*100:.2f}%")

artifact = {
    "weight_xgb": 0.7,
    "weight_ae": 0.3,
    "threshold": threshold,
    "xgb_platt": {"coef": float(cx.coef_[0][0]), "intercept": float(cx.intercept_[0])},
    "ae_platt": {"coef": float(ca.coef_[0][0]), "intercept": float(ca.intercept_[0]), "log1p": True},
    "input_dim": int(cfg["input_dim"]),
    "feature_names": feat,
    "trained_on": "BCCC held-out (test_holdout.csv)",
}
(OUT / "fusion.json").write_text(json.dumps(artifact, indent=2))
print(f"5) Salvat: {OUT / 'fusion.json'}")
