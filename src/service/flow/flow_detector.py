#!/usr/bin/env python3
"""Network-flow detector: supervised XGBoost fused with an unsupervised autoencoder.

    p_xgb  = XGBoost.predict
    p_ae   = Platt(log1p(reconstruction MSE))
    score  = 0.7 * Platt(p_xgb) + 0.3 * p_ae
    alert if score >= threshold (fixed at FPR = 1%)

The autoencoder earns its 30% on traffic the supervised model has not seen: on a leave-heavy-
hitter-out split it lifts AUC from 0.64 to 0.86, where XGBoost alone has latched onto signatures.

The calibrators and the threshold are read from fusion.json - see fit_fusion.py.

XGBoost and PyTorch both link libomp on macOS, so the OpenMP workaround has to be set before torch
is imported or the process segfaults.
"""
import os
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import xgboost as xgb

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(REPO / "src/model/train/flow"))
from tabular_data import load_tabular                       # noqa: E402
from train_autoencoder import TinyAutoencoder, reconstruction_error  # noqa: E402

SEVERITY = [("CRITICAL", 0.95), ("HIGH", 0.85), ("MEDIUM", 0.70), ("LOW", 0.50)]

def severity_for(p: float) -> str:
    for label, t in SEVERITY:
        if p >= t:
            return label
    return "NONE"

def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))

class FlowDetector:
    """Inference-ready flow detector: XGBoost, autoencoder and the fusion between them."""

    def __init__(self,
                 xgb_path=REPO / "data/models/flow-bccc/xgboost_bccc/model.json",
                 ae_dir=REPO / "data/models/flow-bccc/autoencoder_bccc",
                 fusion_path=REPO / "src/service/flow/fusion.json"):
        self.fusion = json.loads(Path(fusion_path).read_text())
        self.features = self.fusion["feature_names"]
        # XGBoost (Booster API, single-thread)
        self.bst = xgb.Booster()
        self.bst.load_model(str(xgb_path))
        self.bst.set_param({"nthread": 1})
        # Autoencoder + scaler
        cfg = json.loads((Path(ae_dir) / "config.json").read_text())
        with open(Path(ae_dir) / "scaler.pkl", "rb") as fh:
            self.scaler = pickle.load(fh)
        self.ae = TinyAutoencoder(input_dim=int(cfg["input_dim"]),
                                  bottleneck=int(cfg["bottleneck"]),
                                  hidden1=int(cfg["hidden1"]), hidden2=int(cfg["hidden2"]))
        self.ae.load_state_dict(torch.load(Path(ae_dir) / "model.pt", map_location="cpu"))
        self.ae.eval()

    def _align(self, df: pd.DataFrame) -> np.ndarray:
        X = df.copy()
        for c in self.features:
            if c not in X.columns:
                X[c] = 0
        return X[self.features].to_numpy(dtype=np.float32)

    def score_matrix(self, Xv: np.ndarray) -> dict:
        # Chunked: XGBoost segfaults on very large matrices
        parts = []
        for s in range(0, len(Xv), 5000):
            parts.append(self.bst.predict(xgb.DMatrix(Xv[s:s + 5000])))
        p_xgb = np.concatenate(parts) if parts else np.array([])
        # Autoencoder MSE
        Xs = np.nan_to_num(self.scaler.transform(Xv).astype(np.float32),
                           nan=0.0, posinf=0.0, neginf=0.0)
        mse = reconstruction_error(self.ae, Xs, batch_size=8192)
        # fuziune Platt + ponderi
        xp = self.fusion["xgb_platt"]; ap = self.fusion["ae_platt"]
        cal_xgb = _sigmoid(xp["coef"] * p_xgb + xp["intercept"])
        cal_ae = _sigmoid(ap["coef"] * np.log1p(mse) + ap["intercept"])
        score = self.fusion["weight_xgb"] * cal_xgb + self.fusion["weight_ae"] * cal_ae
        label = (score >= self.fusion["threshold"]).astype(int)
        return {"p_xgb": p_xgb, "mse": mse, "p_ae": cal_ae,
                "score": score, "label": label}

    def score_frame(self, df: pd.DataFrame) -> dict:
        return self.score_matrix(self._align(df))

if __name__ == "__main__":
    # smoke test over a few held-out records, benign and DDoS
    det = FlowDetector()
    split = load_tabular(str(REPO / "data/bccc-retraining/holdout_split/test_holdout.csv"),
                         sample_size=2000)
    out = det.score_frame(split.X)
    y = split.y.astype(int)
    sc, lab = out["score"], out["label"]
    tp = int(((lab == 1) & (y == 1)).sum()); fn = int(((lab == 0) & (y == 1)).sum())
    fp = int(((lab == 1) & (y == 0)).sum()); tn = int(((lab == 0) & (y == 0)).sum())
    print(f"smoke (n=2000): recall={tp/max(tp+fn,1):.3f} FPR={fp/max(fp+tn,1)*100:.2f}% "
          f"prag={det.fusion['threshold']:.3f}")
    print(f"  exemplu DDoS: score={sc[y==1][:3]}")
    print(f"  exemplu benign: score={sc[y==0][:3]}")
