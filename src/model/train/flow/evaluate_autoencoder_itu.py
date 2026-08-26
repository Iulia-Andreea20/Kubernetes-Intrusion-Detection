#!/usr/bin/env python3
"""Evaluate the ITU-trained autoencoder on ITU val (random split) and LHO test.

Produces AE predictions in the SAME row order as the corresponding XGBoost
predictions so that src/model/train/flow/hybrid_flow.py can fuse them via Platt
calibration.

Outputs:
  - data/models/evaluation/autoencoder_predictions/ae_predictions_itu_val.csv
  - data/models/evaluation/autoencoder_predictions/ae_predictions_itu_lho.csv
  - data/models/evaluation/autoencoder_itu_operating_points.json
"""
from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                              roc_auc_score, roc_curve)

REPO = Path(__file__).resolve().parents[4]
REPO = REPO.parent
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tabular_data import load_tabular  # noqa: E402
from train_autoencoder import TinyAutoencoder, reconstruction_error  # noqa: E402

AE_DIR = REPO / "data/models/autoencoder_itu"
ITU_CSV = REPO / "itu_dataset_clean.csv"
HEAVY_HITTERS = ["100.64.0.2", "10.16.0.6", "10.16.0.5"]

def load_autoencoder(model_dir: Path):
    config = json.loads((model_dir / "config.json").read_text())
    threshold = json.loads((model_dir / "threshold.json").read_text())["threshold"]
    with open(model_dir / "scaler.pkl", "rb") as fh:
        scaler = pickle.load(fh)
    model = TinyAutoencoder(
        input_dim=int(config["input_dim"]),
        bottleneck=int(config["bottleneck"]),
        hidden1=int(config["hidden1"]),
        hidden2=int(config["hidden2"]),
    )
    state = torch.load(model_dir / "model.pt", map_location="cpu")
    model.load_state_dict(state)
    model.eval()
    return model, scaler, threshold, config

def operating_points(y_true: np.ndarray, y_score: np.ndarray) -> dict:
    out = {
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "pr_auc": float(average_precision_score(y_true, y_score)),
    }
    prec, rec, thr = precision_recall_curve(y_true, y_score)
    f1 = 2 * prec[:-1] * rec[:-1] / (prec[:-1] + rec[:-1] + 1e-12)
    if len(f1):
        i = int(np.argmax(f1))
        out["best_f1"] = {"threshold": float(thr[i]),
                          "precision": float(prec[i]),
                          "recall": float(rec[i]),
                          "f1": float(f1[i])}
    fpr_c, tpr_c, _ = roc_curve(y_true, y_score)
    for tgt in (0.01, 0.001):
        m = fpr_c <= tgt
        if m.any():
            i = int(np.where(m)[0][np.argmax(tpr_c[m])])
        else:
            i = int(np.argmin(fpr_c))
        out[f"recall_at_fpr_{tgt}"] = {"achieved_fpr": float(fpr_c[i]),
                                       "recall": float(tpr_c[i])}
    for tgt in (0.95, 0.99):
        m = tpr_c >= tgt
        if m.any():
            i = int(np.where(m)[0][np.argmin(fpr_c[m])])
        else:
            i = int(np.argmax(tpr_c))
        out[f"fpr_at_recall_{tgt}"] = {"achieved_recall": float(tpr_c[i]),
                                       "fpr": float(fpr_c[i])}
    return out

def main():
    print(f"Loading ITU dataset from {ITU_CSV} ...")
    # Load via the canonical preprocessing pipeline used by XGB training.
    split = load_tabular(str(ITU_CSV))
    X_all = split.X.to_numpy(dtype=np.float32)
    y_all = split.y.astype(int)
    print(f"  ITU total: {len(X_all):,} rows, {len(split.feature_names)} features")

    # Also load the Src IP column separately for LHO partitioning.
    print("Loading Src IP column for LHO partition ...")
    src_ips = pd.read_csv(str(ITU_CSV), usecols=["Src IP"])["Src IP"].to_numpy()
    assert len(src_ips) == len(X_all), \
        f"Row count mismatch: src_ips={len(src_ips)} vs features={len(X_all)}"

    # Load AE
    print(f"Loading AE from {AE_DIR} ...")
    model, scaler, threshold, config = load_autoencoder(AE_DIR)
    feature_names = config["feature_names"]
    print(f"  AE input_dim={config['input_dim']}, threshold={threshold:.6f}")

    out_dir = REPO / "data/models/evaluation/autoencoder_predictions"
    out_dir.mkdir(parents=True, exist_ok=True)
    metrics_out: dict = {}

    # 1) ITU val (random 20% with stratify)
    print("\n=== Reproducing ITU random val split (test_size=0.2, random_state=42, stratify=y) ===")
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
    )
    print(f"  val rows: {len(X_val):,}  ({(y_val==1).sum():,} attack)")
    X_val_scaled = scaler.transform(X_val).astype(np.float32)
    X_val_scaled = np.nan_to_num(X_val_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    mse_val = reconstruction_error(model, X_val_scaled, batch_size=8192)
    pred_val = (mse_val >= threshold).astype(int)

    # Save AE predictions in same order as XGB val
    df_val = pd.DataFrame({"actual": y_val, "ae_mse": mse_val,
                            "ae_score": mse_val / max(threshold, 1e-12),
                            "ae_pred": pred_val})
    df_val.to_csv(out_dir / "ae_predictions_itu_val.csv", index=False)
    print(f"  wrote {out_dir / 'ae_predictions_itu_val.csv'}")

    val_ops = operating_points(y_val, mse_val)
    val_ops["at_training_threshold"] = {
        "recall": float(pred_val[y_val == 1].mean()) if (y_val == 1).any() else None,
        "fpr": float(pred_val[y_val == 0].mean()) if (y_val == 0).any() else None,
    }
    metrics_out["itu_val_random"] = val_ops
    print(f"  ROC-AUC={val_ops['roc_auc']:.4f}  PR-AUC={val_ops['pr_auc']:.4f}")
    print(f"  best F1={val_ops['best_f1']['f1']:.4f}  "
          f"recall@FPR=1%={val_ops['recall_at_fpr_0.01']['recall']:.4f}")

    # 2) ITU LHO test (heavy hitter rows)
    print("\n=== ITU LHO test (heavy hitters: ", HEAVY_HITTERS, ") ===")
    lho_mask = np.isin(src_ips, HEAVY_HITTERS)
    X_lho = X_all[lho_mask]
    y_lho = y_all[lho_mask]
    print(f"  LHO test rows: {len(X_lho):,}  ({(y_lho==1).sum():,} attack)")
    X_lho_scaled = scaler.transform(X_lho).astype(np.float32)
    X_lho_scaled = np.nan_to_num(X_lho_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    mse_lho = reconstruction_error(model, X_lho_scaled, batch_size=8192)
    pred_lho = (mse_lho >= threshold).astype(int)

    df_lho = pd.DataFrame({"actual": y_lho, "ae_mse": mse_lho,
                            "ae_score": mse_lho / max(threshold, 1e-12),
                            "ae_pred": pred_lho})
    df_lho.to_csv(out_dir / "ae_predictions_itu_lho.csv", index=False)
    print(f"  wrote {out_dir / 'ae_predictions_itu_lho.csv'}")

    lho_ops = operating_points(y_lho, mse_lho)
    lho_ops["at_training_threshold"] = {
        "recall": float(pred_lho[y_lho == 1].mean()) if (y_lho == 1).any() else None,
        "fpr": float(pred_lho[y_lho == 0].mean()) if (y_lho == 0).any() else None,
    }
    metrics_out["itu_lho"] = lho_ops
    print(f"  ROC-AUC={lho_ops['roc_auc']:.4f}  PR-AUC={lho_ops['pr_auc']:.4f}")
    print(f"  best F1={lho_ops['best_f1']['f1']:.4f}  "
          f"recall@FPR=1%={lho_ops['recall_at_fpr_0.01']['recall']:.4f}")

    out_metrics = REPO / "data/models/evaluation/autoencoder_itu_operating_points.json"
    out_metrics.parent.mkdir(parents=True, exist_ok=True)
    out_metrics.write_text(json.dumps(metrics_out, indent=2))
    print(f"\nWrote {out_metrics}")

if __name__ == "__main__":
    main()
