#!/usr/bin/env python3
"""Build aligned XGB + AE predictions on ITU LHO test rows, then run hybrid fusion.

Both models are evaluated on the SAME rows in the SAME order (heavy-hitter rows
from itu.csv, in CSV row order). This produces aligned per-row predictions so
hybrid_flow.py can fuse them via Platt calibration without the row-mismatch
assertion failure.
"""
from __future__ import annotations

import json
import pickle
import sys
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import xgboost as xgb

REPO = Path(__file__).resolve().parents[4]
REPO = REPO.parent
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tabular_data import load_tabular  # noqa: E402
from train_autoencoder import TinyAutoencoder, reconstruction_error  # noqa: E402

ITU_CSV = REPO / "itu_dataset_clean.csv"
HEAVY_HITTERS = ["100.64.0.2", "10.16.0.6", "10.16.0.5"]

XGB_LHO_MODEL = REPO / "cluster/dizertatie/data/models/flow-bccc/xgboost_itu_lho/model.json"
AE_ITU_DIR = REPO / "data/models/autoencoder_itu"

OUT_DIR = REPO / "data/models/evaluation/autoencoder_predictions"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def main():
    # 1. Load ITU with canonical preprocessing
    print(f"Loading ITU from {ITU_CSV} ...")
    split = load_tabular(str(ITU_CSV))
    X_all = split.X.to_numpy(dtype=np.float32)
    y_all = split.y.astype(int)
    feature_names = split.feature_names
    print(f"  total: {len(X_all):,} rows, {len(feature_names)} features")

    # 2. Load Src IP for LHO partition
    src_ips = pd.read_csv(str(ITU_CSV), usecols=["Src IP"])["Src IP"].to_numpy()
    lho_mask = np.isin(src_ips, HEAVY_HITTERS)
    X_lho = X_all[lho_mask]
    y_lho = y_all[lho_mask]
    print(f"  LHO test: {len(X_lho):,} rows ({(y_lho==1).sum():,} attack, {(y_lho==0).sum():,} benign)")

    # 3. XGBoost LHO predictions on aligned set (chunked to avoid OOM/segfault)
    print(f"\nLoading XGBoost LHO from {XGB_LHO_MODEL} ...", flush=True)
    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model(str(XGB_LHO_MODEL))
    print(f"  model expects {xgb_model.n_features_in_} features, data has {X_lho.shape[1]}", flush=True)
    print(f"  predicting in chunks of 100k rows...", flush=True)
    CHUNK = 100_000
    xgb_proba_chunks = []
    for start in range(0, len(X_lho), CHUNK):
        end = min(start + CHUNK, len(X_lho))
        chunk_proba = xgb_model.predict_proba(X_lho[start:end])[:, 1]
        xgb_proba_chunks.append(chunk_proba)
        if (start // CHUNK) % 5 == 0:
            print(f"    chunk {start//CHUNK + 1}/{(len(X_lho) + CHUNK - 1)//CHUNK}", flush=True)
    xgb_proba = np.concatenate(xgb_proba_chunks)
    xgb_pred = (xgb_proba >= 0.5).astype(int)
    print(f"  XGB predicted positive: {xgb_pred.sum():,}/{len(xgb_pred):,}  "
          f"({xgb_pred[y_lho==1].sum()/(y_lho==1).sum()*100:.1f}% recall on attack)")

    xgb_df = pd.DataFrame({
        "actual": y_lho,
        "predicted": xgb_pred,
        "probability": xgb_proba,
    })
    xgb_path = OUT_DIR / "xgb_lho_aligned.csv"
    xgb_df.to_csv(xgb_path, index=False)
    print(f"  wrote {xgb_path}")

    # 4. AE LHO predictions on aligned set
    print(f"\nLoading AE from {AE_ITU_DIR} ...")
    config = json.loads((AE_ITU_DIR / "config.json").read_text())
    threshold = json.loads((AE_ITU_DIR / "threshold.json").read_text())["threshold"]
    with open(AE_ITU_DIR / "scaler.pkl", "rb") as fh:
        scaler = pickle.load(fh)
    ae_model = TinyAutoencoder(
        input_dim=int(config["input_dim"]),
        bottleneck=int(config["bottleneck"]),
        hidden1=int(config["hidden1"]),
        hidden2=int(config["hidden2"]),
    )
    ae_model.load_state_dict(torch.load(AE_ITU_DIR / "model.pt", map_location="cpu"))
    ae_model.eval()

    X_lho_scaled = scaler.transform(X_lho).astype(np.float32)
    X_lho_scaled = np.nan_to_num(X_lho_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    ae_mse = reconstruction_error(ae_model, X_lho_scaled, batch_size=8192)
    ae_pred = (ae_mse >= threshold).astype(int)
    print(f"  AE predicted positive (mse >= P95): {ae_pred.sum():,}/{len(ae_pred):,}  "
          f"({ae_pred[y_lho==1].sum()/(y_lho==1).sum()*100:.1f}% recall on attack)")

    ae_df = pd.DataFrame({
        "actual": y_lho,
        "ae_mse": ae_mse,
        "ae_score": ae_mse / max(threshold, 1e-12),
        "ae_pred": ae_pred,
    })
    ae_path = OUT_DIR / "ae_lho_aligned.csv"
    ae_df.to_csv(ae_path, index=False)
    print(f"  wrote {ae_path}")

    # 5. Run hybrid_flow.py with aligned files
    print("\nRunning hybrid_flow.py for ITU LHO with aligned predictions ...")
    out_metrics = REPO / "data/models/evaluation/flow_hybrid_itu_lho_aligned.json"
    result = subprocess.run([
        "python3", str(Path(__file__).parent / "hybrid_flow.py"),
        "--xgb-predictions", str(xgb_path),
        "--ae-predictions", str(ae_path),
        "--out", str(out_metrics),
    ], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr)

if __name__ == "__main__":
    main()
