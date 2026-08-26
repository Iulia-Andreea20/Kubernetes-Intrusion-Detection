#!/usr/bin/env python3
"""BCCC LHO: aligned predictions XGB (retrained LHO) + AE (existing BCCC) + hybrid.

Adapted from lho_hybrid_aligned.py with BCCC paths and heavy hitters.

Uses:
  - XGB LHO retrained pe BCCC train_without_holdout.csv (top 3 HH excluded)
  - the existing BCCC autoencoder (trained on benign only, 317 features)
  - BCCC heavy hitters: the top 3 attackers (130.63.226.46, 10.0.4.132, 141.98.11.161)
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

BCCC_CSV = REPO / "data/bccc-retraining/holdout_split/train_without_holdout.csv"
HEAVY_HITTERS = ["130.63.226.46", "10.0.4.132", "141.98.11.161"]

XGB_LHO_MODEL = REPO / "data/models/flow-bccc/xgboost_bccc_lho/model.json"
AE_BCCC_DIR = REPO / "data/models/flow-bccc/autoencoder_bccc"

OUT_DIR = REPO / "data/models/evaluation/autoencoder_predictions"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def main():
    print(f"Loading BCCC from {BCCC_CSV} ...", flush=True)
    split = load_tabular(str(BCCC_CSV))
    X_all = split.X.to_numpy(dtype=np.float32)
    y_all = split.y.astype(int)
    feature_names = split.feature_names
    print(f"  total: {len(X_all):,} rows, {len(feature_names)} features", flush=True)

    print("Loading src_ip column for LHO partition ...", flush=True)
    src_ips = pd.read_csv(str(BCCC_CSV), usecols=["src_ip"])["src_ip"].to_numpy()
    assert len(src_ips) == len(X_all), \
        f"Row mismatch: src_ips={len(src_ips)} vs features={len(X_all)}"

    lho_mask = np.isin(src_ips, HEAVY_HITTERS)
    X_lho = X_all[lho_mask].copy()  # explicit copy so X_all can be released
    y_lho = y_all[lho_mask].copy()
    print(f"  LHO test: {len(X_lho):,} rows ({(y_lho==1).sum():,} attack, "
          f"{(y_lho==0).sum():,} benign)", flush=True)

    # Free memory: drop full BCCC arrays + src_ips + split (~1 GB freed)
    import gc
    del X_all, y_all, src_ips, split
    gc.collect()
    print(f"  Memory freed after LHO extraction.", flush=True)

    # 1. XGBoost LHO predictions (Booster API + chunked for safety)
    print(f"\nLoading XGBoost BCCC LHO from {XGB_LHO_MODEL} ...", flush=True)
    booster = xgb.Booster()
    booster.load_model(str(XGB_LHO_MODEL))
    print(f"  booster expects {booster.num_features()} features, data has {X_lho.shape[1]}", flush=True)

    X_lho_clean = np.ascontiguousarray(X_lho, dtype=np.float32)
    X_lho_clean = np.nan_to_num(X_lho_clean, nan=0.0, posinf=0.0, neginf=0.0)

    print(f"  predicting in chunks of 20k rows...", flush=True)
    CHUNK = 20_000
    xgb_proba_chunks = []
    n_chunks = (len(X_lho_clean) + CHUNK - 1) // CHUNK
    for ci in range(n_chunks):
        start = ci * CHUNK
        end = min(start + CHUNK, len(X_lho_clean))
        dmat = xgb.DMatrix(X_lho_clean[start:end])
        chunk_proba = booster.predict(dmat)
        xgb_proba_chunks.append(chunk_proba)
        del dmat
        if ci % 10 == 0 or ci == n_chunks - 1:
            print(f"    chunk {ci+1}/{n_chunks}", flush=True)
    xgb_proba = np.concatenate(xgb_proba_chunks)
    xgb_pred = (xgb_proba >= 0.5).astype(int)
    print(f"  XGB predicted positive: {xgb_pred.sum():,}/{len(xgb_pred):,}  "
          f"({xgb_pred[y_lho==1].sum()/(y_lho==1).sum()*100:.1f}% recall on attack)", flush=True)

    xgb_path = OUT_DIR / "xgb_bccc_lho_aligned.csv"
    pd.DataFrame({
        "actual": y_lho,
        "predicted": xgb_pred,
        "probability": xgb_proba,
    }).to_csv(xgb_path, index=False)
    print(f"  wrote {xgb_path}", flush=True)

    # 2. AE predictions on same aligned rows
    print(f"\nLoading AE BCCC from {AE_BCCC_DIR} ...", flush=True)
    config = json.loads((AE_BCCC_DIR / "config.json").read_text())
    threshold = json.loads((AE_BCCC_DIR / "threshold.json").read_text())["threshold"]
    with open(AE_BCCC_DIR / "scaler.pkl", "rb") as fh:
        scaler = pickle.load(fh)
    ae_model = TinyAutoencoder(
        input_dim=int(config["input_dim"]),
        bottleneck=int(config["bottleneck"]),
        hidden1=int(config["hidden1"]),
        hidden2=int(config["hidden2"]),
    )
    ae_model.load_state_dict(torch.load(AE_BCCC_DIR / "model.pt", map_location="cpu"))
    ae_model.eval()
    print(f"  AE input_dim={config['input_dim']}, threshold P95={threshold:.6f}", flush=True)

    X_lho_scaled = scaler.transform(X_lho).astype(np.float32)
    X_lho_scaled = np.nan_to_num(X_lho_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    ae_mse = reconstruction_error(ae_model, X_lho_scaled, batch_size=8192)
    ae_pred = (ae_mse >= threshold).astype(int)
    print(f"  AE predicted positive (mse >= P95): {ae_pred.sum():,}/{len(ae_pred):,}  "
          f"({ae_pred[y_lho==1].sum()/(y_lho==1).sum()*100:.1f}% recall on attack)", flush=True)

    ae_path = OUT_DIR / "ae_bccc_lho_aligned.csv"
    pd.DataFrame({
        "actual": y_lho,
        "ae_mse": ae_mse,
        "ae_score": ae_mse / max(threshold, 1e-12),
        "ae_pred": ae_pred,
    }).to_csv(ae_path, index=False)
    print(f"  wrote {ae_path}", flush=True)

    # 3. Run hybrid_flow.py for fusion
    print("\nRunning hybrid_flow.py for BCCC LHO with aligned predictions ...", flush=True)
    out_metrics = REPO / "data/models/evaluation/flow_hybrid_bccc_lho_aligned.json"
    result = subprocess.run([
        "python3", str(Path(__file__).parent / "hybrid_flow.py"),
        "--xgb-predictions", str(xgb_path),
        "--ae-predictions", str(ae_path),
        "--out", str(out_metrics),
    ], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr)
    print(f"\nFinal metrics: {out_metrics}", flush=True)

if __name__ == "__main__":
    main()
