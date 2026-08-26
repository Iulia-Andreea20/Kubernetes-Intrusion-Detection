#!/usr/bin/env python3
"""Train an autoencoder backstop on BCCC benign flows.

Architecture: tiny MLP autoencoder (317 -> 128 -> 32 -> 8 -> 32 -> 128 -> 317).
Trained on benign rows only; reconstruction error becomes the anomaly score
at inference. Deployed in parallel with the supervised XGBoost classifier:
XGBoost catches known DDoS signatures, the autoencoder flags anything that
deviates from the benign distribution it learned -- the "unknown attack"
safety net.

Saves: model.pt, scaler.pkl, config.json, threshold.json, metrics.json.

Approach motivated by Mirsky et al. (Kitsune, NDSS 2018), Sarhan et al.
(NetFlow datasets, 2022) and Andresini et al. (hybrid AE+classifier, 2021)
- supervised + unsupervised hybrid as a defense against unknown attacks.
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

REPO = Path(__file__).resolve().parents[4]
REPO = REPO.parent
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
from tabular_data import load_tabular  # noqa: E402

SEED = 42

class TinyAutoencoder(nn.Module):
    """Symmetric MLP autoencoder.

    Default architecture (input_dim -> 128 -> 32 -> 8 -> 32 -> 128 -> input_dim)
    is intentionally small (~80k params) so it fits in a Kubernetes pod and
    trains in minutes on a laptop CPU.
    """

    def __init__(self, input_dim: int, bottleneck: int = 8,
                 hidden1: int = 128, hidden2: int = 32) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden1),
            nn.ReLU(),
            nn.Linear(hidden1, hidden2),
            nn.ReLU(),
            nn.Linear(hidden2, bottleneck),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, hidden2),
            nn.ReLU(),
            nn.Linear(hidden2, hidden1),
            nn.ReLU(),
            nn.Linear(hidden1, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

def reconstruction_error(model: TinyAutoencoder, X: np.ndarray,
                          batch_size: int = 4096) -> np.ndarray:
    """Per-row MSE between input and reconstruction."""
    model.eval()
    errors: list[np.ndarray] = []
    Xt = torch.from_numpy(X.astype(np.float32))
    with torch.no_grad():
        for i in range(0, len(Xt), batch_size):
            batch = Xt[i:i + batch_size]
            recon = model(batch)
            mse = ((batch - recon) ** 2).mean(dim=1).cpu().numpy()
            errors.append(mse)
    return np.concatenate(errors)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data", default=str(REPO / "data/bccc-retraining/holdout_split/train_without_holdout.csv"))
    parser.add_argument(
        "--output-dir", default=str(REPO / "data/models/flow-bccc/autoencoder_bccc"))
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--bottleneck", type=int, default=8)
    parser.add_argument("--val-frac", type=float, default=0.1)
    parser.add_argument("--patience", type=int, default=5)
    parser.add_argument("--threshold-percentile", type=float, default=95.0,
                        help="Percentile of validation benign MSE used as threshold.")
    args = parser.parse_args()

    torch.manual_seed(SEED)
    np.random.seed(SEED)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading training data from {args.data} ...")
    split = load_tabular(args.data)
    feature_names = split.feature_names
    X_all = split.X.to_numpy(dtype=np.float32)
    y_all = split.y.astype(int)
    n_total = len(X_all)
    print(f"  total: {n_total:,} rows, {len(feature_names)} features")
    print(f"  benign: {(y_all == 0).sum():,}, attack: {(y_all == 1).sum():,}")

    benign_mask = (y_all == 0)
    X_benign = X_all[benign_mask]
    print(f"Training on benign only: {len(X_benign):,} rows")

    # Shuffle + split benign into train / val for early stopping.
    rng = np.random.default_rng(SEED)
    indices = rng.permutation(len(X_benign))
    val_cut = int(len(X_benign) * (1 - args.val_frac))
    train_idx = indices[:val_cut]
    val_idx = indices[val_cut:]
    X_train_benign = X_benign[train_idx]
    X_val_benign = X_benign[val_idx]
    print(f"  train benign: {len(X_train_benign):,}")
    print(f"  val benign  : {len(X_val_benign):,}")

    # Standardise on TRAIN benign only (the deployed scaler).
    scaler = StandardScaler().fit(X_train_benign)
    X_train_scaled = scaler.transform(X_train_benign).astype(np.float32)
    X_val_scaled = scaler.transform(X_val_benign).astype(np.float32)
    # Replace any remaining NaN/Inf from numerically degenerate features.
    X_train_scaled = np.nan_to_num(X_train_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    X_val_scaled = np.nan_to_num(X_val_scaled, nan=0.0, posinf=0.0, neginf=0.0)

    input_dim = X_train_scaled.shape[1]
    model = TinyAutoencoder(input_dim=input_dim, bottleneck=args.bottleneck)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: TinyAutoencoder, {n_params:,} parameters, bottleneck={args.bottleneck}")

    optim = torch.optim.Adam(model.parameters(), lr=args.lr)
    loss_fn = nn.MSELoss()
    Xt_train = torch.from_numpy(X_train_scaled)
    Xt_val = torch.from_numpy(X_val_scaled)

    best_val = float("inf")
    best_state = None
    bad_epochs = 0
    history: list[dict] = []

    start = time.time()
    for epoch in range(1, args.epochs + 1):
        model.train()
        perm = torch.randperm(len(Xt_train))
        epoch_loss = 0.0
        nb = 0
        for i in range(0, len(perm), args.batch_size):
            idx = perm[i:i + args.batch_size]
            batch = Xt_train[idx]
            optim.zero_grad()
            recon = model(batch)
            loss = loss_fn(recon, batch)
            loss.backward()
            optim.step()
            epoch_loss += float(loss)
            nb += 1
        train_mse = epoch_loss / max(nb, 1)

        # Validation: mean reconstruction error on benign val.
        val_errors = reconstruction_error(model, X_val_scaled,
                                            batch_size=args.batch_size)
        val_mse = float(val_errors.mean())
        history.append({"epoch": epoch, "train_mse": train_mse, "val_mse": val_mse})
        print(f"  epoch {epoch:3d}  train_mse={train_mse:.6f}  val_mse={val_mse:.6f}")

        if val_mse < best_val - 1e-6:
            best_val = val_mse
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            bad_epochs = 0
        else:
            bad_epochs += 1
            if bad_epochs >= args.patience:
                print(f"  early stop after epoch {epoch} (no improvement for {args.patience}).")
                break

    train_time = time.time() - start
    if best_state is not None:
        model.load_state_dict(best_state)

    # Threshold from validation benign reconstruction error.
    val_errors = reconstruction_error(model, X_val_scaled, batch_size=args.batch_size)
    threshold = float(np.percentile(val_errors, args.threshold_percentile))
    print(f"Threshold @P{args.threshold_percentile}: {threshold:.6f}")
    print(f"Val benign MSE  mean={val_errors.mean():.6f}  "
          f"std={val_errors.std():.6f}  max={val_errors.max():.6f}")

    # Persist artefacts.
    torch.save(model.state_dict(), out_dir / "model.pt")
    with open(out_dir / "scaler.pkl", "wb") as fh:
        pickle.dump(scaler, fh)
    config = {
        "input_dim": int(input_dim),
        "bottleneck": int(args.bottleneck),
        "hidden1": 128,
        "hidden2": 32,
        "feature_names": list(feature_names),
        "trained_on": "BCCC benign-only flows",
        "training_data_path": args.data,
        "n_train_benign": int(len(X_train_benign)),
        "n_val_benign": int(len(X_val_benign)),
        "lr": args.lr,
        "batch_size": args.batch_size,
        "epochs_run": len(history),
        "training_time_seconds": train_time,
        "seed": SEED,
    }
    (out_dir / "config.json").write_text(json.dumps(config, indent=2))
    (out_dir / "threshold.json").write_text(json.dumps({
        "percentile": args.threshold_percentile,
        "threshold": threshold,
        "val_benign_mse_mean": float(val_errors.mean()),
        "val_benign_mse_std": float(val_errors.std()),
        "val_benign_mse_max": float(val_errors.max()),
    }, indent=2))
    (out_dir / "training_history.json").write_text(json.dumps(history, indent=2))
    metrics = {
        "best_val_mse": best_val,
        "threshold_percentile": args.threshold_percentile,
        "threshold": threshold,
        "training_time_seconds": train_time,
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nSaved model + scaler + config to {out_dir}")

if __name__ == "__main__":
    main()
