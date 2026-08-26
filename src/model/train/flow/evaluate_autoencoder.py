#!/usr/bin/env python3
"""Evaluate the trained autoencoder backstop on Flow test sets.

For each test set:
  * Compute per-row reconstruction MSE.
  * Compute operating points (ROC-AUC, PR-AUC, recall@FPR=1%, FPR@recall=95%, ...).
  * Save predictions.csv (actual, ae_mse, ae_score, ae_pred_at_threshold).

The "ae_score" column is the MSE normalised by the training threshold so it is
on a comparable [0, ~10] scale across test sets; "ae_pred_at_threshold" is 1
if MSE >= training threshold (the >=P95 of validation benign MSE).

Output: ``data/models/evaluation/autoencoder_operating_points.json``.
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                              roc_auc_score, roc_curve)

REPO = Path(__file__).resolve().parents[4]
REPO = REPO.parent
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tabular_data import load_tabular  # noqa: E402
from train_autoencoder import TinyAutoencoder, reconstruction_error  # noqa: E402

AE_DIR = REPO / "data/models/flow-bccc/autoencoder_bccc"

TEST_SETS = {
    "bccc_test_heldout_day":
        REPO / "data/bccc-retraining/holdout_split/test_holdout.csv",
    "cic2018_test_novel_attacks":
        REPO / "data/bccc-retraining/cic2018_split/test.csv",
}

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

def best_f1_from_pr(y_true: np.ndarray, y_score: np.ndarray) -> dict:
    prec, rec, thr = precision_recall_curve(y_true, y_score)
    f1 = 2 * prec[:-1] * rec[:-1] / (prec[:-1] + rec[:-1] + 1e-12)
    if len(f1) == 0:
        return {}
    idx = int(np.argmax(f1))
    return {"threshold": float(thr[idx]),
            "precision": float(prec[idx]),
            "recall": float(rec[idx]),
            "f1": float(f1[idx])}

def recall_at_fpr(y_true: np.ndarray, y_score: np.ndarray, target_fpr: float) -> dict:
    fpr, tpr, thr = roc_curve(y_true, y_score)
    mask = fpr <= target_fpr
    if not mask.any():
        idx = int(np.argmin(fpr))
    else:
        idx = int(np.where(mask)[0][np.argmax(tpr[mask])])
    return {"target_fpr": target_fpr,
            "achieved_fpr": float(fpr[idx]),
            "recall": float(tpr[idx]),
            "threshold": float(thr[idx]) if idx < len(thr) else None}

def fpr_at_recall(y_true: np.ndarray, y_score: np.ndarray, target_recall: float) -> dict:
    fpr, tpr, thr = roc_curve(y_true, y_score)
    mask = tpr >= target_recall
    if not mask.any():
        idx = int(np.argmax(tpr))
    else:
        idx = int(np.where(mask)[0][np.argmin(fpr[mask])])
    return {"target_recall": target_recall,
            "achieved_recall": float(tpr[idx]),
            "fpr": float(fpr[idx])}

def evaluate_on_csv(name: str, csv_path: Path, model: TinyAutoencoder,
                     scaler, threshold: float, feature_names: list[str],
                     out_dir: Path) -> dict:
    print(f"\n=== {name}  ({csv_path}) ===")
    split = load_tabular(csv_path)
    X = split.X.to_numpy(dtype=np.float32)
    y = split.y.astype(int)
    print(f"  rows: {len(X):,}  ({(y==1).sum():,} attack)")

    # Schema alignment: pad missing BCCC features with 0, drop extras.
    test_feat_set = set(split.feature_names)
    extras = test_feat_set - set(feature_names)
    missing = set(feature_names) - test_feat_set
    if extras or missing:
        print(f"  schema diff: {len(missing)} missing, {len(extras)} extra "
              f"(reindexed to BCCC schema, zero-filled)")
        aligned = pd.DataFrame(X, columns=split.feature_names)
        aligned = aligned.reindex(columns=feature_names, fill_value=0.0)
        X = aligned.to_numpy(dtype=np.float32)

    # Standardise with the BCCC-trained scaler.
    X_scaled = scaler.transform(X).astype(np.float32)
    X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

    mse = reconstruction_error(model, X_scaled, batch_size=4096)
    # ae_score: MSE / threshold (relative, so >1 means above the training cap).
    score = mse / max(threshold, 1e-12)
    pred = (mse >= threshold).astype(int)

    # If all labels are one class, skip ROC/PR.
    n_classes = len(np.unique(y))
    metrics: dict = {
        "rows": int(len(X)),
        "n_attack": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
        "ae_threshold": float(threshold),
        "mse_stats": {
            "benign_mean": float(mse[y == 0].mean()) if (y == 0).any() else None,
            "benign_median": float(np.median(mse[y == 0])) if (y == 0).any() else None,
            "benign_p95": float(np.percentile(mse[y == 0], 95)) if (y == 0).any() else None,
            "attack_mean": float(mse[y == 1].mean()) if (y == 1).any() else None,
            "attack_median": float(np.median(mse[y == 1])) if (y == 1).any() else None,
            "attack_p05": float(np.percentile(mse[y == 1], 5)) if (y == 1).any() else None,
        },
        "at_training_threshold": {
            "recall": float(pred[y == 1].mean()) if (y == 1).any() else None,
            "fpr": float(pred[y == 0].mean()) if (y == 0).any() else None,
        },
    }

    if n_classes > 1:
        metrics["roc_auc"] = float(roc_auc_score(y, mse))
        metrics["pr_auc"] = float(average_precision_score(y, mse))
        metrics["best_f1"] = best_f1_from_pr(y, mse)
        metrics["recall_at_fpr_0.01"] = recall_at_fpr(y, mse, 0.01)
        metrics["recall_at_fpr_0.001"] = recall_at_fpr(y, mse, 0.001)
        metrics["fpr_at_recall_0.95"] = fpr_at_recall(y, mse, 0.95)
        metrics["fpr_at_recall_0.99"] = fpr_at_recall(y, mse, 0.99)

    print(f"  benign MSE mean/median/p95 = "
          f"{metrics['mse_stats']['benign_mean']:.4f} / "
          f"{metrics['mse_stats']['benign_median']:.4f} / "
          f"{metrics['mse_stats']['benign_p95']:.4f}")
    print(f"  attack MSE mean/median/p05 = "
          f"{metrics['mse_stats']['attack_mean']:.4f} / "
          f"{metrics['mse_stats']['attack_median']:.4f} / "
          f"{metrics['mse_stats']['attack_p05']:.4f}")
    if "roc_auc" in metrics:
        print(f"  ROC-AUC = {metrics['roc_auc']:.4f}  PR-AUC = {metrics['pr_auc']:.4f}")
        bf = metrics["best_f1"]
        print(f"  best F1 = {bf['f1']:.4f} @thr={bf['threshold']:.4f} "
              f"(prec={bf['precision']:.3f} rec={bf['recall']:.3f})")
        print(f"  recall @ FPR=1%  = {metrics['recall_at_fpr_0.01']['recall']:.4f}")
        print(f"  FPR @ recall=95% = {metrics['fpr_at_recall_0.95']['fpr']:.4f}")
    print(f"  @training threshold: recall={metrics['at_training_threshold']['recall']:.4f}, "
          f"FPR={metrics['at_training_threshold']['fpr']:.4f}")

    # Save per-row predictions for downstream hybrid fusion.
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_path = out_dir / f"ae_predictions_{name}.csv"
    pd.DataFrame({"actual": y, "ae_mse": mse,
                  "ae_score": score, "ae_pred": pred}).to_csv(pred_path, index=False)
    print(f"  wrote {pred_path}")
    return metrics

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ae-dir", default=str(AE_DIR))
    parser.add_argument("--out",
                        default=str(REPO / "data/models/evaluation/autoencoder_operating_points.json"))
    parser.add_argument("--predictions-dir",
                        default=str(REPO / "data/models/evaluation/autoencoder_predictions"))
    args = parser.parse_args()

    ae_dir = Path(args.ae_dir)
    model, scaler, threshold, config = load_autoencoder(ae_dir)
    feature_names = config["feature_names"]
    print(f"Loaded autoencoder from {ae_dir}")
    print(f"  input_dim={config['input_dim']}  bottleneck={config['bottleneck']}")
    print(f"  threshold (P95 val benign) = {threshold:.6f}")

    results: dict[str, dict] = {}
    pred_dir = Path(args.predictions_dir)
    for name, path in TEST_SETS.items():
        if not path.exists():
            print(f"  SKIP {name}: {path} not found")
            continue
        results[name] = evaluate_on_csv(name, path, model, scaler, threshold,
                                          feature_names, pred_dir)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {out_path}")

if __name__ == "__main__":
    main()
