#!/usr/bin/env python3
"""Hybrid Flow detector: XGBoost (supervised, known DDoS) + Autoencoder
(unsupervised, novel anomaly backstop).

Combines per-event scores from both models and reports operating points for
four fusion strategies:

  - xgb_only            baseline: just XGBoost calibrated probability
  - ae_only             baseline: just AE anomaly score (Platt-calibrated)
  - score_mean          simple average of calibrated XGB + AE scores
  - max_calibrated      OR-style: max(p_xgb, p_ae)  -- maximises coverage
  - weighted (0.7/0.3)  default weighted sum tuned for precision

Calibration is fitted on the FIRST HALF of the BCCC held-out predictions and
evaluated on the SECOND HALF, so the reported metrics are honest.

Output: ``data/models/evaluation/flow_hybrid_metrics.json``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix,
                              precision_recall_curve, roc_auc_score, roc_curve)

REPO = Path(__file__).resolve().parents[4]
REPO = REPO.parent

def fit_calibrator(scores: np.ndarray, labels: np.ndarray) -> LogisticRegression:
    """Platt scaling: logistic regression on (score, label)."""
    cal = LogisticRegression()
    cal.fit(scores.reshape(-1, 1), labels)
    return cal

def calibrate(cal: LogisticRegression, scores: np.ndarray) -> np.ndarray:
    return cal.predict_proba(scores.reshape(-1, 1))[:, 1]

def operating_points(y_true: np.ndarray, y_score: np.ndarray) -> dict:
    out: dict = {
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
    fpr_curve, tpr_curve, thr_curve = roc_curve(y_true, y_score)
    for target_fpr in (0.01, 0.001):
        mask = fpr_curve <= target_fpr
        if mask.any():
            i = int(np.where(mask)[0][np.argmax(tpr_curve[mask])])
        else:
            i = int(np.argmin(fpr_curve))
        out[f"recall_at_fpr_{target_fpr}"] = {
            "achieved_fpr": float(fpr_curve[i]),
            "recall": float(tpr_curve[i]),
        }
    for target_recall in (0.95, 0.99):
        mask = tpr_curve >= target_recall
        if mask.any():
            i = int(np.where(mask)[0][np.argmin(fpr_curve[mask])])
        else:
            i = int(np.argmax(tpr_curve))
        out[f"fpr_at_recall_{target_recall}"] = {
            "achieved_recall": float(tpr_curve[i]),
            "fpr": float(fpr_curve[i]),
        }
    # At default 0.5 threshold (post-calibration both scores are probabilities)
    pred = (y_score >= 0.5).astype(int)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    out["at_threshold_0.5"] = {
        "tp": int(cm[1, 1]), "fp": int(cm[0, 1]),
        "tn": int(cm[0, 0]), "fn": int(cm[1, 0]),
        "precision": float(cm[1, 1] / max(cm[1, 1] + cm[0, 1], 1)),
        "recall": float(cm[1, 1] / max(cm[1, 1] + cm[1, 0], 1)),
        "fpr": float(cm[0, 1] / max(cm[0, 0] + cm[0, 1], 1)),
    }
    return out

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--xgb-predictions",
        default=str(REPO / "data/models/flow-bccc/xgboost_bccc/predictions_test.csv"))
    parser.add_argument(
        "--ae-predictions",
        default=str(REPO / "data/models/evaluation/autoencoder_predictions/ae_predictions_bccc_test_heldout_day.csv"))
    parser.add_argument(
        "--out",
        default=str(REPO / "data/models/evaluation/flow_hybrid_metrics.json"))
    args = parser.parse_args()

    xgb = pd.read_csv(args.xgb_predictions)
    ae = pd.read_csv(args.ae_predictions)
    assert len(xgb) == len(ae), \
        f"row mismatch: xgb={len(xgb)} ae={len(ae)}"
    assert (xgb["actual"].to_numpy() == ae["actual"].to_numpy()).all(), \
        "label alignment mismatch -- predictions are in different row order!"

    y = xgb["actual"].astype(int).to_numpy()
    xgb_raw = xgb["probability"].astype(float).to_numpy()
    ae_raw = ae["ae_mse"].astype(float).to_numpy()

    print(f"Hybrid evaluation on {len(y):,} rows "
          f"({(y==1).sum():,} attack, {(y==0).sum():,} benign)")

    # Split 50/50 -- calibration vs evaluation -- in row order (the predictions
    # are already in test-set row order = held-out day in time order).
    half = len(y) // 2
    y_cal, y_eval = y[:half], y[half:]
    xgb_cal, xgb_eval = xgb_raw[:half], xgb_raw[half:]
    ae_cal, ae_eval = ae_raw[:half], ae_raw[half:]

    xgb_calibrator = fit_calibrator(xgb_cal, y_cal)
    ae_calibrator = fit_calibrator(np.log1p(ae_cal), y_cal)  # log-transform MSE first
    print("Fitted Platt calibrators on calibration half.")

    p_xgb = calibrate(xgb_calibrator, xgb_eval)
    p_ae = calibrate(ae_calibrator, np.log1p(ae_eval))

    strategies = {
        "xgb_only_raw":      xgb_eval,
        "ae_only_raw":       ae_eval,
        "xgb_only_calibrated": p_xgb,
        "ae_only_calibrated":  p_ae,
        "score_mean":        (p_xgb + p_ae) / 2.0,
        "max_calibrated":    np.maximum(p_xgb, p_ae),
        "weighted_70_30":    0.7 * p_xgb + 0.3 * p_ae,
    }

    results: dict = {
        "calibration_n": int(half),
        "evaluation_n": int(len(y) - half),
        "evaluation_attack": int((y_eval == 1).sum()),
        "evaluation_benign": int((y_eval == 0).sum()),
        "strategies": {},
    }

    print("\n=== Operating points per fusion strategy ===\n")
    print(f"{'strategy':<22}{'ROC-AUC':>9}{'PR-AUC':>9}"
          f"{'best_F1':>10}{'rec@FPR=1%':>13}{'FPR@rec=95%':>13}")
    print("-" * 76)
    for name, score in strategies.items():
        ops = operating_points(y_eval, score)
        results["strategies"][name] = ops
        bf = ops.get("best_f1", {})
        r1 = ops.get("recall_at_fpr_0.01", {}).get("recall", 0)
        f95 = ops.get("fpr_at_recall_0.95", {}).get("fpr", 0)
        print(f"{name:<22}{ops['roc_auc']:>9.4f}{ops['pr_auc']:>9.4f}"
              f"{bf.get('f1', 0):>10.4f}{r1:>13.4f}{f95:>13.4f}")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nWrote {args.out}")

if __name__ == "__main__":
    main()
