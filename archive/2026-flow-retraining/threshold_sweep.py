#!/usr/bin/env python3
"""Sweep decision thresholds over a predictions.csv from any model.

This script is model-agnostic. Train any model, dump a predictions CSV with
columns (actual, probability), and run this script to compute per-threshold
metrics, ROC, PR curves, and operating-point recommendations for an IDS.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threshold sweep / IDS operating-point analysis.")
    parser.add_argument("--predictions", required=True,
                        help="Path to predictions CSV (must have columns 'actual' and 'probability').")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (defaults to predictions CSV's parent).")
    parser.add_argument("--start", type=float, default=0.05)
    parser.add_argument("--stop", type=float, default=0.95)
    parser.add_argument("--step", type=float, default=0.05)
    return parser.parse_args()

def evaluate_at_threshold(y, proba, threshold: float) -> dict:
    preds = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()

    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y, preds)),
        "balanced_accuracy": float(balanced_accuracy_score(y, preds)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }

def find_operating_points(rows: list[dict]) -> dict:
    df = pd.DataFrame(rows)
    best_f1 = df.iloc[df["f1"].idxmax()].to_dict()
    best_balanced = df.iloc[df["balanced_accuracy"].idxmax()].to_dict()

    recall_95 = df[df["recall"] >= 0.95].sort_values("precision", ascending=False).head(1)
    recall_99 = df[df["recall"] >= 0.99].sort_values("precision", ascending=False).head(1)

    points = {
        "best_f1": best_f1,
        "best_balanced_accuracy": best_balanced,
    }
    if not recall_95.empty:
        points["recall_at_least_0.95_max_precision"] = recall_95.iloc[0].to_dict()
    if not recall_99.empty:
        points["recall_at_least_0.99_max_precision"] = recall_99.iloc[0].to_dict()
    return points

def main() -> None:
    args = parse_args()
    predictions_path = Path(args.predictions)
    if not predictions_path.exists():
        raise FileNotFoundError(f"Predictions file not found: {predictions_path}")

    output_dir = Path(args.output_dir) if args.output_dir else predictions_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(predictions_path)
    if "actual" not in df.columns or "probability" not in df.columns:
        raise ValueError("predictions CSV must contain columns 'actual' and 'probability'")

    y = df["actual"].astype(int).values
    proba = df["probability"].astype(float).values

    thresholds = np.arange(args.start, args.stop + 1e-9, args.step)
    rows = [evaluate_at_threshold(y, proba, float(t)) for t in thresholds]
    sweep_df = pd.DataFrame(rows)

    name = predictions_path.stem.replace("predictions_", "")
    sweep_df.to_csv(output_dir / f"threshold_sweep_{name}.csv", index=False)

    operating = find_operating_points(rows)
    summary = {
        "input": str(predictions_path),
        "samples": int(len(y)),
        "positive_count": int((y == 1).sum()),
        "negative_count": int((y == 0).sum()),
        "roc_auc": float(roc_auc_score(y, proba)) if len(np.unique(y)) > 1 else None,
        "pr_auc": float(average_precision_score(y, proba)) if len(np.unique(y)) > 1 else None,
        "operating_points": operating,
    }
    (output_dir / f"threshold_summary_{name}.json").write_text(json.dumps(summary, indent=2))

    print(f"\nThreshold sweep written to: {output_dir / f'threshold_sweep_{name}.csv'}")
    print(f"Summary written to:         {output_dir / f'threshold_summary_{name}.json'}\n")
    print("Operating point recommendations:")
    for name, point in operating.items():
        print(f"  [{name}] threshold={point['threshold']:.2f} "
              f"f1={point['f1']:.4f} precision={point['precision']:.4f} "
              f"recall={point['recall']:.4f} fpr={point['false_positive_rate']:.4f}")

if __name__ == "__main__":
    main()
