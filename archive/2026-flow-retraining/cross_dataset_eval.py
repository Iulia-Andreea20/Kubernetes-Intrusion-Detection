#!/usr/bin/env python3
"""Cross-dataset evaluation for tabular IDS models (XGBoost / LightGBM).

Loads a previously trained model and a new CSV (the "other" dataset),
aligns features by training schema, runs predictions, and reports metrics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from tabular_data import load_tabular, print_label_summary

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cross-dataset evaluation of a trained tree model.")
    parser.add_argument("--model-dir", required=True,
                        help="Directory containing model.json (XGBoost) or model.txt (LightGBM).")
    parser.add_argument("--model-type", choices=["xgboost", "lightgbm"], required=True)
    parser.add_argument("--feature-names",
                        help="Optional path to a feature names file (one per line). "
                             "If omitted, will try to read from metrics.json or feature_importance.csv.")
    parser.add_argument("--test-data", required=True, help="CSV from the other dataset.")
    parser.add_argument("--output-dir", default=None,
                        help="Where to write predictions and metrics. Defaults to model-dir/cross_eval/<test_csv_stem>.")
    parser.add_argument("--threshold", type=float, default=0.5)
    return parser.parse_args()

def load_feature_names(args: argparse.Namespace, model_dir: Path) -> list[str]:
    if args.feature_names:
        return [line.strip() for line in Path(args.feature_names).read_text().splitlines() if line.strip()]

    importance_path = model_dir / "feature_importance.csv"
    if importance_path.exists():
        return pd.read_csv(importance_path)["feature"].tolist()

    raise FileNotFoundError(
        "Could not determine feature names. Pass --feature-names or ensure "
        "feature_importance.csv exists in the model directory."
    )

def load_model(args: argparse.Namespace, model_dir: Path):
    if args.model_type == "xgboost":
        model = xgb.XGBClassifier()
        model.load_model(str(model_dir / "model.json"))
        return model
    booster = lgb.Booster(model_file=str(model_dir / "model.txt"))
    return booster

def predict(model, X: np.ndarray, model_type: str) -> np.ndarray:
    if model_type == "xgboost":
        return model.predict_proba(X)[:, 1]
    return model.predict(X)  # LightGBM Booster returns probabilities for binary.

def main() -> None:
    args = parse_args()
    model_dir = Path(args.model_dir)
    test_path = Path(args.test_data)
    if not test_path.exists():
        raise FileNotFoundError(f"Test CSV not found: {test_path}")

    output_dir = Path(args.output_dir) if args.output_dir else (model_dir / "cross_eval" / test_path.stem)
    output_dir.mkdir(parents=True, exist_ok=True)

    feature_names = load_feature_names(args, model_dir)
    model = load_model(args, model_dir)

    print(f"Loaded model: {model_dir} ({args.model_type})")
    print(f"Feature count: {len(feature_names)}")

    test_split = load_tabular(test_path)
    print_label_summary(test_split, "cross_test")

    aligned = test_split.X.copy()
    for column in feature_names:
        if column not in aligned.columns:
            aligned[column] = 0
    aligned = aligned[feature_names]

    proba = predict(model, aligned.values, args.model_type)
    preds = (proba >= args.threshold).astype(int)
    y = test_split.y

    metrics = {
        "threshold": args.threshold,
        "accuracy": float(accuracy_score(y, preds)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "confusion_matrix": confusion_matrix(y, preds).tolist(),
    }
    if len(np.unique(y)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y, proba))
        metrics["pr_auc"] = float(average_precision_score(y, proba))

    pd.DataFrame({"actual": y, "predicted": preds, "probability": proba}).to_csv(
        output_dir / "predictions_cross.csv", index=False
    )
    (output_dir / "metrics_cross.json").write_text(json.dumps({
        "test_data": str(test_path),
        "model_dir": str(model_dir),
        "model_type": args.model_type,
        "metrics": metrics,
    }, indent=2))

    print("\nCross-dataset metrics:")
    for key in ("accuracy", "f1", "precision", "recall", "roc_auc", "pr_auc"):
        if key in metrics:
            print(f"  {key}: {metrics[key]:.4f}")
    print("\nConfusion matrix:")
    print(np.array(metrics["confusion_matrix"]))
    print(f"\nResults saved to: {output_dir}")

if __name__ == "__main__":
    main()
