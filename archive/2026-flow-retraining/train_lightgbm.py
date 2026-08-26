#!/usr/bin/env python3
"""Train and evaluate a LightGBM classifier on BCCC or ITU/Sever CSV data."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

from tabular_data import load_tabular, print_label_summary

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train LightGBM on a CSV intrusion dataset.")
    parser.add_argument("--data", required=True, help="Training CSV path.")
    parser.add_argument("--test-data", default=None, help="Optional separate test CSV.")
    parser.add_argument("--output-dir", default="models/lightgbm_model", help="Output directory.")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--num-leaves", type=int, default=127)
    parser.add_argument("--max-depth", type=int, default=-1)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--n-estimators", type=int, default=1000)
    parser.add_argument("--min-data-in-leaf", type=int, default=100)
    parser.add_argument("--early-stopping", type=int, default=50)
    parser.add_argument("--threshold", type=float, default=0.5)
    return parser.parse_args()

def fit_lightgbm(args: argparse.Namespace, X_train, y_train, X_val, y_val) -> tuple[lgb.LGBMClassifier, float]:
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    scale_pos_weight = neg / max(pos, 1)

    model = lgb.LGBMClassifier(
        objective="binary",
        n_estimators=args.n_estimators,
        num_leaves=args.num_leaves,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        min_data_in_leaf=args.min_data_in_leaf,
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
        random_state=42,
        verbose=-1,
    )
    start = time.perf_counter()
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        eval_metric="binary_logloss",
        callbacks=[lgb.early_stopping(args.early_stopping, verbose=False)],
    )
    train_time = time.perf_counter() - start
    return model, train_time

def evaluate(model: lgb.LGBMClassifier, X, y, threshold: float):
    proba = model.predict_proba(X)[:, 1]
    preds = (proba >= threshold).astype(int)
    metrics = {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y, preds)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "confusion_matrix": confusion_matrix(y, preds).tolist(),
    }
    if len(np.unique(y)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y, proba))
        metrics["pr_auc"] = float(average_precision_score(y, proba))
    return metrics, proba, preds

def save_predictions(output_dir: Path, name: str, y, proba, preds) -> None:
    pd.DataFrame({"actual": y, "predicted": preds, "probability": proba}).to_csv(
        output_dir / f"predictions_{name}.csv", index=False
    )

def save_pr_roc_curves(output_dir: Path, name: str, y, proba) -> None:
    if len(np.unique(y)) < 2:
        return
    p, r, _ = precision_recall_curve(y, proba)
    fpr, tpr, _ = roc_curve(y, proba)
    pd.DataFrame({"precision": p, "recall": r}).to_csv(output_dir / f"pr_curve_{name}.csv", index=False)
    pd.DataFrame({"fpr": fpr, "tpr": tpr}).to_csv(output_dir / f"roc_curve_{name}.csv", index=False)

def save_feature_importance(output_dir: Path, model: lgb.LGBMClassifier, feature_names: list[str]) -> None:
    importance = model.feature_importances_
    df = pd.DataFrame({"feature": feature_names, "importance": importance})
    df.sort_values("importance", ascending=False).to_csv(
        output_dir / "feature_importance.csv", index=False
    )

def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Loading training data...")
    train_split = load_tabular(args.data, sample_size=args.sample_size)
    print_label_summary(train_split, "train_full")

    X_tr, X_val, y_tr, y_val = train_test_split(
        train_split.X.values, train_split.y,
        test_size=args.test_size, random_state=42, stratify=train_split.y
    )

    test_X, test_y = None, None
    if args.test_data:
        test_split = load_tabular(args.test_data)
        print_label_summary(test_split, "test_external")
        for column in train_split.feature_names:
            if column not in test_split.X.columns:
                test_split.X[column] = 0
        test_X = test_split.X[train_split.feature_names].values
        test_y = test_split.y

    print(f"Train shape: {X_tr.shape}, Val shape: {X_val.shape}")
    model, train_time = fit_lightgbm(args, X_tr, y_tr, X_val, y_val)
    print(f"Training time: {train_time:.1f}s")

    val_metrics, val_proba, val_preds = evaluate(model, X_val, y_val, args.threshold)
    print("\nValidation metrics (default threshold):")
    for key in ("accuracy", "f1", "precision", "recall", "roc_auc", "pr_auc"):
        if key in val_metrics:
            print(f"  {key}: {val_metrics[key]:.4f}")

    save_predictions(output_dir, "val", y_val, val_proba, val_preds)
    save_pr_roc_curves(output_dir, "val", y_val, val_proba)

    test_metrics = None
    if test_X is not None:
        test_metrics, test_proba, test_preds = evaluate(model, test_X, test_y, args.threshold)
        print("\nExternal test metrics (default threshold):")
        for key in ("accuracy", "f1", "precision", "recall", "roc_auc", "pr_auc"):
            if key in test_metrics:
                print(f"  {key}: {test_metrics[key]:.4f}")
        save_predictions(output_dir, "test", test_y, test_proba, test_preds)
        save_pr_roc_curves(output_dir, "test", test_y, test_proba)

    save_feature_importance(output_dir, model, train_split.feature_names)
    model.booster_.save_model(str(output_dir / "model.txt"))

    (output_dir / "metrics.json").write_text(json.dumps({
        "training_time_seconds": train_time,
        "train_rows": int(len(y_tr)),
        "val_rows": int(len(y_val)),
        "test_rows": int(len(test_y)) if test_y is not None else None,
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
        "feature_count": len(train_split.feature_names),
    }, indent=2))

    print(f"\nModel and metrics saved to: {output_dir}")

if __name__ == "__main__":
    main()
