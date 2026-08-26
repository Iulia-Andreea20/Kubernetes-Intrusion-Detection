#!/usr/bin/env python3
"""ITU XGBoost evaluated under leave-heavy-hitter-out (LHO).

Trains on all benign + attacks from MINOR attackers; tests on held-out benign
plus attacks from the TOP-K heavy-hitter source IPs (which the model has never
seen). This is a more honest 'can it detect an unknown attacker?' test than
the random 80/20 split, because ITU is dominated by a few heavy-hitter IPs.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tabular_data import DROP_COLUMNS, detect_label_column, labels_to_binary  # noqa: E402

def to_numeric_features(df: pd.DataFrame, feat_cols: list[str]) -> np.ndarray:
    d = df[feat_cols].copy()
    for c in d.columns:
        if d[c].dtype == "object":
            mapped = d[c].astype(str).str.strip().str.lower().map(
                {"tcp": 6, "udp": 17, "icmp": 1})
            if mapped.notna().any():
                d[c] = mapped.fillna(0)
            else:
                d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.apply(pd.to_numeric, errors="coerce")
    d = d.replace([np.inf, -np.inf], np.nan).fillna(0)
    return d.values

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--top-k", type=int, default=3,
                        help="Number of heavy-hitter attacker IPs to leave out.")
    parser.add_argument("--benign-test-frac", type=float, default=0.3)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {args.data} ...")
    df = pd.read_csv(args.data, low_memory=False)
    print(f"  rows={len(df):,}")

    label_col = detect_label_column(df)
    df["_y"] = labels_to_binary(df[label_col])

    # Top-K heavy hitters by attack flow count
    attack_ips = df.loc[df._y == 1, "src_ip"].value_counts()
    heavy = attack_ips.head(args.top_k).index.tolist()
    total_attack = int(df._y.sum())
    print(f"  Heavy hitters (top {args.top_k}):")
    for ip in heavy:
        n = int(attack_ips[ip])
        print(f"    {ip}: {n:,} attack flows ({n / total_attack:.1%} of all attacks)")

    is_heavy_attack = (df._y == 1) & (df["src_ip"].isin(heavy))
    other_attack = (df._y == 1) & (~df["src_ip"].isin(heavy))
    is_benign = (df._y == 0)

    # Split benign randomly into train/test
    benign_idx = df.index[is_benign].to_numpy()
    rng = np.random.default_rng(42)
    rng.shuffle(benign_idx)
    n_test_b = int(len(benign_idx) * args.benign_test_frac)
    benign_test_idx = benign_idx[:n_test_b]
    benign_train_idx = benign_idx[n_test_b:]

    train_df = pd.concat([
        df.loc[benign_train_idx],
        df.loc[other_attack],
    ], ignore_index=True)
    test_df = pd.concat([
        df.loc[benign_test_idx],
        df.loc[is_heavy_attack],
    ], ignore_index=True)

    print(f"\n  TRAIN: {len(train_df):,} rows  "
          f"({(train_df._y == 0).sum():,} benign + {(train_df._y == 1).sum():,} attack)")
    print(f"  TEST : {len(test_df):,} rows  "
          f"({(test_df._y == 0).sum():,} benign + {(test_df._y == 1).sum():,} attack)")

    # Feature columns: drop identifiers + label + helper
    drop = set(DROP_COLUMNS) | {label_col, "_y"}
    feat_cols = [c for c in df.columns if c not in drop]

    X_train = to_numeric_features(train_df, feat_cols)
    y_train = train_df._y.to_numpy()
    X_test = to_numeric_features(test_df, feat_cols)
    y_test = test_df._y.to_numpy()

    n_pos = max(int((y_train == 1).sum()), 1)
    n_neg = max(int((y_train == 0).sum()), 1)
    spw = n_neg / n_pos
    print(f"\n  scale_pos_weight = {spw:.2f}  ({n_neg:,} neg / {n_pos:,} pos)")

    # Internal val for early stopping
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=42, stratify=y_train)

    model = xgb.XGBClassifier(
        n_estimators=500, max_depth=8, learning_rate=0.1,
        objective="binary:logistic", eval_metric="logloss",
        tree_method="hist", scale_pos_weight=spw,
        early_stopping_rounds=30, n_jobs=-1, random_state=42,
    )

    start = time.perf_counter()
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)
    train_time = time.perf_counter() - start
    print(f"\n  trained in {train_time:.1f}s")

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= args.threshold).astype(int)
    cm = confusion_matrix(y_test, pred, labels=[0, 1]).tolist()

    metrics = {
        "experiment": "leave-heavy-hitter-out",
        "heavy_hitter_ips": heavy,
        "top_k": args.top_k,
        "threshold": args.threshold,
        "training_time_seconds": train_time,
        "train_rows": int(len(y_train)),
        "test_rows": int(len(y_test)),
        "test_benign": int((y_test == 0).sum()),
        "test_attack": int((y_test == 1).sum()),
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, proba)),
        "pr_auc": float(average_precision_score(y_test, proba)),
        "confusion_matrix": cm,
        "false_positive_rate": cm[0][1] / max(cm[0][0] + cm[0][1], 1),
        "feature_count": len(feat_cols),
    }

    print("\n=== leave-heavy-hitter-out test metrics ===")
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc",
              "false_positive_rate"):
        print(f"  {k}: {metrics[k]:.4f}")
    print(f"  confusion: TN={cm[0][0]:,} FP={cm[0][1]:,} "
          f"FN={cm[1][0]:,} TP={cm[1][1]:,}")

    (outdir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    # Use booster API to avoid XGBoost newer-version sklearn mixin bug on save
    model.get_booster().save_model(str(outdir / "model.json"))

    pd.DataFrame({
        "actual": y_test, "predicted": pred, "probability": proba,
    }).to_csv(outdir / "predictions_test.csv", index=False)

    print(f"\n  saved to {outdir}")

if __name__ == "__main__":
    main()
