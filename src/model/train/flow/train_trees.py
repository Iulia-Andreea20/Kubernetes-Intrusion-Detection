#!/usr/bin/env python3
"""Train the tabular baselines - XGBoost and LightGBM - for the runtime IDS.

Input : data/features_tabular.csv      (from features/featurize.py)
Outputs (per model, under models/<name>_audit/):
  metrics.json            test metrics + per-attack-type recall
  predictions.csv         timestamp,user,attack_type,label,prob,pred
  feature_importance.csv  ranked feature importances
  feature_names.json      feature column order (needed by the IDS service)
  model.json / model.txt  the trained model
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

META = ["timestamp", "user", "attack_type", "label"]

def run_model(make_model, save_model, df, feature_cols, train_idx, test_idx, outdir):
    X = df[feature_cols].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)
    attack_type = df["attack_type"].fillna("").to_numpy(dtype=object)

    n_pos = max(int(y[train_idx].sum()), 1)
    n_neg = max(int((y[train_idx] == 0).sum()), 1)
    scale_pos_weight = n_neg / n_pos          # counteracts class imbalance

    model = make_model(scale_pos_weight)
    model.fit(X[train_idx], y[train_idx])

    prob = model.predict_proba(X[test_idx])[:, 1]
    pred = (prob >= 0.5).astype(int)

    metrics = common.binary_metrics(y[test_idx], prob)
    metrics["false_positive_rate"] = common.false_positive_rate(y[test_idx], pred)
    metrics["per_attack_recall"] = common.per_attack_recall(
        y[test_idx], pred, attack_type[test_idx])
    metrics["train_rows"] = int(len(train_idx))
    metrics["test_rows"] = int(len(test_idx))

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    common.save_json(metrics, outdir / "metrics.json")
    pd.DataFrame({
        "timestamp": df["timestamp"].to_numpy()[test_idx],
        "user": df["user"].to_numpy()[test_idx],
        "attack_type": attack_type[test_idx],
        "label": y[test_idx], "prob": prob, "pred": pred,
    }).to_csv(outdir / "predictions.csv", index=False)
    pd.DataFrame({"feature": feature_cols,
                  "importance": model.feature_importances_}) \
        .sort_values("importance", ascending=False) \
        .to_csv(outdir / "feature_importance.csv", index=False)
    common.save_json(feature_cols, outdir / "feature_names.json")
    save_model(model, outdir)
    return metrics

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", default=str(REPO / "archive/audit-v1-kind-transformer/data/features_tabular.csv"))
    parser.add_argument("--outdir", default=str(REPO / "data/models"))
    parser.add_argument("--train-frac", type=float, default=0.7)
    args = parser.parse_args()

    import lightgbm as lgb
    import xgboost as xgb

    df = pd.read_csv(args.features)
    feature_cols = [c for c in df.columns if c not in META]
    train_idx, test_idx = common.time_split(len(df), args.train_frac)
    print(f"Loaded {len(df)} events, {len(feature_cols)} features  "
          f"(train={len(train_idx)} test={len(test_idx)})")

    results = {}
    results["xgboost"] = run_model(
        lambda spw: xgb.XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, eval_metric="aucpr",
            scale_pos_weight=spw, n_jobs=4, random_state=42),
        lambda m, d: m.save_model(str(Path(d) / "model.json")),
        df, feature_cols, train_idx, test_idx, Path(args.outdir) / "xgboost_audit")

    results["lightgbm"] = run_model(
        lambda spw: lgb.LGBMClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, subsample_freq=1,
            scale_pos_weight=spw, n_jobs=4, random_state=42, verbose=-1),
        lambda m, d: m.booster_.save_model(str(Path(d) / "model.txt")),
        df, feature_cols, train_idx, test_idx, Path(args.outdir) / "lightgbm_audit")

    print("\nmodel       acc    prec   recall f1     roc_auc pr_auc  fpr")
    for name, m in results.items():
        print(f"{name:11s} {m['accuracy']:.3f}  {m['precision']:.3f}  "
              f"{m['recall']:.3f}  {m['f1']:.3f}  {m.get('roc_auc', 0):.3f}   "
              f"{m.get('pr_auc', 0):.3f}   {m['false_positive_rate']:.3f}")
    for name, m in results.items():
        print(f"\n{name} per-attack-type recall:")
        for attack_type, v in m["per_attack_recall"].items():
            print(f"  {attack_type:22s} {v['recall']:.3f}  (n={v['support']})")

if __name__ == "__main__":
    main()
