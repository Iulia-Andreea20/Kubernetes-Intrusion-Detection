#!/usr/bin/env python3
"""Feature-ablation study for the audit-module tree baseline.

Quantifies which feature groups carry the IDS signal by retraining XGBoost
with each group removed (or used alone) and reporting the F1/recall/FPR.

Feature groups (mirrors features/featurize.py):
  categorical   - one-hot of verb/resource/subresource/api_group/namespace
  identity      - is_system_user, is_service_account
  response      - response-code flags (resp_2xx, resp_4xx, resp_403, resp_5xx)
  body          - pod_privileged, pod_host_*, rbac_wildcard  (body-derived)
  behavioural   - per-user rate features over 5 s and 60 s windows

Input  : data/features_tabular.csv
Output : models/evaluation/ablation.json
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

META = ["timestamp", "user", "attack_type", "label"]

def feature_groups(columns):
    groups = {"categorical": [], "identity": [], "response": [],
              "body": [], "behavioural": []}
    for col in columns:
        if col in META:
            continue
        if col.startswith(("verb=", "resource=", "subresource=", "api_group=", "namespace=")):
            groups["categorical"].append(col)
        elif col in ("is_system_user", "is_service_account"):
            groups["identity"].append(col)
        elif col.startswith("resp_"):
            groups["response"].append(col)
        elif col.startswith("pod_") or col == "rbac_wildcard":
            groups["body"].append(col)
        elif col.startswith("user_") or col == "secs_since_user_prev":
            groups["behavioural"].append(col)
    return groups

def train_eval(X_tr, y_tr, X_te, y_te, attack_type_te):
    import xgboost as xgb
    spw = max(int((y_tr == 0).sum()), 1) / max(int(y_tr.sum()), 1)
    model = xgb.XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.9, eval_metric="aucpr",
        scale_pos_weight=spw, n_jobs=4, random_state=42)
    model.fit(X_tr, y_tr)
    prob = model.predict_proba(X_te)[:, 1]
    pred = (prob >= 0.5).astype(int)
    metrics = common.binary_metrics(y_te, prob)
    metrics["false_positive_rate"] = common.false_positive_rate(y_te, pred)
    metrics["per_attack_recall"] = common.per_attack_recall(y_te, pred, attack_type_te)
    return metrics

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", default=str(REPO / "archive/audit-v1-kind-transformer/data/features_tabular.csv"))
    parser.add_argument("--outdir", default=str(REPO / "data/models/evaluation"))
    parser.add_argument("--train-frac", type=float, default=0.7)
    args = parser.parse_args()

    df = pd.read_csv(args.features)
    feature_cols = [c for c in df.columns if c not in META]
    groups = feature_groups(df.columns)
    print("Feature groups:")
    for name, cols in groups.items():
        sample = ", ".join(cols[:3])
        print(f"  {name:12s} {len(cols):3d}   e.g. {sample}")

    y = df["label"].to_numpy(int)
    attack_type = df["attack_type"].fillna("").to_numpy(object)
    train_idx, test_idx = common.time_split(len(df), args.train_frac)

    variants = {
        "full": feature_cols,
        "no_behavioural":      [c for c in feature_cols if c not in groups["behavioural"]],
        "no_body":             [c for c in feature_cols if c not in groups["body"]],
        "no_categorical":      [c for c in feature_cols if c not in groups["categorical"]],
        "no_body_no_behav":    [c for c in feature_cols
                                 if c not in groups["body"] and c not in groups["behavioural"]],
        "only_categorical":    groups["categorical"],
        "only_behavioural":    groups["behavioural"],
        "only_body":           groups["body"],
    }

    results = {}
    print()
    for name, cols in variants.items():
        if not cols:
            print(f"  {name:20s} (skipped - no features)")
            continue
        X = df[cols].to_numpy(dtype=float)
        m = train_eval(X[train_idx], y[train_idx], X[test_idx], y[test_idx],
                       attack_type[test_idx])
        m["n_features"] = len(cols)
        results[name] = m

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    common.save_json(results, outdir / "ablation.json")

    base_f1 = results["full"]["f1"]
    print(f"\n{'variant':22s} {'#feat':>5} {'F1':>6} {'recall':>7} "
          f"{'prec':>6} {'FPR':>6}  dF1")
    print("-" * 64)
    for name, m in results.items():
        delta = m["f1"] - base_f1
        marker = "+" if delta >= 0 else ""
        print(f"{name:22s} {m['n_features']:5d}  {m['f1']:.3f}  {m['recall']:.3f}  "
              f"{m['precision']:.3f}  {m['false_positive_rate']:.3f}  "
              f"{marker}{delta:+.3f}")

    print(f"\n -> {outdir}/ablation.json")

if __name__ == "__main__":
    main()
