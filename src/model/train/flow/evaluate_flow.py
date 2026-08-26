#!/usr/bin/env python3
"""Compute operating points for the Flow component.

Same JSON schema as ``data/models/evaluation/operating_points.json``
(the Audit component), so Flow and Audit can be merged into one report.

The four Flow experiments are pinned: BCCC random-split val + held-out day
test, ITU random-split val + leave-heavy-hitter-out test.

Output: ``data/models/evaluation/flow_operating_points.json``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                             roc_auc_score, roc_curve)

REPO = Path(__file__).resolve().parents[4]
REPO = REPO.parent

FLOW_EXPERIMENTS = {
    "xgboost_bccc_val_random": REPO / "data/models/flow-bccc/xgboost_bccc/predictions_val.csv",
    "xgboost_bccc_test_heldout_day": REPO / "data/models/flow-bccc/xgboost_bccc/predictions_test.csv",
    "xgboost_itu_val_random": REPO / "cluster/dizertatie/data/models/flow-bccc/xgboost_itu/predictions_val.csv",
    "xgboost_itu_test_lho": REPO / "cluster/dizertatie/data/models/flow-bccc/xgboost_itu_lho/predictions_test.csv",
    "xgboost_cic2018_val_random": REPO / "data/models/flow-bccc/xgboost_cic2018/predictions_val.csv",
    "xgboost_cic2018_test_novel_attacks": REPO / "data/models/flow-bccc/xgboost_cic2018/predictions_test.csv",
}

def best_f1(y_true: np.ndarray, y_prob: np.ndarray) -> dict | None:
    prec, rec, thr = precision_recall_curve(y_true, y_prob)
    # precision_recall_curve returns one extra point (precision=1, recall=0)
    # with no matching threshold; trim it.
    f1 = 2 * prec[:-1] * rec[:-1] / (prec[:-1] + rec[:-1] + 1e-12)
    if len(f1) == 0:
        return None
    idx = int(np.argmax(f1))
    return {
        "threshold": float(thr[idx]),
        "precision": float(prec[idx]),
        "recall": float(rec[idx]),
        "f1": float(f1[idx]),
    }

def recall_at_fpr(y_true: np.ndarray, y_prob: np.ndarray, target_fpr: float) -> dict:
    """Highest recall achievable while keeping FPR <= target_fpr."""
    fpr, tpr, thr = roc_curve(y_true, y_prob)
    mask = fpr <= target_fpr
    if not mask.any():
        idx = int(np.argmin(fpr))
    else:
        # Among thresholds satisfying the FPR cap, take the one with highest TPR.
        idx = int(np.where(mask)[0][np.argmax(tpr[mask])])
    return {
        "target_fpr": target_fpr,
        "achieved_fpr": float(fpr[idx]),
        "recall": float(tpr[idx]),
        "threshold": float(thr[idx]) if idx < len(thr) else None,
    }

def fpr_at_recall(y_true: np.ndarray, y_prob: np.ndarray, target_recall: float) -> dict:
    """Lowest FPR achievable while keeping recall >= target_recall."""
    fpr, tpr, thr = roc_curve(y_true, y_prob)
    mask = tpr >= target_recall
    if not mask.any():
        idx = int(np.argmax(tpr))
    else:
        idx = int(np.where(mask)[0][np.argmin(fpr[mask])])
    return {
        "target_recall": target_recall,
        "achieved_recall": float(tpr[idx]),
        "fpr": float(fpr[idx]),
    }

def operating_points(predictions_path: Path) -> dict:
    df = pd.read_csv(predictions_path)
    y = df["actual"].astype(int).to_numpy()
    p = df["probability"].astype(float).to_numpy()
    return {
        "roc_auc": float(roc_auc_score(y, p)),
        "pr_auc": float(average_precision_score(y, p)),
        "best_f1": best_f1(y, p),
        "recall_at_fpr_0.01": recall_at_fpr(y, p, 0.01),
        "recall_at_fpr_0.001": recall_at_fpr(y, p, 0.001),
        "fpr_at_recall_0.95": fpr_at_recall(y, p, 0.95),
        "fpr_at_recall_0.99": fpr_at_recall(y, p, 0.99),
        "test_rows": int(len(y)),
        "n_attack": int((y == 1).sum()),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",
                        default=str(REPO / "data/models/evaluation/flow_operating_points.json"))
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict] = {}
    for name, path in FLOW_EXPERIMENTS.items():
        if not path.exists():
            print(f"  SKIP  {name}  ({path} not found)")
            continue
        print(f"  compute  {name}")
        results[name] = operating_points(path)

    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {out_path}\n")

    for name, op in results.items():
        bf = op["best_f1"] or {"f1": 0.0, "threshold": 0.0,
                                "precision": 0.0, "recall": 0.0}
        r1 = op["recall_at_fpr_0.01"]
        r01 = op["recall_at_fpr_0.001"]
        f95 = op["fpr_at_recall_0.95"]
        f99 = op["fpr_at_recall_0.99"]
        print(f"== {name} (n={op['test_rows']:,}, n_attack={op['n_attack']:,}) ==")
        print(f"  ROC-AUC = {op['roc_auc']:.4f}   PR-AUC = {op['pr_auc']:.4f}")
        print(f"  best F1 = {bf['f1']:.4f} @ thr={bf['threshold']:.3f}  "
              f"(prec={bf['precision']:.3f} rec={bf['recall']:.3f})")
        print(f"  recall @ FPR=1%   = {r1['recall']:.4f}  "
              f"(achieved FPR={r1['achieved_fpr']:.4f})")
        print(f"  recall @ FPR=0.1% = {r01['recall']:.4f}  "
              f"(achieved FPR={r01['achieved_fpr']:.4f})")
        print(f"  FPR @ recall=95%  = {f95['fpr']:.4f}  "
              f"(achieved recall={f95['achieved_recall']:.4f})")
        print(f"  FPR @ recall=99%  = {f99['fpr']:.4f}  "
              f"(achieved recall={f99['achieved_recall']:.4f})")
        print()

if __name__ == "__main__":
    main()
