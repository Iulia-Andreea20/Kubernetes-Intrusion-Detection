#!/usr/bin/env python3
"""Alert-fusion analysis across multiple IDS modules.

Combines the predictions of two or more detection modules into a single
detector and measures the trade-off. Strategies:

  * Individual baselines           - each module alone at threshold 0.5
  * OR fusion @ 0.5                - alert if any module fires at 0.5
  * OR fusion CALIBRATED           - per-module threshold tuned to a target
                                     FPR on a held-out half, then OR'd
  * Score-mean ensemble            - average probability, threshold 0.5

The test set in every predictions.csv is split 50/50 in time order:
  first half  -> CALIBRATION  (used to pick per-module thresholds)
  second half -> EVALUATION   (the reported numbers)
so the same data is never used to calibrate AND to report.

Designed for the two-layer IDS architecture: pass one predictions.csv per
module (e.g. one flow model + one audit model) to measure CROSS-LAYER fusion;
or pass several from the same layer to measure intra-layer ensemble.
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

def load_module(path):
    df = pd.read_csv(path)
    return (Path(path).parent.name,
            df["label"].to_numpy(int),
            df["prob"].to_numpy(float),
            df["attack_type"].fillna("").to_numpy(object))

def evaluate(y, prob, pred, atype):
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    total = tp + fp + tn + fn
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    out = {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fp / max(fp + tn, 1),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }
    if len(np.unique(y)) > 1:
        from sklearn.metrics import average_precision_score, roc_auc_score
        out["roc_auc"] = float(roc_auc_score(y, prob))
        out["pr_auc"] = float(average_precision_score(y, prob))
    out["per_attack_recall"] = common.per_attack_recall(y, pred, atype)
    return out

def threshold_for_fpr(y, prob, target_fpr):
    """Smallest threshold tau such that P(prob >= tau | y=0) approx target_fpr."""
    neg_probs = prob[y == 0]
    if len(neg_probs) == 0:
        return 0.5
    return float(np.quantile(neg_probs, 1 - target_fpr))

def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--predictions", nargs="+", required=True,
                        help="predictions.csv paths, one per module")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--outdir", default=str(REPO / "data/models/fusion"))
    args = parser.parse_args()

    modules = []
    y_ref = atype_ref = None
    for path in args.predictions:
        name, y, prob, atype = load_module(path)
        if y_ref is None:
            y_ref, atype_ref = y, atype
        elif len(y) != len(y_ref) or not (y == y_ref).all():
            print(f"ERROR: {path} disagrees on labels - different test set.")
            sys.exit(1)
        modules.append((name, prob))
        print(f"  loaded {name:24s} ({len(y)} events)")

    n = len(y_ref)
    half = n // 2
    cal, ev = slice(0, half), slice(half, n)
    y_e, atype_e = y_ref[ev], atype_ref[ev]
    y_c = y_ref[cal]
    print(f"\n calibration: {half} events  |  evaluation: {n - half} events  "
          f"|  per-module target FPR: {args.target_fpr:.3f}")

    results = {}

    # 1) Individual baselines at threshold 0.5
    for name, prob in modules:
        pred = (prob[ev] >= 0.5).astype(int)
        results[f"individual:{name}"] = evaluate(y_e, prob[ev], pred, atype_e)

    # 2) OR fusion at 0.5
    or_pred = np.zeros(len(y_e), dtype=int)
    or_maxp = np.zeros(len(y_e), dtype=float)
    for _, prob in modules:
        or_pred |= (prob[ev] >= 0.5).astype(int)
        or_maxp = np.maximum(or_maxp, prob[ev])
    results["OR_fusion@0.5"] = evaluate(y_e, or_maxp, or_pred, atype_e)

    # 3) Per-module CALIBRATED OR fusion (target FPR on calibration half)
    cal_pred = np.zeros(len(y_e), dtype=int)
    cal_maxp = np.zeros(len(y_e), dtype=float)
    thresholds = {}
    for name, prob in modules:
        tau = threshold_for_fpr(y_c, prob[cal], args.target_fpr)
        thresholds[name] = tau
        cal_pred |= (prob[ev] >= tau).astype(int)
        cal_maxp = np.maximum(cal_maxp, prob[ev])
    results["OR_fusion_calibrated"] = evaluate(y_e, cal_maxp, cal_pred, atype_e)
    results["OR_fusion_calibrated"]["per_module_thresholds"] = thresholds

    # 4) Score-mean ensemble
    mean_prob = np.mean([prob[ev] for _, prob in modules], axis=0)
    mean_pred = (mean_prob >= 0.5).astype(int)
    results["score_mean@0.5"] = evaluate(y_e, mean_prob, mean_pred, atype_e)

    print(f"\n{'strategy':28s}  {'prec':>5} {'rec':>5} {'f1':>5} {'fpr':>5} {'rocAUC':>7}")
    for name, m in results.items():
        print(f"{name:28s}  {m['precision']:.3f} {m['recall']:.3f} "
              f"{m['f1']:.3f} {m['false_positive_rate']:.3f}   "
              f"{m.get('roc_auc', 0):.3f}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    common.save_json({
        "calibration_n": half, "evaluation_n": n - half,
        "target_fpr": args.target_fpr,
        "modules": [name for name, _ in modules],
        "strategies": results,
    }, outdir / "fusion_metrics.json")
    print(f"\n -> {outdir}/fusion_metrics.json")

if __name__ == "__main__":
    main()
