#!/usr/bin/env python3
"""Run the alert correlator end-to-end on the audit-component predictions.

The 3 audit models (XGBoost, LightGBM, Transformer) act as 3 independent
"components" feeding the correlator. The same pipeline applies to a real
Flow + Audit + Falco multi-source deployment.

Inputs (predictions.csv, columns: timestamp,user,attack_type,label,prob,pred):
  models/xgboost_audit/predictions.csv
  models/lightgbm_audit/predictions.csv
  models/sequence_audit/predictions.csv

Outputs:
  models/correlator/correlator_metrics.json   - aggregate metrics
  models/correlator/incidents.json            - emitted incidents (analyst view)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipeline import Alert, AlertCorrelator  # noqa: E402

COMPONENTS = ["xgboost_audit", "lightgbm_audit", "sequence_audit"]
TARGET_FPR = 0.01
WINDOW_SECONDS = 60.0

def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

def threshold_at_fpr(y_true, y_prob, target_fpr=0.01):
    fpr, tpr, thr = roc_curve(y_true, y_prob)
    mask = fpr <= target_fpr
    if not mask.any():
        return 0.5
    idx = int(np.where(mask)[0][np.argmax(tpr[mask])])
    if idx >= len(thr):
        return 0.5
    return float(thr[idx])

def predictions_to_alerts(df, component):
    alerts = []
    for row in df.itertuples(index=False):
        ts = parse_ts(getattr(row, "timestamp", None))
        if ts is None:
            continue
        attack_hint = (str(row.attack_type)
                       if int(row.label) == 1 and getattr(row, "attack_type", "")
                       else "")
        alerts.append(Alert(
            timestamp=ts,
            actor=str(row.user),
            component=component,
            raw_score=float(row.prob),
            attack_hint=attack_hint,
        ))
    return alerts

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", default=str(REPO / "data/models"))
    parser.add_argument("--window-seconds", type=float, default=WINDOW_SECONDS)
    parser.add_argument("--target-fpr", type=float, default=TARGET_FPR)
    parser.add_argument("--out-dir",
                        default=str(REPO / "data/models/correlator"))
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ----- Load all predictions ------------------------------------------- #
    preds: dict[str, pd.DataFrame] = {}
    for comp in COMPONENTS:
        path = models_dir / comp / "predictions.csv"
        if not path.exists():
            raise FileNotFoundError(path)
        df = pd.read_csv(path)
        df = df.dropna(subset=["timestamp", "user", "prob", "label"])
        preds[comp] = df.reset_index(drop=True)
        print(f"  loaded {comp}: {len(df):,} predictions")

    # ----- Split each component 50/50 — calibration vs test ---------------- #
    calibration_data = {}
    test_data = {}
    for comp in COMPONENTS:
        df = preds[comp]
        half = len(df) // 2
        calibration_data[comp] = (
            df["prob"].iloc[:half].to_numpy(),
            df["label"].iloc[:half].astype(int).to_numpy(),
        )
        test_data[comp] = df.iloc[half:].reset_index(drop=True)

    # ----- Pick per-component thresholds at target FPR (on calibration half) #
    thresholds: dict[str, float] = {}
    for comp in COMPONENTS:
        scores, labels = calibration_data[comp]
        thresholds[comp] = threshold_at_fpr(labels, scores, args.target_fpr)
    print("\nPer-component thresholds (target FPR=%.2f%% on calibration half):"
          % (args.target_fpr * 100))
    for comp, thr in thresholds.items():
        print(f"  {comp}: {thr:.6f}")

    # ----- Fit calibrators ------------------------------------------------- #
    correlator = AlertCorrelator(thresholds=thresholds,
                                  window_seconds=args.window_seconds)
    correlator.fit_calibrators(calibration_data)

    # ----- Build alert stream from the test half --------------------------- #
    test_alerts = []
    for comp in COMPONENTS:
        test_alerts.extend(predictions_to_alerts(test_data[comp], comp))
    print(f"\nRaw alerts on test half (pre-threshold): {len(test_alerts):,}")

    # ----- Run the 5-level pipeline ---------------------------------------- #
    incidents = correlator.run(test_alerts)
    print(f"Incidents emitted: {len(incidents):,}")

    # ----- Ground truth at actor-time-window level ------------------------- #
    # An actor is an *attacker* if any of their alerts in the test half has
    # label=1 within the same time window the correlator would have grouped them.
    # For simplicity we score actor-level: actor is attacker if they have ANY
    # attack event in the test half.
    truth_attackers: set[str] = set()
    for comp in COMPONENTS:
        df = test_data[comp]
        truth_attackers.update(df[df["label"] == 1]["user"].astype(str).unique())

    flagged_attackers = {inc.actor for inc in incidents}

    tp = len(truth_attackers & flagged_attackers)
    fp = len(flagged_attackers - truth_attackers)
    fn = len(truth_attackers - flagged_attackers)

    # ----- Coverage + severity + chain stats ------------------------------- #
    severity_counts = Counter(inc.severity for inc in incidents)
    chain_counts = Counter(inc.chain_matched for inc in incidents
                           if inc.chain_matched)
    detected_attack_types = sorted({
        atk for inc in incidents for atk in inc.attack_sequence if atk
    })

    # Incident-level precision (an incident is "true" if it includes any
    # attack-labelled alert)
    inc_tp = 0
    for inc in incidents:
        if any(a.attack_hint for a in inc.alerts):
            inc_tp += 1
    inc_precision = inc_tp / max(len(incidents), 1)

    # ----- Save metrics --------------------------------------------------- #
    metrics = {
        "config": {
            "window_seconds": args.window_seconds,
            "target_fpr_per_component": args.target_fpr,
            "thresholds": thresholds,
            "components": COMPONENTS,
        },
        "alert_volume": {
            "raw_alerts_total": len(test_alerts),
            "incidents_emitted": len(incidents),
            "deduplication_ratio": round(
                1 - len(incidents) / max(len(test_alerts), 1), 4),
        },
        "actor_level": {
            "n_truth_attackers": len(truth_attackers),
            "n_flagged_attackers": len(flagged_attackers),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(tp / max(tp + fp, 1), 4),
            "recall": round(tp / max(tp + fn, 1), 4),
        },
        "incident_level": {
            "incidents_emitted": len(incidents),
            "incidents_with_attack_in_window": inc_tp,
            "precision": round(inc_precision, 4),
        },
        "chain_matching": {
            "incidents_with_chain": sum(chain_counts.values()),
            "chains_observed": dict(chain_counts),
        },
        "severity_distribution": dict(severity_counts),
        "detected_attack_types": detected_attack_types,
    }

    metrics_path = out_dir / "correlator_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))

    incidents_path = out_dir / "incidents.json"
    incidents_path.write_text(json.dumps(
        [inc.to_dict() for inc in incidents], indent=2))

    print(f"\nWrote {metrics_path}")
    print(f"Wrote {incidents_path}")
    print()
    print("================ Summary ================")
    print(f"Raw alerts            : {len(test_alerts):,}")
    print(f"Incidents emitted     : {len(incidents):,}")
    print(f"Deduplication ratio   : {metrics['alert_volume']['deduplication_ratio']:.2%}")
    print(f"Actor-level precision : {metrics['actor_level']['precision']:.3f}")
    print(f"Actor-level recall    : {metrics['actor_level']['recall']:.3f}")
    print(f"Incident-level precision: {metrics['incident_level']['precision']:.3f}")
    print(f"Chain-matched incidents : {sum(chain_counts.values())}/{len(incidents)}")
    print(f"Severity distribution : {dict(severity_counts)}")
    print(f"Chains observed       : {dict(chain_counts)}")
    print(f"Attack types detected : {len(detected_attack_types)} types")

if __name__ == "__main__":
    main()
