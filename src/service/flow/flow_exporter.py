#!/usr/bin/env python3
"""Prometheus exporter for the flow detector, so Grafana can show both components side by side.

    runtime_ids_flow_predictions_total{verdict="benign|attack"}
    runtime_ids_flow_alerts_total{severity="CRITICAL|HIGH|MEDIUM|LOW"}

Scores in batches with a short pause between them, which makes the attack burst visible as a spike
rather than a single step, then keeps serving /metrics.

    python3 flow_exporter.py     # :9092, 6000 flow records
"""
import os
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import argparse
import sys
import time
from pathlib import Path

from prometheus_client import Counter, Gauge, start_http_server

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(REPO / "src/service/flow"))
from tabular_data import load_tabular                # noqa: E402
from flow_detector import FlowDetector, severity_for  # noqa: E402

FLOW_PRED = Counter("runtime_ids_flow_predictions_total",
                    "Flow records scored.", ["verdict"])
FLOW_ALERT = Counter("runtime_ids_flow_alerts_total",
                     "Alerte Flow (DDoS) pe severitate.", ["severity"])
FLOW_READY = Gauge("runtime_ids_flow_ready", "1 once the flow detector is loaded.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9092)
    ap.add_argument("--limit", type=int, default=6000)
    ap.add_argument("--batch", type=int, default=200)
    ap.add_argument("--delay", type=float, default=0.4)
    args = ap.parse_args()

    start_http_server(args.port)
    print(f"[flow-exporter] metrici pe :{args.port}/metrics", flush=True)
    det = FlowDetector()
    FLOW_READY.set(1)

    split = load_tabular(str(REPO / "data/bccc-retraining/holdout_split/test_holdout.csv"),
                         sample_size=args.limit)
    out = det.score_frame(split.X)
    sc, lab = out["score"], out["label"]
    print(f"[flow-exporter] scoring {len(lab):,} flow records in batches of {args.batch}", flush=True)

    for i in range(0, len(lab), args.batch):
        for j in range(i, min(i + args.batch, len(lab))):
            verdict = "attack" if lab[j] == 1 else "benign"
            FLOW_PRED.labels(verdict=verdict).inc()
            if lab[j] == 1:
                FLOW_ALERT.labels(severity=severity_for(float(sc[j]))).inc()
        time.sleep(args.delay)

    print("[flow-exporter] done; keeping the metrics server up (Ctrl+C to stop)", flush=True)
    while True:
        time.sleep(5)

if __name__ == "__main__":
    main()
