#!/usr/bin/env python3
"""Benchmark operational metrics (model size + inference latency) for trained models.

This script is the operational side of the model comparison. It measures:
- disk footprint of the saved model
- inference latency per single sample (P50, P95)
- inference throughput in samples per second (batch=64)

It does not retrain anything; it only loads models that already exist.
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd

@dataclass
class BenchmarkResult:
    model_name: str
    model_dir: str
    size_mb: float
    sample_count: int
    p50_latency_ms_single: float
    p95_latency_ms_single: float
    throughput_samples_per_second_batch64: float

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark model size and inference speed.")
    parser.add_argument("--bccc-csv", required=True, help="A CSV used to source benchmark samples (BCCC or ITU).")
    parser.add_argument("--xgboost-dir", default=None)
    parser.add_argument("--lightgbm-dir", default=None)
    parser.add_argument("--distilbert-dir", default=None)
    parser.add_argument("--samples", type=int, default=200, help="Single-sample latency iterations.")
    parser.add_argument("--batch-iterations", type=int, default=50, help="Batched throughput iterations (batch=64).")
    parser.add_argument("--output", default="benchmark_summary.json")
    return parser.parse_args()

def folder_size_mb(path: Path) -> float:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return total / (1024 * 1024)

def benchmark_callable(predict_fn: Callable[[np.ndarray], np.ndarray],
                       X: np.ndarray,
                       single_iters: int,
                       batch_iters: int) -> tuple[float, float, float]:
    single_latencies = []
    for i in range(min(single_iters, len(X))):
        sample = X[i : i + 1]
        start = time.perf_counter()
        predict_fn(sample)
        single_latencies.append((time.perf_counter() - start) * 1000)

    batch = X[:64] if len(X) >= 64 else X
    batch_latencies = []
    for _ in range(batch_iters):
        start = time.perf_counter()
        predict_fn(batch)
        batch_latencies.append(time.perf_counter() - start)

    p50 = float(np.percentile(single_latencies, 50))
    p95 = float(np.percentile(single_latencies, 95))
    throughput = float(len(batch) / np.mean(batch_latencies))
    return p50, p95, throughput

def bench_xgboost(model_dir: Path, X: np.ndarray, args) -> BenchmarkResult:
    import xgboost as xgb
    model = xgb.XGBClassifier()
    model.load_model(str(model_dir / "model.json"))

    def predict_fn(batch):
        return model.predict_proba(batch)[:, 1]

    p50, p95, tps = benchmark_callable(predict_fn, X, args.samples, args.batch_iterations)
    return BenchmarkResult(
        model_name="xgboost",
        model_dir=str(model_dir),
        size_mb=folder_size_mb(model_dir),
        sample_count=len(X),
        p50_latency_ms_single=p50,
        p95_latency_ms_single=p95,
        throughput_samples_per_second_batch64=tps,
    )

def bench_lightgbm(model_dir: Path, X: np.ndarray, args) -> BenchmarkResult:
    import lightgbm as lgb
    booster = lgb.Booster(model_file=str(model_dir / "model.txt"))

    def predict_fn(batch):
        return booster.predict(batch)

    p50, p95, tps = benchmark_callable(predict_fn, X, args.samples, args.batch_iterations)
    return BenchmarkResult(
        model_name="lightgbm",
        model_dir=str(model_dir),
        size_mb=folder_size_mb(model_dir),
        sample_count=len(X),
        p50_latency_ms_single=p50,
        p95_latency_ms_single=p95,
        throughput_samples_per_second_batch64=tps,
    )

def bench_distilbert(model_dir: Path, args) -> BenchmarkResult:
    import torch
    from transformers import DistilBertForSequenceClassification, DistilBertTokenizer
    tokenizer = DistilBertTokenizer.from_pretrained(model_dir)
    model = DistilBertForSequenceClassification.from_pretrained(model_dir)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    template = ("Network flow from source IP 10.0.1.5 port 54321 to destination IP 10.0.1.10 "
                "port 443 using TCP. The flow lasted 0.1 seconds and contained 100 packets, "
                "120000 total bytes. The packet rate was 1000 packets per second.")
    texts = [template] * 64

    def encode(batch_texts):
        return tokenizer(batch_texts, return_tensors="pt", padding=True, truncation=True, max_length=512).to(device)

    single = encode([template])
    batch = encode(texts)

    with torch.no_grad():
        for _ in range(5):
            model(**single)
            model(**batch)

    single_latencies = []
    with torch.no_grad():
        for _ in range(args.samples):
            start = time.perf_counter()
            model(**single)
            single_latencies.append((time.perf_counter() - start) * 1000)

    batch_latencies = []
    with torch.no_grad():
        for _ in range(args.batch_iterations):
            start = time.perf_counter()
            model(**batch)
            batch_latencies.append(time.perf_counter() - start)

    p50 = float(np.percentile(single_latencies, 50))
    p95 = float(np.percentile(single_latencies, 95))
    throughput = float(64 / np.mean(batch_latencies))

    return BenchmarkResult(
        model_name="distilbert",
        model_dir=str(model_dir),
        size_mb=folder_size_mb(model_dir),
        sample_count=64,
        p50_latency_ms_single=p50,
        p95_latency_ms_single=p95,
        throughput_samples_per_second_batch64=throughput,
    )

def main() -> None:
    args = parse_args()
    results: list[BenchmarkResult] = []

    if args.xgboost_dir or args.lightgbm_dir:
        from tabular_data import load_tabular
        split = load_tabular(args.bccc_csv, sample_size=10000)
        X = split.X.values

    if args.xgboost_dir:
        results.append(bench_xgboost(Path(args.xgboost_dir), X, args))
    if args.lightgbm_dir:
        results.append(bench_lightgbm(Path(args.lightgbm_dir), X, args))
    if args.distilbert_dir:
        results.append(bench_distilbert(Path(args.distilbert_dir), args))

    if not results:
        raise SystemExit("Provide at least one of --xgboost-dir, --lightgbm-dir, --distilbert-dir")

    summary = [asdict(r) for r in results]
    Path(args.output).write_text(json.dumps(summary, indent=2))

    print("\nBenchmark results:")
    df = pd.DataFrame(summary)
    print(df.to_string(index=False))
    print(f"\nSaved to: {args.output}")

if __name__ == "__main__":
    main()
