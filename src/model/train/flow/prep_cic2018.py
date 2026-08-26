#!/usr/bin/env python3
"""Memory-efficient prep for CSE-CIC-IDS2018.

The dataset is ~13 GB across 10 day-CSVs. Pandas concat would OOM on most
machines, so this script processes each day-CSV **in chunks** and writes
``train.csv`` / ``test.csv`` incrementally.

Temporal split is **by file (by day)**: the earliest 70 % of files become
the training set, the latest 30 % become the held-out test set. This mirrors
the BCCC "held-out day" methodology — train on the past, test on the future.

Output:
  <output-dir>/train.csv
  <output-dir>/test.csv
  <output-dir>/prep_summary.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

# Identifier-style columns dropped before training (case-insensitive).
DROP_COLUMNS_LOWER = {
    "flow id", "timestamp", "src ip", "dst ip",
    "source ip", "destination ip", "src port", "dst port",
}

CHUNK_SIZE = 200_000

def find_label_column(columns) -> str | None:
    for c in columns:
        if c.lower().strip() == "label":
            return c
    return None

def process_file(input_path: Path, output_path: Path, header_written: bool,
                 label_counter: dict[str, int]) -> tuple[int, bool]:
    """Stream one input CSV, clean each chunk, append to output_path."""
    size_gb = input_path.stat().st_size / 1e9
    print(f"  -> {input_path.name} ({size_gb:.2f} GB)")
    total_rows = 0

    for chunk in pd.read_csv(input_path, chunksize=CHUNK_SIZE,
                              low_memory=False, encoding_errors="replace"):
        # Some CIC-IDS-2018 files contain duplicate header rows mid-file.
        first_col = chunk.columns[0]
        chunk = chunk[chunk[first_col].astype(str) != str(first_col)]
        if chunk.empty:
            continue

        # Count raw labels (for the summary)
        label_col = find_label_column(chunk.columns)
        if label_col is not None:
            for label_value, count in (chunk[label_col].astype(str).str.strip()
                                        .value_counts().items()):
                label_counter[label_value] = label_counter.get(label_value, 0) + int(count)

        # Drop identifier-style columns.
        drop_cols = [c for c in chunk.columns
                     if c.lower().strip() in DROP_COLUMNS_LOWER]
        chunk = chunk.drop(columns=drop_cols, errors="ignore")

        # Replace +/- inf with NaN so XGBoost / LightGBM are happy.
        numeric_cols = chunk.select_dtypes(include=[np.number]).columns
        if len(numeric_cols):
            chunk[numeric_cols] = chunk[numeric_cols].replace(
                [np.inf, -np.inf], np.nan)

        # Append to output (header only on the very first write).
        chunk.to_csv(output_path,
                      mode="a" if header_written else "w",
                      index=False, header=not header_written)
        header_written = True
        total_rows += len(chunk)

    return total_rows, header_written

def write_split(files: list[Path], output_path: Path) -> tuple[int, dict[str, int]]:
    print(f"\nWriting {output_path} from {len(files)} day file(s)...")
    if output_path.exists():
        output_path.unlink()
    label_counter: dict[str, int] = {}
    rows = 0
    header_written = False
    for input_path in files:
        n, header_written = process_file(input_path, output_path,
                                          header_written, label_counter)
        rows += n
    print(f"  total: {rows:,} rows -> {output_path}")
    return rows, label_counter

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--train-frac", type=float, default=0.7,
                         help="Fraction of day-files used for training "
                              "(default 0.7).")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_paths = sorted(input_dir.glob("*.csv"))
    if not csv_paths:
        raise SystemExit(f"No CSV files under {input_dir}")

    print(f"Found {len(csv_paths)} day-files (sorted alphabetically = "
          f"chronologically for the 2018 naming scheme):")
    for p in csv_paths:
        print(f"  {p.name}  ({p.stat().st_size / 1e9:.2f} GB)")

    n_train = max(1, round(len(csv_paths) * args.train_frac))
    train_files = csv_paths[:n_train]
    test_files = csv_paths[n_train:]

    print(f"\nTrain files ({len(train_files)}):  "
          f"{train_files[0].name} ... {train_files[-1].name}")
    print(f"Test files  ({len(test_files)}):  "
          f"{test_files[0].name} ... {test_files[-1].name}")

    train_rows, train_labels = write_split(train_files, output_dir / "train.csv")
    test_rows, test_labels = write_split(test_files, output_dir / "test.csv")

    summary = {
        "input_dir": str(input_dir),
        "train_files": [p.name for p in train_files],
        "test_files": [p.name for p in test_files],
        "rows_train": train_rows,
        "rows_test": test_rows,
        "train_frac_files": args.train_frac,
        "label_distribution_train": dict(
            sorted(train_labels.items(), key=lambda kv: -kv[1])),
        "label_distribution_test": dict(
            sorted(test_labels.items(), key=lambda kv: -kv[1])),
        "dropped_columns_lowercase": sorted(DROP_COLUMNS_LOWER),
        "chunk_size": CHUNK_SIZE,
    }
    (output_dir / "prep_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nSummary -> {output_dir / 'prep_summary.json'}")
    print("\nTrain label distribution:")
    for k, v in summary["label_distribution_train"].items():
        print(f"  {k!r}: {v:,}")
    print("\nTest label distribution:")
    for k, v in summary["label_distribution_test"].items():
        print(f"  {k!r}: {v:,}")

if __name__ == "__main__":
    main()
