#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge source CSV files into one training CSV.")
    parser.add_argument(
        "--input-dir",
        default="CSVs",
        help="Directory containing source CSV files. Default: CSVs",
    )
    parser.add_argument(
        "--output",
        default="data/bccc-retraining/merged_CSVs.csv",
        help="Output merged CSV path.",
    )
    parser.add_argument(
        "--pattern",
        default="*.csv",
        help="Glob pattern used inside input-dir. Default: *.csv",
    )
    parser.add_argument(
        "--source-column",
        default="source_file",
        help="Column name added to track the original CSV file.",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_path = Path(args.output)

    csv_files = sorted(input_dir.glob(args.pattern))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {input_dir} with pattern {args.pattern}")

    frames = []
    for csv_file in csv_files:
        print(f"Reading {csv_file}")
        frame = pd.read_csv(csv_file, low_memory=False)
        frame[args.source_column] = csv_file.name
        frames.append(frame)

    merged = pd.concat(frames, ignore_index=True, sort=False)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)

    print(f"Merged {len(csv_files)} files")
    print(f"Rows: {len(merged):,}")
    print(f"Columns: {len(merged.columns):,}")
    print(f"Output: {output_path}")

if __name__ == "__main__":
    main()
