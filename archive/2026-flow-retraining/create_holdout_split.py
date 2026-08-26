#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create train/test CSVs by holding out one BCCC capture day."
    )
    parser.add_argument(
        "--input-dir",
        default="CSVs",
        help="Directory containing source CSV files. Default: CSVs",
    )
    parser.add_argument(
        "--holdout",
        default="Tuesday_19_Dec_2023.csv",
        help="CSV filename to keep only for testing.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/bccc-retraining/holdout_split",
        help="Directory where train/test CSVs are written.",
    )
    parser.add_argument(
        "--pattern",
        default="*.csv",
        help="Glob pattern used inside input-dir. Default: *.csv",
    )
    parser.add_argument(
        "--source-column",
        default="source_file",
        help="Column added to identify the original source CSV.",
    )
    return parser.parse_args()

def read_csv_with_source(csv_path: Path, source_column: str) -> pd.DataFrame:
    print(f"Reading {csv_path}")
    frame = pd.read_csv(csv_path, low_memory=False)
    frame[source_column] = csv_path.name
    return frame

def main() -> None:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    holdout_name = Path(args.holdout).name

    csv_files = sorted(input_dir.glob(args.pattern))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {input_dir} with pattern {args.pattern}")

    holdout_files = [path for path in csv_files if path.name == holdout_name]
    if not holdout_files:
        available = ", ".join(path.name for path in csv_files)
        raise FileNotFoundError(f"Holdout file {holdout_name!r} not found. Available: {available}")

    train_files = [path for path in csv_files if path.name != holdout_name]
    if not train_files:
        raise ValueError("No training files remain after removing the holdout file.")

    train_frames = [read_csv_with_source(path, args.source_column) for path in train_files]
    test_frame = read_csv_with_source(holdout_files[0], args.source_column)
    train_frame = pd.concat(train_frames, ignore_index=True, sort=False)

    output_dir.mkdir(parents=True, exist_ok=True)
    train_output = output_dir / "train_without_holdout.csv"
    test_output = output_dir / "test_holdout.csv"

    train_frame.to_csv(train_output, index=False)
    test_frame.to_csv(test_output, index=False)

    print("\nHoldout split created")
    print(f"Training files: {', '.join(path.name for path in train_files)}")
    print(f"Holdout file: {holdout_files[0].name}")
    print(f"Train rows: {len(train_frame):,}")
    print(f"Test rows: {len(test_frame):,}")
    print(f"Train output: {train_output}")
    print(f"Test output: {test_output}")

if __name__ == "__main__":
    main()
