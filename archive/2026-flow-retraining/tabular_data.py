#!/usr/bin/env python3
"""Shared tabular data loader for BCCC and ITU/Sever-style CSV datasets.

This module is intentionally model-agnostic. Both XGBoost and LightGBM use it.
It deliberately drops identifier-style columns that would not generalize in a
Kubernetes deployment (IPs, ports, raw flow_id, timestamps) and keeps only
numeric statistical features extracted by CICFlowMeter-like tools.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

LABEL_CANDIDATES = [
    "label",
    "Label",
    "LABEL",
    "attack",
    "Attack",
    "ATTACK",
    "class",
    "Class",
    "CLASS",
    "type",
    "Type",
    "TYPE",
    "category",
    "Category",
    "CATEGORY",
    "is_attack",
    "is_ddos",
    "ddos",
    "traffic_type",
    "traffic_category",
]

DROP_COLUMNS = {
    "flow_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "src_port",
    "dst_port",
    "source_port",
    "destination_port",
    "activity",
}

@dataclass
class TabularSplit:
    X: pd.DataFrame
    y: np.ndarray
    feature_names: list[str]
    label_column: str

def detect_label_column(df: pd.DataFrame) -> str:
    for column in LABEL_CANDIDATES:
        if column in df.columns:
            return column
    for column in df.columns:
        lower = column.lower()
        if "label" in lower or "attack" in lower or "ddos" in lower:
            return column
    raise ValueError(f"Could not find label column. Columns: {list(df.columns)}")

def labels_to_binary(labels: pd.Series) -> np.ndarray:
    if labels.dtype == "object" or str(labels.dtype).startswith("string"):
        text = labels.astype(str).str.lower().str.strip()
        benign = {"benign", "normal", "legitimate", "0", "false", "no"}
        return (~text.isin(benign)).astype(int).values
    numeric = pd.to_numeric(labels, errors="coerce").fillna(0)
    return (numeric != 0).astype(int).values

def load_tabular(
    data_path: str | Path,
    sample_size: int | None = None,
    extra_drop: Iterable[str] | None = None,
) -> TabularSplit:
    """Load a CSV and return a clean tabular split for ML training.

    Args:
        data_path: Path to the CSV (BCCC merged, BCCC daily, or ITU/Sever).
        sample_size: Optional row sub-sample (useful for smoke tests).
        extra_drop: Additional columns to drop on top of identifier defaults.
    """
    path = Path(data_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    df = pd.read_csv(path, low_memory=False)
    if sample_size is not None and sample_size > 0 and sample_size < len(df):
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    label_column = detect_label_column(df)
    y = labels_to_binary(df[label_column])

    drop_set = set(DROP_COLUMNS) | {label_column}
    if extra_drop:
        drop_set |= set(extra_drop)

    feature_df = df.drop(columns=[c for c in df.columns if c in drop_set], errors="ignore").copy()

    for column in feature_df.columns:
        if feature_df[column].dtype == "object":
            mapped = feature_df[column].astype(str).str.strip().str.lower().map(
                {"tcp": 6, "udp": 17, "icmp": 1}
            )
            if mapped.notna().any():
                feature_df[column] = mapped.fillna(0)
            else:
                feature_df[column] = pd.to_numeric(feature_df[column], errors="coerce")

    feature_df = feature_df.apply(pd.to_numeric, errors="coerce")
    feature_df = feature_df.replace([np.inf, -np.inf], np.nan).fillna(0)

    return TabularSplit(
        X=feature_df,
        y=y,
        feature_names=list(feature_df.columns),
        label_column=label_column,
    )

def align_features(reference: TabularSplit, candidate: TabularSplit) -> TabularSplit:
    """Align candidate.X to reference.feature_names (for cross-dataset eval)."""
    aligned = candidate.X.copy()
    for column in reference.feature_names:
        if column not in aligned.columns:
            aligned[column] = 0
    aligned = aligned[reference.feature_names]
    return TabularSplit(
        X=aligned,
        y=candidate.y,
        feature_names=reference.feature_names,
        label_column=candidate.label_column,
    )

def print_label_summary(split: TabularSplit, name: str) -> None:
    total = len(split.y)
    benign = int((split.y == 0).sum())
    attack = int((split.y == 1).sum())
    print(f"[{name}] rows={total:,} benign={benign:,} attack={attack:,} "
          f"benign_pct={benign / max(total, 1):.2%} attack_pct={attack / max(total, 1):.2%}")
