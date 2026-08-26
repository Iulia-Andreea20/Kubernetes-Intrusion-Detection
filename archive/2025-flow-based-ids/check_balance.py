#!/usr/bin/env python3
"""
Check class balance in BCCC Cloud DDoS 2024 dataset
"""

import pandas as pd
import sys
from collections import Counter

def detect_label_column(df: pd.DataFrame) -> str:
    """Auto-detect the label column."""
    possible_labels = [
        'label', 'Label', 'LABEL',
        'attack', 'Attack', 'ATTACK',
        'class', 'Class', 'CLASS',
        'type', 'Type', 'TYPE',
        'category', 'Category', 'CATEGORY',
        'is_attack', 'is_ddos', 'ddos',
        'traffic_type', 'traffic_category'
    ]

    for col in possible_labels:
        if col in df.columns:
            return col

    for col in df.columns:
        if 'label' in col.lower() or 'attack' in col.lower() or 'ddos' in col.lower():
            return col

    return None

def check_balance(data_path: str, chunk_size: int = 100000):
    """Check balance by processing in chunks."""
    print(f"{'='*70}")
    print(f"CHECKING DATASET BALANCE: {data_path}")
    print(f"{'='*70}\n")

    label_counter = Counter()
    total_rows = 0
    label_col = None

    # First pass: find label column
    print("Step 1: Finding label column...")
    sample = pd.read_csv(data_path, nrows=1000, low_memory=False)
    label_col = detect_label_column(sample)

    if label_col is None:
        print(" Could not find label column!")
        print(f"Available columns: {list(sample.columns)}")
        return

    print(f" Label column found: '{label_col}'\n")

    # Second pass: count labels in chunks
    print(f"Step 2: Counting labels (processing in chunks of {chunk_size:,})...")

    chunk_num = 0
    for chunk in pd.read_csv(data_path, chunksize=chunk_size, low_memory=False):
        chunk_num += 1
        total_rows += len(chunk)

        if label_col in chunk.columns:
            labels = chunk[label_col].value_counts()
            for label, count in labels.items():
                label_counter[label] += count

        if chunk_num % 10 == 0:
            print(f"  Processed {total_rows:,} rows...")

    print(f" Total rows processed: {total_rows:,}\n")

    # Display results
    print(f"{'='*70}")
    print("CLASS DISTRIBUTION")
    print(f"{'='*70}\n")

    print("Raw label counts:")
    for label, count in label_counter.most_common():
        percentage = (count / total_rows) * 100
        print(f"  {label}: {count:,} ({percentage:.2f}%)")

    # Convert to binary
    print(f"\n{'='*70}")
    print("BINARY CLASS DISTRIBUTION (Benign=0, Attack=1)")
    print(f"{'='*70}\n")

    benign_keywords = ['benign', 'normal', 'legitimate', '0', 'false', 'no']
    benign_count = 0
    attack_count = 0

    for label, count in label_counter.items():
        label_str = str(label).lower().strip()
        if label_str in benign_keywords or (isinstance(label, (int, float)) and label == 0):
            benign_count += count
        else:
            attack_count += count

    total = benign_count + attack_count
    benign_pct = (benign_count / total) * 100 if total > 0 else 0
    attack_pct = (attack_count / total) * 100 if total > 0 else 0

    print(f"Benign (0): {benign_count:,} ({benign_pct:.2f}%)")
    print(f"Attack (1): {attack_count:,} ({attack_pct:.2f}%)")
    print(f"Total:     {total:,} (100.00%)")

    # Balance assessment
    print(f"\n{'='*70}")
    print("BALANCE ASSESSMENT")
    print(f"{'='*70}\n")

    if benign_count > 0 and attack_count > 0:
        ratio = min(benign_count, attack_count) / max(benign_count, attack_count)
        imbalance_ratio = max(benign_count, attack_count) / min(benign_count, attack_count)

        print(f"Class ratio (minority/majority): {ratio:.4f}")
        print(f"Imbalance ratio: {imbalance_ratio:.2f}:1\n")

        if ratio >= 0.9:
            print(" Dataset is HIGHLY BALANCED (ratio >= 0.9)")
            print("    Standard training should work well")
        elif ratio >= 0.7:
            print("  Dataset is MODERATELY BALANCED (ratio >= 0.7)")
            print("    Consider using class weights for better results")
        elif ratio >= 0.5:
            print("  Dataset is SLIGHTLY IMBALANCED (ratio >= 0.5)")
            print("    Recommend using class weights or F1-score for evaluation")
        elif ratio >= 0.3:
            print(" Dataset is IMBALANCED (ratio >= 0.3)")
            print("    Strongly recommend:")
            print("     - Class weights in training")
            print("     - Oversampling/undersampling")
            print("     - F1-score for evaluation")
        else:
            print(" Dataset is HIGHLY IMBALANCED (ratio < 0.3)")
            print("    Required:")
            print("     - Class weights (critical)")
            print("     - Oversampling minority class")
            print("     - F1-score or PR-AUC for evaluation")
            print("     - Consider stratified sampling")
    else:
        print(" Only one class found! Dataset cannot be used for binary classification.")

    print(f"\n{'='*70}")

if __name__ == "__main__":
    data_path = sys.argv[1] if len(sys.argv) > 1 else "training_2026/merged_CSVs.csv"
    chunk_size = int(sys.argv[2]) if len(sys.argv) > 2 else 100000

    try:
        check_balance(data_path, chunk_size)
    except Exception as e:
        print(f" Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
