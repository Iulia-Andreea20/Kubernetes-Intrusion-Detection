#!/usr/bin/env python3
"""
Check class balance in BCCC Cloud DDoS 2024 dataset
"""

import pandas as pd
import sys
from pathlib import Path

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

def check_balance(data_path: str, sample_size: int = None):
    """Check class balance in the dataset."""
    print(f"{'='*70}")
    print(f"CHECKING DATASET BALANCE: {data_path}")
    print(f"{'='*70}\n")

    try:
        # Read dataset
        if sample_size:
            print(f"Reading sample of {sample_size} rows...")
            df = pd.read_csv(data_path, nrows=sample_size, low_memory=False)
        else:
            print("Reading full dataset (this may take a while)...")
            # Read in chunks to get full count
            chunk_size = 100000
            chunks = []
            total_rows = 0

            for chunk in pd.read_csv(data_path, chunksize=chunk_size, low_memory=False):
                chunks.append(chunk)
                total_rows += len(chunk)
                if len(chunks) % 10 == 0:
                    print(f"  Processed {total_rows:,} rows...")

            print(f"  Total rows: {total_rows:,}")
            df = pd.concat(chunks, ignore_index=True)

        print(f"Dataset loaded: {len(df):,} rows, {len(df.columns)} columns\n")

        # Detect label column
        label_col = detect_label_column(df)

        if label_col is None:
            print(" Could not find label column!")
            print(f"Available columns: {list(df.columns)[:20]}...")
            return

        print(f"Label column detected: '{label_col}'\n")

        # Check label distribution
        print(f"{'='*70}")
        print("CLASS DISTRIBUTION")
        print(f"{'='*70}")

        label_counts = df[label_col].value_counts()
        total = len(df)

        print(f"\nRaw label counts:")
        for label, count in label_counts.items():
            percentage = (count / total) * 100
            print(f"  {label}: {count:,} ({percentage:.2f}%)")

        # Convert to binary if needed
        print(f"\n{'='*70}")
        print("BINARY CLASS DISTRIBUTION (Benign=0, Attack=1)")
        print(f"{'='*70}")

        if df[label_col].dtype == 'object' or df[label_col].dtype == 'string':
            # String labels
            label_str = df[label_col].astype(str).str.lower().str.strip()
            benign_keywords = ['benign', 'normal', 'legitimate', '0', 'false', 'no']
            binary_labels = (~label_str.isin(benign_keywords)).astype(int)
        else:
            # Numeric labels
            binary_labels = (df[label_col] != 0).astype(int)

        benign_count = (binary_labels == 0).sum()
        attack_count = (binary_labels == 1).sum()
        total = len(binary_labels)

        benign_pct = (benign_count / total) * 100
        attack_pct = (attack_count / total) * 100

        print(f"\nBenign (0): {benign_count:,} ({benign_pct:.2f}%)")
        print(f"Attack (1): {attack_count:,} ({attack_pct:.2f}%)")
        print(f"Total:     {total:,} (100.00%)")

        # Balance assessment
        print(f"\n{'='*70}")
        print("BALANCE ASSESSMENT")
        print(f"{'='*70}")

        ratio = min(benign_count, attack_count) / max(benign_count, attack_count)
        imbalance_ratio = max(benign_count, attack_count) / min(benign_count, attack_count)

        print(f"\nClass ratio (minority/majority): {ratio:.4f}")
        print(f"Imbalance ratio: {imbalance_ratio:.2f}:1")

        if ratio >= 0.9:
            print("\n Dataset is HIGHLY BALANCED (ratio >= 0.9)")
        elif ratio >= 0.7:
            print("\n  Dataset is MODERATELY BALANCED (ratio >= 0.7)")
        elif ratio >= 0.5:
            print("\n  Dataset is SLIGHTLY IMBALANCED (ratio >= 0.5)")
        elif ratio >= 0.3:
            print("\n Dataset is IMBALANCED (ratio >= 0.3)")
        else:
            print("\n Dataset is HIGHLY IMBALANCED (ratio < 0.3)")

        # Recommendations
        print(f"\n{'='*70}")
        print("RECOMMENDATIONS")
        print(f"{'='*70}")

        if ratio < 0.7:
            print("\n  Dataset is imbalanced. Consider:")
            print("  1. Using class weights in training")
            print("  2. Oversampling minority class")
            print("  3. Undersampling majority class")
            print("  4. Using F1-score instead of accuracy for evaluation")
        else:
            print("\n Dataset is balanced. Standard training should work well.")

        # Show sample of each class
        print(f"\n{'='*70}")
        print("SAMPLE DATA BY CLASS")
        print(f"{'='*70}")

        if benign_count > 0:
            print("\nSample Benign flows:")
            benign_samples = df[binary_labels == 0].head(3)
            print(benign_samples[['src_ip', 'dst_ip', 'protocol', label_col]].to_string())

        if attack_count > 0:
            print("\nSample Attack flows:")
            attack_samples = df[binary_labels == 1].head(3)
            print(attack_samples[['src_ip', 'dst_ip', 'protocol', label_col]].to_string())

    except Exception as e:
        print(f" Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    data_path = sys.argv[1] if len(sys.argv) > 1 else "merged_CSVs.csv"
    sample_size = int(sys.argv[2]) if len(sys.argv) > 2 else None

    if sample_size:
        print(f"  Checking balance on sample of {sample_size} rows only")
        print("   (Remove sample_size argument to check full dataset)\n")

    check_balance(data_path, sample_size)
