#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from transformers import DistilBertForSequenceClassification, DistilBertTokenizer

from llm_ids.feature_to_text import FeatureToTextConverter
from train_distilbert import detect_label_column, labels_to_binary, prepare_network_features

def stratified_sample(df: pd.DataFrame, label_column: str, sample_size: int, random_state: int = 123) -> pd.DataFrame:
    """Sample rows while preserving both classes when possible."""
    labels = labels_to_binary(df[label_column])
    class_counts = labels.value_counts()
    if len(class_counts) < 2:
        print(f"WARNING: dataset has only one class ({class_counts.to_dict()}). Metrics will be limited.")
        return df.sample(n=min(sample_size, len(df)), random_state=random_state).reset_index(drop=True)

    per_class = max(1, sample_size // 2)
    selected_idx: list[int] = []
    for class_value in sorted(class_counts.index):
        idx = df.index[labels == class_value].tolist()
        take = min(per_class, len(idx), sample_size - len(selected_idx))
        if take > 0:
            picked = pd.Series(idx).sample(n=take, random_state=random_state).tolist()
            selected_idx.extend(picked)

    if len(selected_idx) < sample_size:
        remaining = [i for i in df.index if i not in set(selected_idx)]
        extra = min(sample_size - len(selected_idx), len(remaining))
        if extra > 0:
            selected_idx.extend(
                pd.Series(remaining).sample(n=extra, random_state=random_state).tolist()
            )

    return df.loc[selected_idx].sample(frac=1, random_state=random_state).reset_index(drop=True)

def print_label_distribution(labels: np.ndarray, title: str) -> None:
    benign = int((labels == 0).sum())
    attack = int((labels == 1).sum())
    total = len(labels)
    print(f"{title}: total={total:,} benign={benign:,} attack={attack:,}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test a trained DistilBERT IDS model.")
    parser.add_argument("--model-dir", default="models/bccc_ddos_model", help="Path to the saved model directory.")
    parser.add_argument("--data", default=None, help="Optional CSV dataset to score.")
    parser.add_argument("--sample-size", type=int, default=5000, help="Rows to sample from --data for testing.")
    parser.add_argument("--batch-size", type=int, default=64, help="Prediction batch size.")
    parser.add_argument("--max-length", type=int, default=512, help="Tokenizer max sequence length.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Attack probability threshold.")
    parser.add_argument("--text", default=None, help="Optional single text flow description to score.")
    parser.add_argument("--predictions-out", default=None,
                        help="Optional path to write a predictions CSV (columns: actual, predicted, probability). "
                             "Compatible with threshold_sweep.py.")
    return parser.parse_args()

def load_model(model_dir: Path) -> tuple[DistilBertTokenizer, DistilBertForSequenceClassification, torch.device]:
    if not model_dir.exists():
        raise FileNotFoundError(f"Model directory not found: {model_dir}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = DistilBertTokenizer.from_pretrained(model_dir)
    model = DistilBertForSequenceClassification.from_pretrained(model_dir)
    model.to(device)
    model.eval()

    print(f"Loaded model from: {model_dir}")
    print(f"Device: {device}")
    return tokenizer, model, device

def predict_texts(
    texts: list[str],
    tokenizer: DistilBertTokenizer,
    model: DistilBertForSequenceClassification,
    device: torch.device,
    batch_size: int,
    max_length: int,
    threshold: float,
) -> tuple[np.ndarray, np.ndarray]:
    attack_probs = []

    for start in range(0, len(texts), batch_size):
        batch_texts = texts[start : start + batch_size]
        inputs = tokenizer(
            batch_texts,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        inputs = {key: value.to(device) for key, value in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[:, 1]
            attack_probs.extend(probs.detach().cpu().numpy().tolist())

    attack_probs_array = np.array(attack_probs)
    predictions = (attack_probs_array >= threshold).astype(int)
    return predictions, attack_probs_array

def score_single_text(args: argparse.Namespace) -> None:
    tokenizer, model, device = load_model(Path(args.model_dir))
    predictions, attack_probs = predict_texts(
        [args.text],
        tokenizer,
        model,
        device,
        batch_size=1,
        max_length=args.max_length,
        threshold=args.threshold,
    )

    label = "Attack" if predictions[0] == 1 else "Benign"
    print(f"Prediction: {label}")
    print(f"Attack probability: {attack_probs[0]:.6f}")

def score_dataset(args: argparse.Namespace) -> None:
    data_path = Path(args.data)
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    tokenizer, model, device = load_model(Path(args.model_dir))

    df = pd.read_csv(data_path, low_memory=False)
    label_column = detect_label_column(df)
    print_label_distribution(labels_to_binary(df[label_column]).values, "Full dataset")

    if args.sample_size > 0 and args.sample_size < len(df):
        df = stratified_sample(df, label_column, args.sample_size, random_state=123)
        print_label_distribution(labels_to_binary(df[label_column]).values, "Sampled subset")

    labels = labels_to_binary(df[label_column]).values
    unique_labels = np.unique(labels)
    if len(unique_labels) < 2:
        print(
            "\nERROR: Only one class present in the evaluation set. "
            "Cannot compute meaningful F1/precision/recall.\n"
            "If using itu_as_bccc.csv, check label distribution:\n"
            "  awk -F',' 'NR>1{print $NF}' data/bccc-retraining/itu_as_bccc.csv | sort | uniq -c | sort -rn | head\n"
            "If all rows are benign, re-run itu_to_bccc.py with --filter none instead of --filter ddos."
        )

    features_df = prepare_network_features(df)
    converter = FeatureToTextConverter()
    texts = [converter.network_flow_to_text(row.to_dict()) for _, row in features_df.iterrows()]

    predictions, attack_probs = predict_texts(
        texts,
        tokenizer,
        model,
        device,
        batch_size=args.batch_size,
        max_length=args.max_length,
        threshold=args.threshold,
    )

    print(f"Rows scored: {len(df):,}")
    print(f"Label column: {label_column}")
    print(f"Threshold: {args.threshold}")
    print(f"Accuracy: {accuracy_score(labels, predictions):.6f}")
    if len(unique_labels) > 1:
        print(f"F1: {f1_score(labels, predictions, zero_division=0):.6f}")
        print(f"Precision: {precision_score(labels, predictions, zero_division=0):.6f}")
        print(f"Recall: {recall_score(labels, predictions, zero_division=0):.6f}")
    print("\nConfusion matrix:")
    print(confusion_matrix(labels, predictions, labels=[0, 1]))
    print("\nClassification report:")
    if len(unique_labels) > 1:
        print(classification_report(labels, predictions, labels=[0, 1], target_names=["Benign", "Attack"], zero_division=0))
    else:
        only_class = "Benign" if unique_labels[0] == 0 else "Attack"
        print(f"Skipped (single class only: {only_class}).")

    preview = pd.DataFrame(
        {
            "actual": labels[:10],
            "predicted": predictions[:10],
            "attack_probability": attack_probs[:10],
        }
    )
    print("\nFirst 10 predictions:")
    print(preview.to_string(index=False))

    if args.predictions_out:
        out_path = Path(args.predictions_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame({
            "actual": labels,
            "predicted": predictions,
            "probability": attack_probs,
        }).to_csv(out_path, index=False)
        print(f"\nPredictions written to: {out_path}")

def main() -> None:
    args = parse_args()
    if args.text:
        score_single_text(args)
    elif args.data:
        score_dataset(args)
    else:
        raise SystemExit("Provide either --data for dataset testing or --text for one manual prediction.")

if __name__ == "__main__":
    main()
