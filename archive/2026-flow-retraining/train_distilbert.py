#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from torch import nn
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizer,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)

from llm_ids.feature_to_text import FeatureToTextConverter

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

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrain DistilBERT on BCCC-style IDS CSV data.")
    parser.add_argument("--data", default="data/merged_CSVs.csv", help="Path to merged training CSV.")
    parser.add_argument(
        "--output-dir",
        default="models/bccc_ddos_model",
        help="Directory where the model and metrics will be saved.",
    )
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs.")
    parser.add_argument("--batch-size", type=int, default=16, help="Per-device batch size.")
    parser.add_argument("--learning-rate", type=float, default=2e-5, help="Learning rate.")
    parser.add_argument("--max-length", type=int, default=512, help="Tokenizer max sequence length.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Validation split fraction.")
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help="Optional row count for quick smoke tests before full training.",
    )
    return parser.parse_args()

def detect_label_column(df: pd.DataFrame) -> str:
    for column in LABEL_CANDIDATES:
        if column in df.columns:
            return column

    for column in df.columns:
        lower = column.lower()
        if "label" in lower or "attack" in lower or "ddos" in lower:
            return column

    raise ValueError(f"Could not find a label column. Available columns: {list(df.columns)}")

def convert_protocol(protocol: Any) -> int:
    if pd.isna(protocol):
        return 6

    if isinstance(protocol, str):
        protocol_map = {
            "tcp": 6,
            "udp": 17,
            "icmp": 1,
        }
        cleaned = protocol.strip().lower()
        if cleaned in protocol_map:
            return protocol_map[cleaned]

    try:
        return int(protocol)
    except (TypeError, ValueError):
        return 6

def first_existing_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    lowered = {column.lower(): column for column in df.columns}
    for candidate in candidates:
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
    return None

def numeric_series(df: pd.DataFrame, candidates: list[str], default: float = 0.0) -> pd.Series:
    column = first_existing_column(df, candidates)
    if column is None:
        return pd.Series(default, index=df.index, dtype="float64")
    return pd.to_numeric(df[column], errors="coerce").fillna(default)

def text_series(df: pd.DataFrame, candidates: list[str], default: str = "unknown") -> pd.Series:
    column = first_existing_column(df, candidates)
    if column is None:
        return pd.Series(default, index=df.index, dtype="object")
    return df[column].fillna(default).astype(str)

def prepare_network_features(df: pd.DataFrame) -> pd.DataFrame:
    features = df.copy()

    duration = numeric_series(features, ["duration_s", "duration", "flow_duration", "Flow Duration"])
    if duration.max() > 1000:
        duration = duration / 1_000_000.0
    features["duration_s"] = duration

    total_packets = numeric_series(
        features,
        ["packets_count", "tot_pkts", "total_packets", "Total Fwd Packets", "Tot Fwd Pkts"],
    )
    fwd_packets = numeric_series(
        features,
        ["fwd_packets_count", "tot_fwd_pkts", "total_fwd_packets", "Total Fwd Packets", "Tot Fwd Pkts"],
    )

    if total_packets.eq(0).all() and not fwd_packets.eq(0).all():
        total_packets = fwd_packets + numeric_series(
            features,
            ["tot_bwd_pkts", "total_bwd_packets", "Total Backward Packets", "Tot Bwd Pkts"],
        )

    bwd_packets = total_packets - fwd_packets
    bwd_packets = bwd_packets.clip(lower=0)

    features["tot_fwd_pkts"] = fwd_packets
    features["tot_bwd_pkts"] = bwd_packets

    total_bytes = numeric_series(
        features,
        [
            "tot_bytes",
            "total_bytes",
            "bytes",
            "bytes_count",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
        ],
    )
    if total_bytes.eq(0).all():
        total_bytes = total_packets * 1500
    features["tot_bytes"] = total_bytes

    features["fwd_pkt_len_mean"] = np.where(fwd_packets > 0, total_bytes / fwd_packets, 0)
    features["bwd_pkt_len_mean"] = np.where(bwd_packets > 0, total_bytes / bwd_packets.replace(0, np.nan), 0)

    safe_duration = duration.replace(0, 1e-9)
    features["flow_pkts_per_s"] = total_packets / safe_duration
    features["flow_iat_mean_s"] = duration / total_packets.replace(0, 1)

    protocol_column = first_existing_column(features, ["protocol", "Protocol"])
    if protocol_column:
        features["protocol"] = features[protocol_column].apply(convert_protocol)
    else:
        features["protocol"] = 6

    features["src_ip"] = text_series(features, ["src_ip", "source_ip", "Src IP", "Source IP"])
    features["dst_ip"] = text_series(features, ["dst_ip", "destination_ip", "Dst IP", "Destination IP"])
    features["src_port"] = numeric_series(features, ["src_port", "source_port", "Src Port", "Source Port"]).astype(int)
    features["dst_port"] = numeric_series(features, ["dst_port", "destination_port", "Dst Port", "Destination Port"]).astype(int)

    features["src_is_pod"] = False
    features["dst_is_pod"] = False
    features["dst_is_service"] = False

    return features

def labels_to_binary(labels: pd.Series) -> pd.Series:
    if labels.dtype == "object" or str(labels.dtype).startswith("string"):
        label_text = labels.astype(str).str.lower().str.strip()
        benign_keywords = {"benign", "normal", "legitimate", "0", "false", "no"}
        return (~label_text.isin(benign_keywords)).astype(int)

    return (pd.to_numeric(labels, errors="coerce").fillna(0) != 0).astype(int)

def load_and_prepare_data(data_path: Path, sample_size: int | None, test_size: float) -> tuple:
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {data_path}")

    print("=" * 70)
    print("Loading BCCC Cloud DDoS dataset")
    print(f"Dataset file: {data_path}")
    print("=" * 70)

    preview = pd.read_csv(data_path, nrows=10000)
    label_column = detect_label_column(preview)
    print(f"Label column detected: {label_column}")

    df = pd.read_csv(data_path, low_memory=False)
    if sample_size:
        df = df.sample(n=min(sample_size, len(df)), random_state=42)
        print(f"Using sample of {len(df):,} rows")
    else:
        print(f"Loaded {len(df):,} rows")

    df["label"] = labels_to_binary(df[label_column])

    print("\nBinary label distribution:")
    for label, count in df["label"].value_counts().sort_index().items():
        name = "Benign" if label == 0 else "Attack"
        pct = count / len(df) * 100
        print(f"  {name} ({label}): {count:,} ({pct:.2f}%)")

    features_df = prepare_network_features(df)
    converter = FeatureToTextConverter()

    print("\nConverting rows to text...")
    texts = [converter.network_flow_to_text(row.to_dict()) for _, row in features_df.iterrows()]

    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts,
        df["label"].values,
        test_size=test_size,
        random_state=42,
        stratify=df["label"],
    )

    print(f"Train samples: {len(train_texts):,}")
    print(f"Validation samples: {len(val_texts):,}")
    print(f"Train labels: {Counter(train_labels)}")
    print(f"Validation labels: {Counter(val_labels)}")

    return train_texts, val_texts, train_labels, val_labels, label_column

def compute_metrics(eval_pred: tuple[np.ndarray, np.ndarray]) -> dict[str, float]:
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=1)
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1": f1_score(labels, predictions),
        "precision": precision_score(labels, predictions),
        "recall": recall_score(labels, predictions),
    }

class WeightedTrainer(Trainer):
    def __init__(self, class_weights: torch.Tensor | None = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights

    def compute_loss(self, model: torch.nn.Module, inputs: dict[str, Any], return_outputs: bool = False, **kwargs: Any):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.get("logits")

        if self.class_weights is not None:
            loss_fct = nn.CrossEntropyLoss(weight=self.class_weights.to(logits.device))
        else:
            loss_fct = nn.CrossEntropyLoss()

        loss = loss_fct(logits, labels)
        return (loss, outputs) if return_outputs else loss

def train_model(args: argparse.Namespace) -> None:
    data_path = Path(args.data)
    output_dir = Path(args.output_dir)

    train_texts, val_texts, train_labels, val_labels, label_column = load_and_prepare_data(
        data_path=data_path,
        sample_size=args.sample_size,
        test_size=args.test_size,
    )

    tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=2,
    )

    train_encodings = tokenizer(
        train_texts,
        padding="max_length",
        truncation=True,
        max_length=args.max_length,
        return_tensors="pt",
    )
    val_encodings = tokenizer(
        val_texts,
        padding="max_length",
        truncation=True,
        max_length=args.max_length,
        return_tensors="pt",
    )

    train_dataset = Dataset.from_dict(
        {
            "input_ids": train_encodings["input_ids"],
            "attention_mask": train_encodings["attention_mask"],
            "labels": torch.tensor(train_labels, dtype=torch.long),
        }
    )
    val_dataset = Dataset.from_dict(
        {
            "input_ids": val_encodings["input_ids"],
            "attention_mask": val_encodings["attention_mask"],
            "labels": torch.tensor(val_labels, dtype=torch.long),
        }
    )
    train_dataset.set_format("torch")
    val_dataset.set_format("torch")

    class_weights = compute_class_weight("balanced", classes=np.unique(train_labels), y=train_labels)
    class_weights_tensor = torch.tensor(class_weights, dtype=torch.float)
    print(f"\nClass weights: benign={class_weights_tensor[0]:.4f}, attack={class_weights_tensor[1]:.4f}")

    output_dir.mkdir(parents=True, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        weight_decay=0.01,
        logging_dir=str(output_dir / "logs"),
        logging_steps=100,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=2,
        seed=42,
        fp16=torch.cuda.is_available(),
        report_to="none",
    )

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)],
        class_weights=class_weights_tensor,
    )

    print("\nStarting training...")
    trainer.train()

    print("\nEvaluating...")
    eval_results = trainer.evaluate()
    predictions = trainer.predict(val_dataset)
    pred_labels = np.argmax(predictions.predictions, axis=1)
    probs = torch.softmax(torch.tensor(predictions.predictions), dim=-1)[:, 1].numpy()

    cm = confusion_matrix(val_labels, pred_labels)
    report = classification_report(
        val_labels,
        pred_labels,
        target_names=["Benign", "DDoS Attack"],
        output_dict=True,
    )

    try:
        roc_auc = roc_auc_score(val_labels, probs)
        pr_auc = average_precision_score(val_labels, probs)
        precision, recall, _ = precision_recall_curve(val_labels, probs)
        pd.DataFrame({"precision": precision, "recall": recall}).to_csv(output_dir / "pr_curve.csv", index=False)
    except ValueError:
        roc_auc = None
        pr_auc = None

    metrics = {
        "dataset": str(data_path),
        "label_column": label_column,
        "eval_metrics": {key: float(value) for key, value in eval_results.items() if isinstance(value, (int, float))},
        "confusion_matrix": cm.tolist(),
        "roc_auc": float(roc_auc) if roc_auc is not None else None,
        "pr_auc": float(pr_auc) if pr_auc is not None else None,
        "classification_report": report,
    }

    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    pd.DataFrame(cm, index=["Benign", "DDoS Attack"], columns=["Pred_Benign", "Pred_Attack"]).to_csv(
        output_dir / "confusion_matrix.csv"
    )

    trainer.save_model()
    tokenizer.save_pretrained(output_dir)

    print("\nTraining completed.")
    print(f"Model saved to: {output_dir}")
    print(f"Metrics saved to: {output_dir / 'metrics.json'}")

def main() -> None:
    args = parse_args()
    train_model(args)

if __name__ == "__main__":
    main()
