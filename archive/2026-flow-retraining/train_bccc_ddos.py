#!/usr/bin/env python3
"""
Train DistilBERT model on BCCC Cloud DDoS Attacks 2024 dataset
"""

import os
import sys
import argparse
import json
import pandas as pd
import numpy as np
from pathlib import Path
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, average_precision_score
)

import torch
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback
)
from datasets import Dataset

# Add llm_ids to path
sys.path.insert(0, str(Path(__file__).parent / "llm_ids"))
from feature_to_text import FeatureToTextConverter

def detect_label_column(df: pd.DataFrame) -> str:
    """Auto-detect the label column in the dataset."""
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

    # Check for columns with 'label' or 'attack' in name
    for col in df.columns:
        if 'label' in col.lower() or 'attack' in col.lower() or 'ddos' in col.lower():
            return col

    raise ValueError(f"Could not find label column. Available columns: {list(df.columns)}")

def convert_protocol(protocol):
    """Convert protocol to numeric if needed."""
    if isinstance(protocol, str):
        protocol_map = {
            'TCP': 6, 'tcp': 6,
            'UDP': 17, 'udp': 17,
            'ICMP': 1, 'icmp': 1
        }
        return protocol_map.get(protocol, 6)
    return int(protocol) if not pd.isna(protocol) else 6

def prepare_bccc_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Prepare BCCC dataset features for text conversion.
    Maps BCCC columns to standard feature names.
    """
    features = df.copy()

    # Map duration (might be in seconds or microseconds)
    if 'duration' in features.columns:
        duration = pd.to_numeric(features['duration'], errors='coerce')
        # If duration is very small (< 1), assume it's in seconds, otherwise might be microseconds
        if duration.max() > 1000:
            duration = duration / 1_000_000.0  # Convert microseconds to seconds
        features['duration_s'] = duration.fillna(0)
    else:
        features['duration_s'] = 0

    # Map packet counts
    if 'packets_count' in features.columns:
        tot_pkts = pd.to_numeric(features['packets_count'], errors='coerce').fillna(0)
    else:
        tot_pkts = 0

    if 'fwd_packets_count' in features.columns:
        fwd_pkts = pd.to_numeric(features['fwd_packets_count'], errors='coerce').fillna(0)
    else:
        fwd_pkts = 0

    # Calculate backward packets
    bwd_pkts = tot_pkts - fwd_pkts
    bwd_pkts = bwd_pkts.clip(lower=0)

    features['tot_fwd_pkts'] = fwd_pkts
    features['tot_bwd_pkts'] = bwd_pkts

    # Map bytes if available
    byte_cols = [c for c in features.columns if 'byte' in c.lower() or 'bytes' in c.lower()]
    if byte_cols:
        tot_bytes = pd.to_numeric(features[byte_cols[0]], errors='coerce').fillna(0)
    else:
        # Estimate bytes from packets (average packet size ~1500 bytes)
        tot_bytes = tot_pkts * 1500

    features['tot_bytes'] = tot_bytes

    # Calculate packet length means
    features['fwd_pkt_len_mean'] = np.where(
        fwd_pkts > 0,
        tot_bytes / fwd_pkts,
        0
    )
    features['bwd_pkt_len_mean'] = np.where(
        bwd_pkts > 0,
        tot_bytes / bwd_pkts,
        0
    )

    # Calculate packets per second
    duration = features['duration_s'].replace(0, 1e-9)  # Avoid division by zero
    features['flow_pkts_per_s'] = tot_pkts / duration

    # Calculate IAT (inter-arrival time) - simplified
    features['flow_iat_mean_s'] = duration / tot_pkts.replace(0, 1)

    # Map protocol
    if 'protocol' in features.columns:
        features['protocol'] = features['protocol'].apply(convert_protocol)
    else:
        features['protocol'] = 6  # Default to TCP

    # Map IPs and ports
    if 'src_ip' in features.columns:
        features['src_ip'] = features['src_ip'].astype(str)
    else:
        features['src_ip'] = 'unknown'

    if 'dst_ip' in features.columns:
        features['dst_ip'] = features['dst_ip'].astype(str)
    else:
        features['dst_ip'] = 'unknown'

    if 'src_port' in features.columns:
        features['src_port'] = pd.to_numeric(features['src_port'], errors='coerce').fillna(0).astype(int)
    else:
        features['src_port'] = 0

    if 'dst_port' in features.columns:
        features['dst_port'] = pd.to_numeric(features['dst_port'], errors='coerce').fillna(0).astype(int)
    else:
        features['dst_port'] = 0

    # Kubernetes context (not available in BCCC, set to False)
    features['src_is_pod'] = False
    features['dst_is_pod'] = False
    features['dst_is_service'] = False

    return features

def load_and_prepare_data(data_path: str) -> tuple:
    """
    Load BCCC Cloud DDoS 2024 dataset (training_2026/merged_CSVs.csv) and convert to text format for LLM.
    This function ONLY uses the specified dataset file - no other datasets are loaded.

    Args:
        data_path: Path to training_2026/merged_CSVs.csv file

    Returns:
        Tuple of (train_texts, val_texts, train_labels, val_labels, label_column)
    """
    print(f"{'='*70}")
    print(f"Loading BCCC Cloud DDoS 2024 dataset")
    print(f"Dataset file: {data_path}")
    print(f"{'='*70}")

    # Load in chunks if file is large
    try:
        # Try to read first chunk to get structure
        chunk = pd.read_csv(data_path, nrows=10000)
        print(f"Dataset structure detected. Total columns: {len(chunk.columns)}")
        print(f"Columns: {list(chunk.columns)[:10]}...")

        # Detect label column
        label_col = detect_label_column(chunk)
        print(f"Label column detected: {label_col}")

        # Read full dataset
        print("Reading full dataset (this may take a while for large files)...")
        df = pd.read_csv(data_path, low_memory=False)
        print(f"Loaded {len(df)} samples")

    except Exception as e:
        print(f"Error loading dataset: {e}")
        raise

    # Check label distribution
    if label_col in df.columns:
        print(f"\n{'='*70}")
        print("LABEL DISTRIBUTION ANALYSIS")
        print(f"{'='*70}")
        print(f"\nRaw label distribution:")
        label_counts = df[label_col].value_counts()
        total = len(df)
        for label, count in label_counts.items():
            pct = (count / total) * 100
            print(f"  {label}: {count:,} ({pct:.2f}%)")

        # Convert labels to binary (0 = benign, 1 = attack/suspicious)
        if df[label_col].dtype == 'object' or df[label_col].dtype == 'string':
            # String labels - convert to binary
            label_str = df[label_col].astype(str).str.lower().str.strip()
            benign_keywords = ['benign', 'normal', 'legitimate', '0', 'false', 'no']
            # Treat 'suspicious' as attack (1)
            df['label'] = (~label_str.isin(benign_keywords)).astype(int)
        else:
            # Numeric labels
            df['label'] = (df[label_col] != 0).astype(int)

        print(f"\nBinary label distribution:")
        binary_counts = df['label'].value_counts()
        benign_count = binary_counts.get(0, 0)
        attack_count = binary_counts.get(1, 0)
        benign_pct = (benign_count / total) * 100
        attack_pct = (attack_count / total) * 100

        print(f"  Benign (0): {benign_count:,} ({benign_pct:.2f}%)")
        print(f"  Attack (1): {attack_count:,} ({attack_pct:.2f}%)")

        # Balance assessment
        if benign_count > 0 and attack_count > 0:
            ratio = min(benign_count, attack_count) / max(benign_count, attack_count)
            imbalance_ratio = max(benign_count, attack_count) / min(benign_count, attack_count)

            print(f"\nBalance Assessment:")
            print(f"  Class ratio (minority/majority): {ratio:.4f}")
            print(f"  Imbalance ratio: {imbalance_ratio:.2f}:1")

            if ratio >= 0.9:
                print(f"   Dataset is HIGHLY BALANCED")
            elif ratio >= 0.7:
                print(f"    Dataset is MODERATELY BALANCED - consider class weights")
            elif ratio >= 0.5:
                print(f"    Dataset is SLIGHTLY IMBALANCED - class weights will be applied")
            elif ratio >= 0.3:
                print(f"   Dataset is IMBALANCED - strongly recommend class weights")
            else:
                print(f"   Dataset is HIGHLY IMBALANCED - class weights required")

        print(f"{'='*70}\n")
    else:
        raise ValueError(f"Label column '{label_col}' not found in dataset")

    # Prepare features
    print("\nPreparing features...")
    features_df = prepare_bccc_features(df)

    # Convert to text
    print("Converting features to text descriptions...")
    converter = FeatureToTextConverter()
    texts = []

    # Process in batches to avoid memory issues
    batch_size = 10000
    for i in range(0, len(features_df), batch_size):
        batch = features_df.iloc[i:i+batch_size]
        for _, row in batch.iterrows():
            text = converter.network_flow_to_text(row.to_dict())
            texts.append(text)
        if (i + batch_size) % 50000 == 0:
            print(f"  Processed {i + batch_size} samples...")

    print(f"Converted {len(texts)} samples to text")

    # Split into train/validation
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts,
        df['label'].values,
        test_size=0.2,
        random_state=42,
        stratify=df['label']
    )

    print(f"\nTrain: {len(train_texts)} samples")
    print(f"Validation: {len(val_texts)} samples")
    print(f"Train label distribution: {Counter(train_labels)}")
    print(f"Val label distribution: {Counter(val_labels)}")

    return train_texts, val_texts, train_labels, val_labels, label_col

def compute_metrics(eval_pred):
    """Compute metrics for evaluation."""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=1)

    return {
        'accuracy': accuracy_score(labels, predictions),
        'f1': f1_score(labels, predictions),
        'precision': precision_score(labels, predictions),
        'recall': recall_score(labels, predictions)
    }

def train_model(
    train_texts: list,
    val_texts: list,
    train_labels: list,
    val_labels: list,
    output_dir: str = "./bccc_ddos_model",
    num_epochs: int = 3,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
    max_length: int = 512
):
    """
    Train DistilBERT for binary classification on BCCC DDoS dataset.
    """
    print(f"\n{'='*70}")
    print("TRAINING DISTILBERT MODEL")
    print(f"{'='*70}")
    print(f"Model: distilbert-base-uncased")
    print(f"Output directory: {output_dir}")
    print(f"Epochs: {num_epochs}")
    print(f"Batch size: {batch_size}")
    print(f"Learning rate: {learning_rate}")
    print(f"Max length: {max_length}")
    print(f"{'='*70}\n")

    print("Loading tokenizer and model...")
    tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=2  # Binary classification: benign (0) or DDoS attack (1)
    )

    # Tokenize datasets
    print("Tokenizing training data...")
    train_encodings = tokenizer(
        train_texts,
        padding="max_length",
        truncation=True,
        max_length=max_length,
        return_tensors="pt"
    )

    print("Tokenizing validation data...")
    val_encodings = tokenizer(
        val_texts,
        padding="max_length",
        truncation=True,
        max_length=max_length,
        return_tensors="pt"
    )

    # Create HuggingFace datasets
    train_dataset = Dataset.from_dict({
        'input_ids': train_encodings['input_ids'],
        'attention_mask': train_encodings['attention_mask'],
        'labels': torch.tensor(train_labels, dtype=torch.long)
    })

    val_dataset = Dataset.from_dict({
        'input_ids': val_encodings['input_ids'],
        'attention_mask': val_encodings['attention_mask'],
        'labels': torch.tensor(val_labels, dtype=torch.long)
    })

    train_dataset.set_format('torch')
    val_dataset.set_format('torch')

    # Calculate class weights for imbalanced dataset
    from sklearn.utils.class_weight import compute_class_weight
    import numpy as np

    class_weights = compute_class_weight(
        'balanced',
        classes=np.unique(train_labels),
        y=train_labels
    )
    class_weights_dict = {i: weight for i, weight in enumerate(class_weights)}
    class_weights_tensor = torch.tensor([class_weights_dict[0], class_weights_dict[1]], dtype=torch.float)

    print(f"\nClass weights (for imbalanced dataset):")
    print(f"  Benign (0): {class_weights_dict[0]:.4f}")
    print(f"  Attack (1): {class_weights_dict[1]:.4f}")

    # Training arguments
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        learning_rate=learning_rate,
        weight_decay=0.01,
        logging_dir=f"{output_dir}/logs",
        logging_steps=100,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",  # Use F1-score for imbalanced dataset
        greater_is_better=True,
        save_total_limit=2,
        seed=42,
        fp16=torch.cuda.is_available(),
        report_to="none"
    )

    # Custom trainer with class weights
    from torch import nn

    class WeightedTrainer(Trainer):
        """Trainer with class weights for imbalanced dataset."""
        def __init__(self, class_weights=None, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.class_weights = class_weights

        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.get("labels")
            outputs = model(**inputs)
            logits = outputs.get("logits")

            if self.class_weights is not None:
                loss_fct = nn.CrossEntropyLoss(weight=self.class_weights.to(logits.device))
            else:
                loss_fct = nn.CrossEntropyLoss()

            loss = loss_fct(logits, labels)
            return (loss, outputs) if return_outputs else loss

    # Initialize trainer with class weights
    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)],
        class_weights=class_weights_tensor
    )

    # Train
    print("\nStarting training...")
    trainer.train()

    # Evaluate
    print("\n" + "="*70)
    print("EVALUATION RESULTS")
    print("="*70)
    eval_results = trainer.evaluate()
    print(f"\nValidation Metrics:")
    for key, value in eval_results.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")

    # Detailed evaluation
    print("\n" + "="*70)
    print("DETAILED CLASSIFICATION REPORT")
    print("="*70)
    predictions = trainer.predict(val_dataset)
    pred_labels = np.argmax(predictions.predictions, axis=1)

    print("\nClassification Report:")
    print(classification_report(val_labels, pred_labels, target_names=['Benign', 'DDoS Attack']))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(val_labels, pred_labels)
    print(cm)
    print(f"\n  True Negatives (BenignBenign): {cm[0][0]}")
    print(f"  False Positives (BenignAttack): {cm[0][1]}")
    print(f"  False Negatives (AttackBenign): {cm[1][0]}")
    print(f"  True Positives (AttackAttack): {cm[1][1]}")

    # ROC-AUC and PR-AUC
    try:
        probs = torch.softmax(torch.tensor(predictions.predictions), dim=-1)[:, 1].numpy()
        roc_auc = roc_auc_score(val_labels, probs)
        ap = average_precision_score(val_labels, probs)
        print(f"\nROC-AUC Score: {roc_auc:.4f}")
        print(f"PR-AUC (Average Precision): {ap:.4f}")
    except Exception as e:
        roc_auc = None
        ap = None
        print(f"\nCould not calculate ROC-AUC / PR-AUC: {e}")

    # Save performance artifacts
    print(f"\nSaving performance artifacts...")
    os.makedirs(output_dir, exist_ok=True)
    metrics = {
        "eval_metrics": {k: float(v) for k, v in eval_results.items() if isinstance(v, (int, float))},
        "confusion_matrix": cm.tolist(),
        "roc_auc": float(roc_auc) if roc_auc is not None else None,
        "pr_auc": float(ap) if ap is not None else None,
        "class_report": classification_report(val_labels, pred_labels, target_names=["Benign", "DDoS Attack"], output_dict=True),
    }
    (Path(output_dir) / "metrics.json").write_text(json.dumps(metrics, indent=2))

    # Save PR curve data
    if roc_auc is not None and ap is not None:
        prec, rec, _ = precision_recall_curve(val_labels, probs)
        pr_df = pd.DataFrame({"precision": prec, "recall": rec})
        pr_df.to_csv(Path(output_dir) / "pr_curve.csv", index=False)

    # Save confusion matrix
    cm_df = pd.DataFrame(cm, index=["Benign", "DDoS Attack"], columns=["Pred_Benign", "Pred_Attack"])
    cm_df.to_csv(Path(output_dir) / "confusion_matrix.csv")

    # Save model and tokenizer
    print(f"\n{'='*70}")
    print(f"Saving model to {output_dir}...")
    trainer.save_model()
    tokenizer.save_pretrained(output_dir)
    print(f" Model saved successfully!")
    print(f"{'='*70}\n")

    return trainer, model, tokenizer

def main():
    parser = argparse.ArgumentParser(
        description="Train DistilBERT on BCCC Cloud DDoS Attacks 2024 dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--data",
        type=str,
        default="training_2026/merged_CSVs.csv",
        help="Path to BCCC Cloud DDoS dataset CSV file (default: training_2026/merged_CSVs.csv). Only uses this single dataset."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./bccc_ddos_model",
        help="Output directory for trained model (default: ./bccc_ddos_model)"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs (default: 3)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Training batch size (default: 16)"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-5,
        help="Learning rate (default: 2e-5)"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=512,
        help="Maximum sequence length (default: 512)"
    )

    args = parser.parse_args()

    # Check if data file exists
    if not os.path.exists(args.data):
        print(f" Error: Dataset file not found: {args.data}")
        sys.exit(1)

    try:
        # Load and prepare data
        train_texts, val_texts, train_labels, val_labels, label_col = load_and_prepare_data(args.data)

        # Train model
        trainer, model, tokenizer = train_model(
            train_texts,
            val_texts,
            train_labels,
            val_labels,
            output_dir=args.output_dir,
            num_epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            max_length=args.max_length
        )

        print(" Training completed successfully!")
        print(f"\nModel saved to: {args.output_dir}")
        print(f"You can now use this model for inference.")

    except Exception as e:
        print(f"\n Error during training: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
