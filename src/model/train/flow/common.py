"""Shared helpers for the runtime-IDS training scripts.

Keeping the split and the metrics in one place guarantees the tree models and
the deep sequence model are evaluated identically and are comparable.
"""
import json

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score,
                             confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)

def time_split(n, train_frac=0.7):
    """Time-ordered split: the earliest `train_frac` of rows is the training
    set, the rest is the test set.

    The dataset is already sorted by timestamp, so this is an honest
    'train on the past, test on the future' holdout - no future leakage.
    """
    cut = int(n * train_frac)
    idx = np.arange(n)
    return idx[:cut], idx[cut:]

def binary_metrics(y_true, y_prob, threshold=0.5):
    """Standard binary-classification metrics at a given decision threshold."""
    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob, dtype=float)
    y_pred = (y_prob >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0)
    metrics = {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }
    if len(set(y_true.tolist())) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        metrics["pr_auc"] = float(average_precision_score(y_true, y_prob))
    return metrics

def false_positive_rate(y_true, y_pred):
    """Fraction of benign events wrongly flagged as attacks."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    negatives = (y_true == 0)
    return float((y_pred[negatives] == 1).mean()) if negatives.sum() else 0.0

def per_attack_recall(y_true, y_pred, attack_types):
    """Recall for each attack type (among events whose true label is attack)."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    attack_types = np.asarray(attack_types, dtype=object)
    result = {}
    for attack_type in sorted(set(attack_types[y_true == 1].tolist())):
        mask = (y_true == 1) & (attack_types == attack_type)
        result[attack_type] = {
            "support": int(mask.sum()),
            "recall": float((y_pred[mask] == 1).mean()) if mask.sum() else 0.0,
        }
    return result

def save_json(obj, path):
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)
