#!/usr/bin/env python3
"""Generate the five comparison plots for the BCCC held-out experiment."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

# 1. Configure where the artifacts live
MODELS_ROOT = Path("cluster/dizertatie/retraining_bccc/models")
OUTPUT_DIR = Path("cluster/dizertatie/data/models/flow-bccc/plots_holdout")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODELS = {
    "DistilBERT": MODELS_ROOT / "bccc_ddos_holdout_model",
    "XGBoost":    MODELS_ROOT / "xgboost_bccc",
    "LightGBM":   MODELS_ROOT / "lightgbm_bccc",
}

# 2. Plot 1: headline metric bar chart
def plot_headline_metrics():
    metric_keys = ["accuracy", "f1", "precision", "recall", "roc_auc"]
    rows = []
    for name, path in MODELS.items():
        preds = pd.read_csv(path / "predictions_test.csv")
        y, proba = preds["actual"].values, preds["probability"].values
        pred_hard = (proba >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred_hard, labels=[0, 1]).ravel()
        rows.append({
            "model": name,
            "accuracy":  (tp + tn) / len(y),
            "precision": tp / max(tp + fp, 1),
            "recall":    tp / max(tp + fn, 1),
            "f1":        2 * tp / max(2 * tp + fp + fn, 1),
            "roc_auc":   roc_auc_score(y, proba),
        })
    df = pd.DataFrame(rows).set_index("model")[metric_keys]
    ax = df.plot(kind="bar", figsize=(10, 5), rot=0, edgecolor="black")
    ax.set_title("Held-out day (Tuesday) — model comparison")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1)
    ax.legend(title="Metric", loc="lower right")
    ax.grid(axis="y", linestyle=":")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "01_headline_metrics.png", dpi=150)
    plt.close()
    df.to_csv(OUTPUT_DIR / "01_headline_metrics.csv")

# 3. Plot 2 + 3: ROC and PR overlay
def plot_roc_pr():
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for name, path in MODELS.items():
        preds = pd.read_csv(path / "predictions_test.csv")
        y, proba = preds["actual"].values, preds["probability"].values
        fpr, tpr, _ = roc_curve(y, proba)
        prec, rec, _ = precision_recall_curve(y, proba)
        axes[0].plot(fpr, tpr, label=f"{name} (AUC={roc_auc_score(y, proba):.3f})")
        axes[1].plot(rec, prec, label=f"{name} (AP={average_precision_score(y, proba):.3f})")
    axes[0].plot([0, 1], [0, 1], "--", color="grey")
    axes[0].set_xlabel("False positive rate"); axes[0].set_ylabel("True positive rate")
    axes[0].set_title("ROC — Tuesday"); axes[0].legend(loc="lower right"); axes[0].grid(linestyle=":")
    axes[1].set_xlabel("Recall"); axes[1].set_ylabel("Precision")
    axes[1].set_title("Precision-Recall — Tuesday"); axes[1].legend(loc="lower left"); axes[1].grid(linestyle=":")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "02_roc_pr.png", dpi=150)
    plt.close()

# 4. Plot 4: confusion matrices grid
def plot_confusion_matrices():
    fig, axes = plt.subplots(1, len(MODELS), figsize=(4 * len(MODELS), 4))
    for ax, (name, path) in zip(axes, MODELS.items()):
        preds = pd.read_csv(path / "predictions_test.csv")
        y, p = preds["actual"].values, (preds["probability"].values >= 0.5).astype(int)
        cm = confusion_matrix(y, p, labels=[0, 1])
        im = ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=11,
                    color="white" if v > cm.max() / 2 else "black")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["Pred Benign", "Pred Attack"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["True Benign", "True Attack"])
        ax.set_title(name)
    fig.colorbar(im, ax=axes.ravel().tolist(), shrink=0.7)
    plt.savefig(OUTPUT_DIR / "03_confusion_matrices.png", dpi=150, bbox_inches="tight")
    plt.close()

# 5. Plot 5: top-15 feature importance for the two tree models
def plot_feature_importance():
    fig, axes = plt.subplots(1, 2, figsize=(12, 6))
    for ax, (name, path) in zip(axes, [("XGBoost", MODELS["XGBoost"]),
                                       ("LightGBM", MODELS["LightGBM"])]):
        fi = pd.read_csv(path / "feature_importance.csv").head(15).iloc[::-1]
        ax.barh(fi["feature"], fi["importance"])
        ax.set_title(f"{name} — Top-15 features")
        ax.set_xlabel("Importance")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "04_feature_importance.png", dpi=150)
    plt.close()

if __name__ == "__main__":
    plot_headline_metrics()
    plot_roc_pr()
    plot_confusion_matrices()
    plot_feature_importance()
    print(f"Plots saved to: {OUTPUT_DIR}")