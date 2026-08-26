#!/usr/bin/env python3
"""Operating-point + coverage analysis for the trained IDS modules.

Discovers every models/<name>/predictions.csv and produces:

  models/evaluation/operating_points.json   - ROC/PR AUC, best-F1, recall@FPR,
                                              FPR@recall for each model
  models/evaluation/per_attack_summary.csv  - per-attack-type recall, all models
  models/evaluation/pr_curves.png           - precision-recall curves
  models/evaluation/roc_curves.png          - ROC curves
  models/evaluation/mitre_coverage.md       - MITRE ATT&CK coverage table

These are the figures and operating points a thesis defence is built around.
"""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                             roc_auc_score, roc_curve)

REPO = Path(__file__).resolve().parents[4]

# Each attack scenario -> MITRE ATT&CK technique it represents.
MITRE_TABLE = [
    ("recon",           "T1613", "Container and Resource Discovery",  "Discovery"),
    ("exec_abuse",      "T1609", "Container Administration Command",  "Execution"),
    ("rbac_escalation", "T1078", "Valid Accounts",                    "Privilege Escalation"),
    ("secret_access",   "T1552", "Unsecured Credentials",             "Credential Access"),
    ("sa_token_abuse",  "T1528", "Steal Application Access Token",    "Credential Access"),
    ("malicious_pod",   "T1610", "Deploy Container",                  "Execution / Priv. Esc."),
]

def operating_points(y, prob):
    precision, recall, thr_pr = precision_recall_curve(y, prob)
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-9)
    i = int(np.argmax(f1))
    best_f1 = {"threshold": float(thr_pr[i]),
               "precision": float(precision[i]),
               "recall": float(recall[i]),
               "f1": float(f1[i])}

    fpr, tpr, thr_roc = roc_curve(y, prob)

    def recall_at_fpr(target):
        idx = np.searchsorted(fpr, target, side="right") - 1
        if idx < 0:
            return {"target_fpr": target, "achieved": False}
        return {"target_fpr": target, "achieved_fpr": float(fpr[idx]),
                "recall": float(tpr[idx]),
                "threshold": float(thr_roc[idx]) if idx < len(thr_roc) else None}

    def fpr_at_recall(target):
        idx = np.searchsorted(tpr, target, side="left")
        if idx >= len(tpr):
            return {"target_recall": target, "achieved": False}
        return {"target_recall": target, "achieved_recall": float(tpr[idx]),
                "fpr": float(fpr[idx])}

    return {
        "roc_auc": float(roc_auc_score(y, prob)),
        "pr_auc": float(average_precision_score(y, prob)),
        "best_f1": best_f1,
        "recall_at_fpr_0.01":  recall_at_fpr(0.01),
        "recall_at_fpr_0.001": recall_at_fpr(0.001),
        "fpr_at_recall_0.95":  fpr_at_recall(0.95),
        "fpr_at_recall_0.99":  fpr_at_recall(0.99),
    }

def discover_modules(models_dir):
    modules = []
    for d in sorted(models_dir.iterdir()):
        if not d.is_dir() or d.name in ("evaluation", "fusion"):
            continue
        pred = d / "predictions.csv"
        if pred.exists():
            modules.append((d.name, pred))
    return modules

def write_mitre_table(path):
    with open(path, "w") as f:
        f.write("# MITRE ATT&CK Coverage - Two-Layer Kubernetes IDS\n\n")
        f.write("## Audit layer (this work)\n\n")
        f.write("| Scenario | MITRE ID | Technique | Tactic | Covered |\n")
        f.write("|---|---|---|---|---|\n")
        for sc, mid, name, tactic in MITRE_TABLE:
            f.write(f"| `{sc}` | {mid} | {name} | {tactic} |  |\n")
        f.write("\n## Network-flow layer (complementary - Report 1)\n\n")
        f.write("None of these techniques appear in the API audit log "
                "(they happen at the network layer, which the API server does "
                "not record). They are exactly what a flow-based detector "
                "covers and what the audit layer cannot see.\n\n")
        f.write("| Attack class | MITRE ID | Technique | Audit layer |\n")
        f.write("|---|---|---|---|\n")
        f.write("| DDoS | T1498 | Network Denial of Service |  invisible |\n")
        f.write("| Port scanning | T1046 | Network Service Discovery |  invisible |\n")
        f.write("| Brute force | T1110 | Brute Force |  invisible |\n")
        f.write("| Remote exploitation | T1210 | Exploitation of Remote Services |  invisible |\n")
        f.write("\n## Conclusion\n\n")
        f.write("The two layers are **complementary**: neither covers the "
                "techniques of the other. A complete Kubernetes IDS requires "
                "both. Alert-level fusion (OR / calibrated OR) yields the "
                "union of MITRE coverage.\n")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", default=str(REPO / "data/models"))
    parser.add_argument("--outdir", default=str(REPO / "data/models/evaluation"))
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    modules = discover_modules(models_dir)
    if not modules:
        print(f"No predictions.csv files found under {models_dir}")
        return
    print(f"Discovered {len(modules)} module(s):")
    for name, _ in modules:
        print(f"  - {name}")

    op_points = {}
    per_attack_rows = []

    fig_pr, ax_pr = plt.subplots(figsize=(7, 5))
    fig_roc, ax_roc = plt.subplots(figsize=(7, 5))

    for name, path in modules:
        df = pd.read_csv(path)
        y = df["label"].to_numpy(int)
        prob = df["prob"].to_numpy(float)
        attack_type = df["attack_type"].fillna("").to_numpy(object)

        op_points[name] = operating_points(y, prob)
        op_points[name]["test_rows"] = int(len(y))
        op_points[name]["n_attack"] = int(y.sum())

        precision, recall, _ = precision_recall_curve(y, prob)
        ax_pr.plot(recall, precision, label=f"{name} (AP={op_points[name]['pr_auc']:.3f})")

        fpr, tpr, _ = roc_curve(y, prob)
        ax_roc.plot(fpr, tpr, label=f"{name} (AUC={op_points[name]['roc_auc']:.3f})")

        pred = (prob >= 0.5).astype(int)
        for atk in sorted(set(attack_type[y == 1].tolist())):
            mask = (y == 1) & (attack_type == atk)
            per_attack_rows.append({"model": name, "attack_type": atk,
                                     "support": int(mask.sum()),
                                     "recall_at_0.5": float((pred[mask] == 1).mean())})

    ax_pr.set_xlabel("Recall")
    ax_pr.set_ylabel("Precision")
    ax_pr.set_title("Precision-Recall curves (audit layer)")
    ax_pr.legend(loc="lower left")
    ax_pr.grid(alpha=0.3)
    ax_pr.set_xlim(0, 1); ax_pr.set_ylim(0, 1.02)

    ax_roc.plot([0, 1], [0, 1], "k--", alpha=0.4)
    ax_roc.set_xlabel("False Positive Rate")
    ax_roc.set_ylabel("True Positive Rate")
    ax_roc.set_title("ROC curves (audit layer)")
    ax_roc.legend(loc="lower right")
    ax_roc.grid(alpha=0.3)
    ax_roc.set_xlim(0, 1); ax_roc.set_ylim(0, 1.02)

    fig_pr.tight_layout()
    fig_pr.savefig(outdir / "pr_curves.png", dpi=150)
    fig_roc.tight_layout()
    fig_roc.savefig(outdir / "roc_curves.png", dpi=150)

    with open(outdir / "operating_points.json", "w") as f:
        json.dump(op_points, f, indent=2)

    per_attack_df = pd.DataFrame(per_attack_rows)
    per_attack_df.to_csv(outdir / "per_attack_summary.csv", index=False)

    write_mitre_table(outdir / "mitre_coverage.md")

    pivot = per_attack_df.pivot(index="attack_type", columns="model",
                                 values="recall_at_0.5")
    print("\nPer-attack-type recall @ threshold 0.5:")
    print(pivot.to_string(float_format=lambda x: f"{x:.3f}"))

    print(f"\n{'model':22s} {'ROC':>6} {'PR':>6} {'bestF1':>7} "
          f"{'rec@FPR=1%':>11} {'rec@FPR=0.1%':>13}")
    for name, op in op_points.items():
        r1 = op["recall_at_fpr_0.01"].get("recall", 0)
        r01 = op["recall_at_fpr_0.001"].get("recall", 0)
        print(f"{name:22s} {op['roc_auc']:.3f}  {op['pr_auc']:.3f}  "
              f"{op['best_f1']['f1']:.3f}    {r1:>9.3f}     {r01:>9.3f}")

    print(f"\n -> {outdir}/  (operating_points.json, per_attack_summary.csv, "
          f"pr_curves.png, roc_curves.png, mitre_coverage.md)")

if __name__ == "__main__":
    main()
