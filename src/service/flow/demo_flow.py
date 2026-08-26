#!/usr/bin/env python3
"""Replay BCCC flow records through the hybrid detector and print what each model contributed."""
import os
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import argparse
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "archive/2026-flow-retraining"))
sys.path.insert(0, str(REPO / "src/service/flow"))
from tabular_data import load_tabular            # noqa: E402
from flow_detector import FlowDetector, severity_for  # noqa: E402

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
BOLD = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"

def banner(t):
    print(f"\n{BOLD}{B}{'=' * 66}{X}\n{BOLD}{B}  {t}{X}\n{BOLD}{B}{'=' * 66}{X}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=8000, help="how many flow records to replay")
    args = ap.parse_args()

    banner("COMPONENTA FLOW — detector hibrid XGBoost + Autoencoder (BCCC)")
    det = FlowDetector()
    print(f"{G} models loaded{X}: XGBoost (supervised) + Autoencoder (unsupervised) "
          f"+ fuziune Platt (prag@FPR=1% = {det.fusion['threshold']:.3f})")

    split = load_tabular(str(REPO / "data/bccc-retraining/holdout_split/test_holdout.csv"),
                         sample_size=args.limit)
    y = split.y.astype(int)
    print(f"  flow records: {len(y):,} ({int((y == 1).sum()):,} DDoS / {int((y == 0).sum()):,} benign)")
    out = det.score_frame(split.X)
    sc, lab, pxgb, pae = out["score"], out["label"], out["p_xgb"], out["p_ae"]

    banner("FEED — flow records prin detector (p_xgb · p_ae · score fuzionat)")
    bi = np.where(y == 0)[0][:4]
    di = np.where(y == 1)[0][:4]
    for idx in list(bi) + list(di):
        real = "DDoS  " if y[idx] == 1 else "benign"
        brk = f"p_xgb={pxgb[idx]:.2f} p_ae={pae[idx]:.2f}  score={sc[idx]:.3f}"
        if lab[idx] == 1:
            print(f"  {R}{BOLD} ALERT{X} [{R}{severity_for(sc[idx]):8s}{X}] {brk}  {DIM}real={real}{X}")
        else:
            print(f"  {G} benign{X}             [{'NONE':8s}] {brk}  {DIM}real={real}{X}")

    banner("REZULTATE AGREGATE")
    tp = int(((lab == 1) & (y == 1)).sum()); fn = int(((lab == 0) & (y == 1)).sum())
    fp = int(((lab == 1) & (y == 0)).sum()); tn = int(((lab == 0) & (y == 0)).sum())
    recall = tp / max(tp + fn, 1); fpr = fp / max(fp + tn, 1); prec = tp / max(tp + fp, 1)
    print(f"  Recall DDoS: {G}{recall:.3f}{X}   Precision: {prec:.3f}   "
          f"FPR: {Y}{fpr * 100:.2f}%{X}   (la pragul de deploy)")
    print(f"\n  {DIM}XGBoost prinde signature-ul DDoS cunoscut (AUC ~0.97); autoencoder-ul e")
    print(f"  plasa unsupervised — valoarea lui apare mai ales la distribution shift")
    print(f"  (pe ITU leave-heavy-hitter-out, AUC 0.66  0.86; vezi lucrarea).{X}")

    banner("flow record -> XGBoost + autoencoder -> fusion -> alert")

if __name__ == "__main__":
    main()
