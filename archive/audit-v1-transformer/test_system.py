#!/usr/bin/env python3
"""Smoke test pentru sistemul IDS multi-componentă (Flow + Audit).

Validează că AMBELE componente sunt funcționale:
  - Flow (XGBoost + Autoencoder pe BCCC): prinde DDoS, FPR mic, separă clasele.
  - Audit (Transformer pe audit K8s, via serviciu): benignfără alertă, atacalertă.

Rulare:
  python3 test_system.py          # necesită serviciul Audit pe :8080
Cod de ieșire 0 = toate testele PASS.
"""
import os
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import json
import sys
from pathlib import Path

RID = Path(__file__).resolve().parent          # runtime_ids/
ROOT = RID.parent                              # repo root
sys.path.insert(0, str(ROOT / "retraining_bccc"))
sys.path.insert(0, str(RID / "flow"))

import requests                                 # noqa: E402
from tabular_data import load_tabular           # noqa: E402
from flow_detector import FlowDetector          # noqa: E402

P = "\033[92mPASS\033[0m"; F = "\033[91mFAIL\033[0m"
results = []

def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{P if cond else F}] {name}  {detail}")

# ---------------- TEST 1: Componenta Flow ---------------- #
print("=== TEST 1: Componenta Flow (XGBoost + Autoencoder, BCCC) ===")
det = FlowDetector()
check("Flow: modele + fuziune încărcate", True)
split = load_tabular(str(ROOT / "data/bccc-retraining/holdout_split/test_holdout.csv"),
                     sample_size=3000)
y = split.y.astype(int)
out = det.score_frame(split.X)
lab, sc = out["label"], out["score"]
tp = int(((lab == 1) & (y == 1)).sum()); fn = int(((lab == 0) & (y == 1)).sum())
fp = int(((lab == 1) & (y == 0)).sum()); tn = int(((lab == 0) & (y == 0)).sum())
recall = tp / max(tp + fn, 1); fpr = fp / max(fp + tn, 1)
sep = float(sc[y == 1].mean() - sc[y == 0].mean())
check("Flow: recall DDoS > 0.60", recall > 0.60, f"(recall={recall:.3f})")
check("Flow: FPR < 6%", fpr < 0.06, f"(FPR={fpr*100:.2f}%)")
check("Flow: separă benign vs DDoS (Δscore > 0.3)", sep > 0.30, f"(Δ={sep:.2f})")

# ---------------- TEST 2: Componenta Audit ---------------- #
print("\n=== TEST 2: Componenta Audit (Transformer, via serviciu :8080) ===")
SVC = "http://localhost:8080"
try:
    ready = requests.get(f"{SVC}/readyz", timeout=5).json().get("status") == "ready"
except Exception:
    ready = False
check("Audit: serviciu activ", ready, f"({SVC})")
if ready:
    seqs = [json.loads(l) for l in open(RID / "data/sequences.jsonl")]
    benign = next(d for d in seqs if d["label"] == 0 and any(t != "<PAD>" for t in d["tokens"]))
    attack = next(d for d in seqs if d["label"] == 1)
    rb = requests.post(f"{SVC}/predict", json={"tokens": benign["tokens"], "actor": benign["user"]}, timeout=5).json()
    ra = requests.post(f"{SVC}/predict", json={"tokens": attack["tokens"], "actor": attack["user"]}, timeout=5).json()
    check("Audit: benign  fără alertă", rb["label"] == 0, f"(p={rb['probability']:.3f})")
    check("Audit: atac  alertă", ra["label"] == 1, f"(p={ra['probability']:.3f}, {ra['severity']})")
else:
    print("  (pornește serviciul: cd service && uvicorn ids_service:app --port 8080)")

# ---------------- bilanț ---------------- #
ok = sum(results); tot = len(results)
print(f"\n=== {ok}/{tot} teste PASS ===")
sys.exit(0 if ok == tot else 1)
