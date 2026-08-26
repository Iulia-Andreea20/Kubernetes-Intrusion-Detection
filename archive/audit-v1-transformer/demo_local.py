#!/usr/bin/env python3
"""Demo local end-to-end — Componenta Audit

NU necesită cluster.

Rulare:
  python3 demo/demo_local.py
  python3 demo/demo_local.py --delay 0.15
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parents[1]          # runtime_ids/
SEQ = REPO / "data" / "sequences.jsonl"
SERVICE = "http://localhost:8080"

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
BOLD = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"

SESSION = requests.Session()

def predict(tokens, actor):
    resp = SESSION.post(f"{SERVICE}/predict",
                        json={"tokens": tokens, "actor": actor}, timeout=10)
    resp.raise_for_status()
    return resp.json()

def ready() -> bool:
    try:
        return SESSION.get(f"{SERVICE}/readyz", timeout=5).json().get("status") == "ready"
    except Exception:
        return False

def banner(t):
    print(f"\n{BOLD}{B}{'=' * 66}{X}")
    print(f"{BOLD}{B}  {t}{X}")
    print(f"{BOLD}{B}{'=' * 66}{X}")

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="pauză (s) între evenimentele din feed-ul live")
    ap.add_argument("--limit", type=int, default=0,
                    help="procesează doar primele N secvențe la agregat (0 = tot)")
    args = ap.parse_args()

    # ---- 1. SERVICIU ---- #
    banner("1. SERVICIUL IDS (Componenta Audit)")
    if not ready():
        print(f"{R} Serviciul nu răspunde la {SERVICE}.{X}")
        print(f"  Pornește-l: cd runtime_ids/service && "
              f"uvicorn ids_service:app --port 8080")
        sys.exit(1)
    print(f"{G} Serviciu activ{X} — model Transformer încărcat (sequence_audit), "
          f"endpoint POST /predict, metrici Prometheus la /metrics")

    seqs = [json.loads(l) for l in open(SEQ)]

    # ---- 2. FEED LIVE (eșantion curat) ---- #
    banner("2. FEED LIVE — detecție în timp real (eșantion)")
    feed, nb, seen = [], 0, set()
    for d in seqs:
        if d["label"] == 0 and nb < 6 and any(t != "<PAD>" for t in d["tokens"]):
            feed.append(d); nb += 1
        elif d["label"] == 1 and d["attack_type"] not in seen:
            feed.append(d); seen.add(d["attack_type"])
        if nb >= 6 and len(seen) >= 6:
            break
    for d in feed:
        r = predict(d["tokens"], d["user"])
        real = [t for t in d["tokens"] if t != "<PAD>"]
        tail = "  ".join(real[-5:])
        if r["label"] == 1:
            print(f"  {R}{BOLD} ALERTĂ{X} [{R}{r['severity']:8s}{X}] "
                  f"user={d['user']:16s} p={r['probability']:.3f}  "
                  f"{R}{BOLD}{d['attack_type']}{X}")
            print(f"      {DIM}{tail}{X}")
        else:
            print(f"  {G} benign{X}             user={d['user']:16s} "
                  f"p={r['probability']:.3f}")
        if args.delay:
            time.sleep(args.delay)

    # ---- 3. AGREGAT (tot setul) ---- #
    banner("3. REZULTATE AGREGATE — tot setul prin serviciul live")
    data = seqs[:args.limit] if args.limit else seqs
    print(f"  Procesez {len(data):,} secvențe prin serviciu...")
    by_atk = defaultdict(lambda: [0, 0])
    sev = Counter(); tp = fp = tn = fn = 0
    rows = []
    t0 = time.time()
    for i, d in enumerate(data):
        r = predict(d["tokens"], d["user"])
        pred, true = r["label"], d["label"]
        if true == 1:
            by_atk[d["attack_type"]][1] += 1
            if pred == 1:
                by_atk[d["attack_type"]][0] += 1; tp += 1
            else:
                fn += 1
        else:
            fp += 1 if pred == 1 else 0
            tn += 1 if pred == 0 else 0
        if pred == 1:
            sev[r["severity"]] += 1
        rows.append((d["timestamp"], d["user"], d["attack_type"], true,
                     round(r["probability"], 6), pred))
        if (i + 1) % 1500 == 0:
            print(f"    ... {i + 1:,}/{len(data):,}")
    dt = time.time() - t0
    recall = tp / max(tp + fn, 1)
    prec = tp / max(tp + fp, 1)
    fpr = fp / max(fp + tn, 1)

    print(f"\n  {BOLD}Detecție per tip de atac (recall):{X}")
    for atk, (det, tot) in sorted(by_atk.items(), key=lambda kv: -kv[1][1]):
        bar = "" * int(det / tot * 20)
        print(f"    {atk:22s} {det:4d}/{tot:<4d} ({det / tot * 100:5.1f}%) {G}{bar}{X}")
    print(f"\n  {BOLD}Global:{X} recall={G}{recall:.3f}{X}  "
          f"precision={G}{prec:.3f}{X}  FPR={Y}{fpr * 100:.2f}%{X}  "
          f"({len(data):,} cereri în {dt:.1f}s)")
    print(f"  {BOLD}Severități alerte:{X} {dict(sev)}")

    demo_pred = REPO / "demo" / "demo_predictions_sequence.csv"
    with open(demo_pred, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "user", "attack_type", "label", "prob", "pred"])
        w.writerows(rows)
    print(f"  {DIM}predicții live scrise în {demo_pred.relative_to(REPO)}{X}")

    # ---- 4. CORELARE ---- #
    banner("4. CORELARE  INCIDENTE (vederea analistului SOC)")
    print(f"  {DIM}Corelatorul agregă alertele din cele 3 componente "
          f"(XGBoost + LightGBM + Transformer)  incidente.{X}")
    res = subprocess.run([sys.executable, str(REPO / "correlator" / "run_correlator.py")],
                         capture_output=True, text=True)
    out = res.stdout
    if "Summary" in out:
        print("\n" + out[out.index("====") if "====" in out else 0:])
    else:
        print(out[-1200:])
        if res.returncode != 0:
            print(f"{R}{res.stderr[-800:]}{X}")

    inc_path = REPO / "models" / "correlator" / "incidents.json"
    if inc_path.exists():
        incs = json.loads(inc_path.read_text())
        print(f"  {BOLD}Incidente emise: {len(incs)}{X}")
        for inc in incs[:6]:
            chain = inc.get("chain_matched") or "-"
            seq = ", ".join(a for a in inc.get("attack_sequence", []) if a)[:50]
            print(f"    {R} {inc.get('severity', '?'):8s}{X} "
                  f"actor={inc.get('actor', '?'):16s} chain={chain:16s} {DIM}{seq}{X}")

    banner("DEMO COMPLET   (serviciu  detecție  alerte  corelare  incidente)")

if __name__ == "__main__":
    main()
