#!/usr/bin/env python3
#  LEGACY (faza inițială kind + model Transformer) — NU sistemul actual v2.2/2.4. NU rula la apărare ca „IDS-ul meu". Sistemul curent (XGBoost + 6 reguli, AKS managed) = demo/run_demo_aks.sh. Vezi demo/README.md + SCENARIU_PREZENTARE.md.
"""Trigger demo: trimite ferestre REALE (benigne + atac) din cloud_test la serviciul Audit.
Serviciul (model max-pool) le scorează -> metrici Prometheus -> alertă -> Alertmanager -> email MailHog.
Necesită: kubectl -n runtime-ids port-forward svc/ids-service 8080:8080
"""
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

URL = "http://localhost:8080/predict"
SAMPLES = Path(__file__).parent / "cloud_test.jsonl"

def post(tokens, actor):
    req = urllib.request.Request(
        URL, data=json.dumps({"tokens": tokens, "actor": actor}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)

samples = [json.loads(l) for l in open(SAMPLES)]
benign = [s for s in samples if s["label"] == 0]
attack = [s for s in samples if s["label"] == 1]

print(f">> trimit {len(benign)} ferestre BENIGNE (baseline verde)...")
bf = 0
for s in benign:
    bf += post(s["tokens"], s.get("user", "?"))["label"]
print(f"   benign marcate ca ATAC (false positives): {bf}/{len(benign)}")

print(f">> trimit {len(attack)} ferestre de ATAC...")
af = 0
sev = Counter()
for s in attack:
    r = post(s["tokens"], s.get("user", "?"))
    af += r["label"]; sev[r["severity"]] += 1
print(f"   atac detectate: {af}/{len(attack)}  severități: {dict(sev)}")
print("\n>> metricile sunt acum în /metrics; Prometheus va declanșa alerta în ~1 min -> email MailHog.")
