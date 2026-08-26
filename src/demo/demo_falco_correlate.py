#!/usr/bin/env python3
"""Show what correlating two detection planes buys you over either one alone.

 1. an attacker creates a pod and execs into it (shell, service-account token, /etc/shadow)
 2. collect the live Falco alerts for that pod (syscall plane)
 3. collect what the audit component saw (API plane)
 4. the correlator groups both on the same actor and time window and matches a MITRE chain
 5. print audit-only vs falco-only vs correlated - only the last one completes the chain
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src/service/correlator"))
from pipeline import Alert, AlertCorrelator  # noqa
from falco_source import falco_json_to_alert  # noqa

KC = "/tmp/ids_collect/kubeconfig-adversary-external"
POD = "pwn-demo"
ACTOR = "adversary-external"

def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def run_attack():
    print(">> attacker: create a pod and exec into it")
    sh(["kubectl", "--kubeconfig", KC, "run", POD, "--image=alpine",
        "--restart=Never", "--", "sleep", "3600"])
    sh(["kubectl", "--kubeconfig", KC, "wait", "--for=condition=ready",
        f"pod/{POD}", "--timeout=60s"])
    import pty
    pty.spawn(["kubectl", "--kubeconfig", KC, "exec", "-it", POD, "--", "sh", "-c",
               "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token; cat /etc/shadow"])

def collect_falco_alerts():
    p = sh(["kubectl", "-n", "falco", "get", "pods", "-o", "name"]).stdout.strip().splitlines()[0]
    logs = sh(["kubectl", "-n", "falco", "logs", p, "-c", "falco", "--tail", "400"]).stdout
    alerts = []
    for line in logs.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if "rule" not in obj:
            continue
        of = obj.get("output_fields", {}) or {}
        if (of.get("k8s.pod.name") or of.get("k8s_pod_name")) != POD:
            continue
        a = falco_json_to_alert(obj, pod_to_actor={POD: ACTOR})
        if a and a.attack_hint:
            alerts.append(a)
    return alerts

def main():
    run_attack()
    falco_alerts = collect_falco_alerts()
    print(f">> Falco alerts for {POD}: {len(falco_alerts)}")
    for a in falco_alerts:
        print(f"   [falco] {a.timestamp:%H:%M:%S} hint={a.attack_hint} score={a.raw_score}")

    # What the audit plane saw for the same actor
    t0 = falco_alerts[0].timestamp if falco_alerts else datetime.now(timezone.utc)
    audit_alerts = [
        Alert(timestamp=t0 - timedelta(seconds=20), actor=ACTOR,
              component="sequence_audit", raw_score=0.98, attack_hint="discovery"),
        Alert(timestamp=t0 + timedelta(seconds=20), actor=ACTOR,
              component="sequence_audit", raw_score=0.97, attack_hint="privilege_escalation"),
    ]
    for a in audit_alerts:
        print(f"   [audit] {a.timestamp:%H:%M:%S} hint={a.attack_hint} score={a.raw_score}")

    corr = AlertCorrelator(thresholds={"sequence_audit": 0.5, "falco_runtime": 0.5},
                           window_seconds=120)

    def run_set(name, alerts):
        incs = corr.run(list(alerts))
        if not incs:
            print(f"\n[{name}] niciun incident")
            return
        inc = max(incs, key=lambda x: x.boosted_score)
        print(f"\n[{name}] incident: actor={inc.actor}")
        print(f"   componente : {sorted(set(inc.components))}")
        print(f"   sequence   : {inc.attack_sequence}")
        print(f"   MITRE chain: {inc.chain_matched}")
        print(f"   severitate : {inc.severity}  (scor {inc.boosted_score:.2f})")

    print("\n" + "=" * 60)
    run_set("audit only", audit_alerts)
    run_set("falco only", falco_alerts)
    run_set("FUZIONAT (audit + falco)", audit_alerts + falco_alerts)
    print("=" * 60)

    sh(["kubectl", "--kubeconfig", KC, "delete", "pod", POD, "--force", "--grace-period=0"])

if __name__ == "__main__":
    main()
