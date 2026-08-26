#!/usr/bin/env python3
"""Falco true positives vs false positives: does a legitimate debug exec look like a hostile one?

backend-developer runs a normal debugging shell; adversary-external runs a hostile one that reads
the service-account token and /etc/shadow. Counts Falco alerts per pod and per rule.
"""
import json
import pty
import subprocess
import sys
from collections import defaultdict

KB = "/tmp/ids_collect/kubeconfig-backend-developer"
KA = "/tmp/ids_collect/kubeconfig-adversary-external"
BENIGN_POD, ATTACK_POD = "benign-debug", "attack-pwn"

def sh(c):
    return subprocess.run(c, capture_output=True, text=True)

def make_and_exec(kc, pod, cmd):
    sh(["kubectl", "--kubeconfig", kc, "run", pod, "--image=alpine",
        "--restart=Never", "--", "sleep", "3600"])
    sh(["kubectl", "--kubeconfig", kc, "wait", "--for=condition=ready",
        f"pod/{pod}", "--timeout=60s"])
    pty.spawn(["kubectl", "--kubeconfig", kc, "exec", "-it", pod, "--", "sh", "-c", cmd])

print(">> BENIGN: backend-developer face exec legitim de debugging...")
make_and_exec(KB, BENIGN_POD, "ls /; cat /etc/hostname; whoami; ps")
print(">> ATAC: adversary-external face exec ostil...")
make_and_exec(KA, ATTACK_POD, "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token; cat /etc/shadow")

# collect the Falco alerts
p = sh(["kubectl", "-n", "falco", "get", "pods", "-o", "name"]).stdout.strip().splitlines()[0]
logs = sh(["kubectl", "-n", "falco", "logs", p, "-c", "falco", "--tail", "800"]).stdout
by_pod = defaultdict(lambda: defaultdict(int))
for line in logs.splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        o = json.loads(line)
    except Exception:
        continue
    if "rule" not in o:
        continue
    pod = (o.get("output_fields", {}) or {}).get("k8s.pod.name", "")
    if pod in (BENIGN_POD, ATTACK_POD):
        by_pod[pod][o["rule"]] += 1

print("\n" + "=" * 60)
print(" Falco: benign vs attack, alerts per pod and rule")
print("=" * 60)
for pod, kind in [(BENIGN_POD, "BENIGN (backend-developer)"), (ATTACK_POD, "ATAC (adversary-external)")]:
    print(f"\n {kind}  [pod={pod}]")
    if not by_pod[pod]:
        print("   (no alerts)")
    for rule, n in sorted(by_pod[pod].items(), key=lambda kv: -kv[1]):
        tag = "FP" if pod == BENIGN_POD else "TP"
        print(f"   [{tag}] {rule}  x{n}")
print("=" * 60)

# cleanup
sh(["kubectl", "--kubeconfig", KB, "delete", "pod", BENIGN_POD, "--force", "--grace-period=0"])
sh(["kubectl", "--kubeconfig", KA, "delete", "pod", ATTACK_POD, "--force", "--grace-period=0"])
