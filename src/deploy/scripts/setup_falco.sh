#!/bin/bash
# Install Falco, the syscall-level layer, with versioned values instead of a one-liner.
# Idempotent. Not part of the normal deploy: on the AKS node kernel the engine loads but never
# emits, so this only pays off on a node where eBPF capture actually works.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K="${KUBECTL:-kubectl}"

echo ">> Falco [1/3]: helm repo"
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update falcosecurity >/dev/null 2>&1 || true

echo ">> Falco [2/3]: exporter ConfigMap (Prometheus bridge)"
$K create namespace runtime-ids >/dev/null 2>&1 || true
$K -n runtime-ids create configmap falco-exporter-code \
  --from-file=falco_exporter.py="$HERE/../k8s/falco_exporter.py" \
  --dry-run=client -o yaml | $K apply -f -
$K apply -f "$HERE/../k8s/80-falco-exporter.yaml"

echo ">> Falco [3/3]: DaemonSet (modern eBPF + http_output -> exporter)"
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace -f "$HERE/../k8s/falco-values.yaml"
$K -n falco rollout status ds/falco --timeout=180s || true
echo ">> Falco installed: privileged DaemonSet in ns falco, alerts -> falco-exporter:9093 -> Prometheus"
