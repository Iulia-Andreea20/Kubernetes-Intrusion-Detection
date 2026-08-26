#!/usr/bin/env bash
# Create a local kind cluster with Kubernetes API audit logging enabled.
set -euo pipefail

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKDIR"
CLUSTER_NAME="runtime-ids"

echo "[*] Workspace: $WORKDIR"

# preconditions
command -v docker  >/dev/null || { echo "ERROR: docker not found"; exit 1; }
docker info >/dev/null 2>&1   || { echo "ERROR: docker daemon not running"; exit 1; }
command -v kubectl >/dev/null || { echo "ERROR: kubectl not found"; exit 1; }

if ! command -v kind >/dev/null; then
  echo "ERROR: kind is not installed. Install it with one of:"
  echo "  brew install kind"
  echo "  curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-\$(uname)-amd64 \\"
  echo "    && chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind"
  exit 1
fi

# audit log sink
mkdir -p audit-logs data
: > audit-logs/audit.log   # apiserver appends here via the kind hostPath mount

# (re)create cluster
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "[*] Cluster '$CLUSTER_NAME' exists - deleting and recreating."
  kind delete cluster --name "$CLUSTER_NAME"
fi

echo "[*] Creating kind cluster with audit logging..."
kind create cluster --name "$CLUSTER_NAME" --config cluster/kind-config.yaml

# verify
kubectl --context "kind-$CLUSTER_NAME" get nodes
kubectl --context "kind-$CLUSTER_NAME" get ns >/dev/null
sleep 3
if [ -s audit-logs/audit.log ]; then
  echo "[OK] Audit log is live: $(wc -l < audit-logs/audit.log) events so far."
else
  echo "[WARN] audit-logs/audit.log is empty - inspect the apiserver:"
  echo "       docker exec ${CLUSTER_NAME}-control-plane crictl ps | grep apiserver"
fi

echo
echo "Next: ./attacks/run_dataset.sh"
