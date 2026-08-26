#!/bin/bash
# Deploy the detector, the Log Analytics adapter and the observability stack onto managed AKS.
set -uo pipefail
# An active Python venv on PATH breaks az and kubectl, so drop it for the duration of the script.
if [ -n "${VIRTUAL_ENV:-}" ]; then
  PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v "^${VIRTUAL_ENV}/bin$" | paste -sd: -)"
  unset VIRTUAL_ENV PYTHONHOME; export PATH PYTHONNOUSERSITE=1
fi
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$REPO/src"; K="kubectl"
GP="$SRC/observability/grafana"
ENVFILE="$SRC/cluster/aks/env.generated"

echo ">> [1/5] namespace"
$K apply -f "$SRC/deploy/k8s/00-namespace.yaml"

echo ">> [2/5] Grafana ConfigMaps (datasource + dashboards)"
$K -n monitoring create configmap grafana-datasource \
  --from-file="$GP/provisioning/datasources/datasource.yml" --dry-run=client -o yaml | $K apply -f -
$K -n monitoring create configmap grafana-provider \
  --from-file="$GP/provisioning/dashboards/provider.yml" --dry-run=client -o yaml | $K apply -f -
$K -n monitoring create configmap grafana-dashboards \
  --from-file="$GP/dashboards/ids_soc.json" --from-file="$GP/dashboards/ids_mlops.json" \
  --dry-run=client -o yaml | $K apply -f -

echo ">> [3/5] detector + flow + observability"
$K apply -f "$SRC/deploy/k8s/11-audit-xgb.yaml" -f "$SRC/deploy/k8s/20-flow.yaml"
$K apply -f "$SRC/deploy/k8s/40-prometheus.yaml" \
         -f "$SRC/deploy/k8s/50-alertmanager.yaml" \
         -f "$SRC/deploy/k8s/60-mailhog.yaml" \
         -f "$SRC/deploy/k8s/70-grafana.yaml"
# Falco is not deployed here. On the AKS node kernel (5.15-azure) the engine captures nothing:
# modern_ebpf is rejected by the verifier and kmod loads but never emits. setup_falco.sh is kept
# for a node where it does work.

echo ">> [4/5] live feed: Log Analytics adapter (needs env.generated from setup_aks.sh)"
if [ -f "$ENVFILE" ]; then
  set -a; . "$ENVFILE"; set +a
  $K -n runtime-ids create configmap ids-azure-config \
    --from-literal=LA_WORKSPACE_ID="$LA_WORKSPACE_ID" --dry-run=client -o yaml | $K apply -f -
  # On a student subscription there is usually no service principal, so the adapter falls back to
  # the kubelet managed identity. Only create the secret when credentials are actually present.
  if [ -n "${AZURE_CLIENT_ID:-}" ]; then
    $K -n runtime-ids create secret generic ids-azure-sp \
      --from-literal=AZURE_TENANT_ID="${AZURE_TENANT_ID:-}" \
      --from-literal=AZURE_CLIENT_ID="${AZURE_CLIENT_ID:-}" \
      --from-literal=AZURE_CLIENT_SECRET="${AZURE_CLIENT_SECRET:-}" --dry-run=client -o yaml | $K apply -f -
    echo "   adapter auth: service principal"
  else
    echo "   adapter auth: kubelet managed identity"
  fi
  $K apply -f "$SRC/deploy/k8s/30-adapter.yaml"
else
  echo "   (no env.generated - skipping the adapter. Run setup_aks.sh first, or POST /predict/raw directly.)"
fi

echo ">> [5/5] waiting for the detector..."
$K -n runtime-ids rollout status deploy/ids-audit-xgb --timeout=300s || true
echo ""
$K -n runtime-ids get pods -o wide
echo ""
echo ">> opening Grafana + MailHog"
pkill -f "port-forward.*svc/grafana 3000:3000" 2>/dev/null || true
pkill -f "port-forward.*svc/mailhog 8025:8025" 2>/dev/null || true
$K -n monitoring rollout status deploy/grafana --timeout=90s >/dev/null 2>&1 || true
nohup $K -n monitoring port-forward svc/grafana 3000:3000 >/tmp/pf-grafana.log 2>&1 &
nohup $K -n monitoring port-forward svc/mailhog 8025:8025 >/tmp/pf-mailhog.log 2>&1 &
sleep 4
if command -v open >/dev/null 2>&1; then open http://localhost:3000 2>/dev/null || true; open http://localhost:8025 2>/dev/null || true; fi
echo "   Grafana  http://localhost:3000 (admin/admin)"
echo "   MailHog  http://localhost:8025"
echo "   stop the tunnels: pkill -f 'port-forward.*svc/(grafana 3000|mailhog 8025)'"
