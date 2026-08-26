#!/bin/bash
# Deploy everything into a local kind cluster: both detectors and the observability stack as pods.
# Build the image first:
#   docker build -f src/deploy/images/Dockerfile.runtime -t runtime-ids:1.0 .
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$REPO/src"
CTX="kind-runtime-ids"
CLUSTER="runtime-ids"
K="kubectl --context $CTX"
cd "$SRC/deploy"

echo ">> [1/5] loading the IDS image into kind"
kind load docker-image runtime-ids:1.0 --name "$CLUSTER"

echo ">> [2/5] loading the observability images from the local Docker cache"
for img in prom/prometheus:v2.54.1 prom/alertmanager:v0.27.0 mailhog/mailhog:v1.0.1 grafana/grafana:11.1.0; do
  kind load docker-image "$img" --name "$CLUSTER" 2>/dev/null && echo "    $img" || echo "   (skipped $img, the node will pull it)"
done

echo ">> [3/5] namespace"
$K apply -f k8s/00-namespace.yaml

echo ">> [4/5] Grafana ConfigMaps"
GP="$SRC/observability/grafana"
$K -n runtime-ids create configmap grafana-datasource \
  --from-file="$GP/provisioning/datasources/datasource.yml" \
  --dry-run=client -o yaml | $K apply -f -
$K -n runtime-ids create configmap grafana-provider \
  --from-file="$GP/provisioning/dashboards/provider.yml" \
  --dry-run=client -o yaml | $K apply -f -
$K -n runtime-ids create configmap grafana-dashboards \
  --from-file="$GP/dashboards/ids_soc.json" \
  --from-file="$GP/dashboards/ids_mlops.json" \
  --dry-run=client -o yaml | $K apply -f -

echo ">> [5/5] applying manifests"
$K apply -f k8s/

echo ""
echo ">> waiting for the detector"
$K -n runtime-ids rollout status deploy/ids-audit --timeout=180s || true
echo ""
$K -n runtime-ids get pods -o wide
echo ""
echo "=================================================================="
echo " Port-forward the UIs from separate terminals:"
echo "   kubectl --context $CTX -n runtime-ids port-forward svc/grafana 3000:3000"
echo "   kubectl --context $CTX -n runtime-ids port-forward svc/mailhog 8025:8025"
echo " Then http://localhost:3000 (admin/admin) and http://localhost:8025"
echo "=================================================================="
