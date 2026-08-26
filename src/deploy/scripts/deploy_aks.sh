#!/bin/bash
# Deploy onto an AKS cluster that already exists (created through the portal, say).
# Steps: credentials -> kube-audit diagnostic setting -> service principal -> secrets -> manifests.
# For a cluster built from scratch use cluster/aks/setup_aks.sh + deploy_obs_aks.sh instead.
#
#   bash src/deploy/scripts/deploy_aks.sh
#
# Override from the environment if your names differ:
set -euo pipefail
RG="${RG:-intrusion-detection-aks_group}"
AKS="${AKS:-intrusion-detection-aks}"
SUB="${SUB:-31bb85a2-bdc2-420b-841e-13ab01c07038}"   # Azure for Students
SP_NAME="${SP_NAME:-sp-ids-la-reader}"

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$REPO/src"
K="kubectl"

az account set --subscription "$SUB"

echo ">> [1/7] kubectl credentials for $AKS"
az aks get-credentials -g "$RG" -n "$AKS" --overwrite-existing

echo ">> [2/7] finding the Log Analytics workspace"
LAW_RID="$(az aks show -g "$RG" -n "$AKS" \
  --query "addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID" -o tsv)"
if [ -z "$LAW_RID" ] || [ "$LAW_RID" = "null" ]; then
  echo "   !! Container Insights is off; enabling the monitoring add-on"
  az aks enable-addons -g "$RG" -n "$AKS" -a monitoring -o none
  LAW_RID="$(az aks show -g "$RG" -n "$AKS" \
    --query "addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID" -o tsv)"
fi
LAW_ID="$(az monitor log-analytics workspace show --ids "$LAW_RID" --query customerId -o tsv)"
echo "   workspace: $LAW_RID"
echo "   customerId (LA_WORKSPACE_ID): $LAW_ID"

echo ">> [3/7] diagnostic setting: kube-audit -> Log Analytics"
AKS_ID="$(az aks show -g "$RG" -n "$AKS" --query id -o tsv)"
az monitor diagnostic-settings create --name ids-audit -o none \
  --resource "$AKS_ID" --workspace "$LAW_RID" \
  --logs '[{"category":"kube-audit","enabled":true},{"category":"kube-audit-admin","enabled":true}]' \
  || echo "   (diagnostic setting already exists)"

echo ">> [4/7] service principal with the Log Analytics Reader role"
SP_JSON="$(az ad sp create-for-rbac -n "$SP_NAME" --role "Log Analytics Reader" --scopes "$LAW_RID" -o json)"
SP_TENANT="$(echo "$SP_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["tenant"])')"
SP_APPID="$(echo "$SP_JSON"  | python3 -c 'import json,sys;print(json.load(sys.stdin)["appId"])')"
SP_PASS="$(echo "$SP_JSON"   | python3 -c 'import json,sys;print(json.load(sys.stdin)["password"])')"

echo ">> [5/7] namespace and secrets"
$K apply -f "$SRC/deploy/k8s/00-namespace.yaml"
$K -n runtime-ids create configmap ids-azure-config \
  --from-literal=LA_WORKSPACE_ID="$LAW_ID" \
  --dry-run=client -o yaml | $K apply -f -
$K -n runtime-ids create secret generic ids-azure-sp \
  --from-literal=AZURE_TENANT_ID="$SP_TENANT" \
  --from-literal=AZURE_CLIENT_ID="$SP_APPID" \
  --from-literal=AZURE_CLIENT_SECRET="$SP_PASS" \
  --dry-run=client -o yaml | $K apply -f -

echo ">> [6/7] Grafana ConfigMaps"
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
  --from-file="$GP/dashboards/falco_container.json" \
  --dry-run=client -o yaml | $K apply -f -

echo ">> [7/8] Falco and its Prometheus exporter"
KUBECTL="$K" bash "$SRC/deploy/scripts/setup_falco.sh"

echo ">> [8/8] applying the manifests"
$K apply -f "$SRC/deploy/k8s/"
$K apply -f "$SRC/deploy/k8s/40-prometheus.yaml" \
         -f "$SRC/deploy/k8s/50-alertmanager.yaml" \
         -f "$SRC/deploy/k8s/60-mailhog.yaml" \
         -f "$SRC/deploy/k8s/70-grafana.yaml"

echo ""
echo ">> waiting for the detector"
$K -n runtime-ids rollout status deploy/ids-audit --timeout=240s || true
echo ""
$K -n runtime-ids get pods -o wide
echo ""
echo "=================================================================="
echo " Done. Port-forward the UIs from separate terminals:"
echo "   kubectl -n runtime-ids port-forward svc/grafana 3000:3000"
echo "   kubectl -n runtime-ids port-forward svc/mailhog 8025:8025"
echo " Apoi: http://localhost:3000 (admin/admin) · http://localhost:8025"
echo ""
echo " This costs money. Tear everything down with:"
echo "   az group delete -n $RG --yes --no-wait"
echo "   az ad sp delete --id $SP_APPID"
echo "=================================================================="
