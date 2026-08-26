#!/bin/bash
# Provision the AKS cluster and the Log Analytics workspace the detector reads from.
# Run after `az login`. The defaults recreate the exact cluster described in CLUSTER_STATE.md.
#
# Images live on Docker Hub and survive deleting the cluster, so nothing is rebuilt here.
# The adapter authenticates with the kubelet managed identity, because `az ad sp create-for-rbac`
# is blocked on an Azure for Students subscription.
#
# Writes env.generated with the new workspace id for deploy_obs_aks.sh to pick up.
set -euo pipefail

# az crashes with a circular import if the project venv is on PATH, so drop it for this script.
if [ -n "${VIRTUAL_ENV:-}" ]; then
  PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v "^${VIRTUAL_ENV}/bin$" | paste -sd: -)"
  unset VIRTUAL_ENV PYTHONHOME; export PATH PYTHONNOUSERSITE=1
fi

# Overridable from the environment; the defaults are the cluster the thesis used.
RG="${RG:-intusion-detection-project}"
LOCATION="${LOCATION:-northeurope}"
AKS="${AKS:-intrusion-detection-aks}"
LAW="${LAW:-law-ids-aks}"
NODE_SIZE="${NODE_SIZE:-Standard_DS2_v2}"   # 2 vCPU / 7 GB
NODE_COUNT="${NODE_COUNT:-2}"

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$REPO"

echo ">> [1/5] resource group $RG ($LOCATION)"
az group create -n "$RG" -l "$LOCATION" -o none

echo ">> [2/5] Log Analytics workspace $LAW"
# Created through generic ARM rather than `az monitor log-analytics workspace create`, which is
# broken upstream in azure-cli 2.87 (msrest circular import, reproducible in the official image).
az resource create -g "$RG" -n "$LAW" --resource-type Microsoft.OperationalInsights/workspaces \
  --location "$LOCATION" --properties '{"sku":{"name":"PerGB2018"},"retentionInDays":30}' -o none
LAW_ID="$(az resource show -g "$RG" -n "$LAW" --resource-type Microsoft.OperationalInsights/workspaces --query properties.customerId -o tsv)"
LAW_RID="$(az resource show -g "$RG" -n "$LAW" --resource-type Microsoft.OperationalInsights/workspaces --query id -o tsv)"

echo ">> [3/5] AKS $AKS ($NODE_COUNT x $NODE_SIZE)"
az aks create -g "$RG" -n "$AKS" --node-count "$NODE_COUNT" --node-vm-size "$NODE_SIZE" \
  --generate-ssh-keys -o none
az aks get-credentials -g "$RG" -n "$AKS" --overwrite-existing

echo ">> [4/5] diagnostic settings: kube-audit + kube-audit-admin -> Log Analytics"
# Without this the audit stream never reaches the workspace and the whole system sees nothing.
AKS_ID="$(az aks show -g "$RG" -n "$AKS" --query id -o tsv)"
# Same broken SDK path as above, so this goes through `az rest` too.
az rest --method put \
  --url "https://management.azure.com${AKS_ID}/providers/Microsoft.Insights/diagnosticSettings/ids-audit?api-version=2021-05-01-preview" \
  --body "{\"properties\":{\"workspaceId\":\"${LAW_RID}\",\"logs\":[{\"category\":\"kube-audit\",\"enabled\":true},{\"category\":\"kube-audit-admin\",\"enabled\":true}]}}" -o none

echo ">> [5/5] Log Analytics Reader role for the kubelet identity"
KID="$(az aks show -g "$RG" -n "$AKS" --query identityProfile.kubeletidentity.objectId -o tsv)"
az role assignment create --assignee-object-id "$KID" --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" --scope "$LAW_RID" -o none

# Consumed by deploy_obs_aks.sh. No service principal secret: managed identity only.
cat > src/cluster/aks/env.generated <<EOF
REGISTRY=docker.io/andreeagrigore
LA_WORKSPACE_ID=$LAW_ID
EOF
chmod 600 src/cluster/aks/env.generated

echo ""
echo "=================================================================="
echo " Provisioned. LA_WORKSPACE_ID=$LAW_ID (written to env.generated)."
echo " Next: bash src/deploy/scripts/deploy_obs_aks.sh"
echo " This costs money. Tear it down with: az group delete -n $RG --yes --no-wait"
echo "=================================================================="
