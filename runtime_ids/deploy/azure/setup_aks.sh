#!/bin/bash
# Provisionează AKS managed + Log Analytics pentru IDS v2.x (audit real → Log Analytics).
# RULEAZĂ DUPĂ `az login`. Default-urile reproduc EXACT clusterul folosit (vezi CLUSTER_STATE.md).
#   bash runtime_ids/deploy/azure/setup_aks.sh
# Imaginile sunt pe Docker Hub (andreeagrigore/*, digest-pinned) — PERSISTĂ peste ștergerea clusterului,
# deci NU se rebuild-uiesc aici (doar dacă schimbi codul; vezi deploy_audit_hybrid.sh / Dockerfile.*).
# Auth adapter = MANAGED IDENTITY (identitatea kubelet a AKS) — SP `create-for-rbac` e blocat pe „Azure for Students".
# La final scrie env.generated (REGISTRY gol + LA_WORKSPACE_ID) pt deploy_obs_aks.sh. Vezi RESTORE.md.
set -euo pipefail

# ---- variabile (default = config-ul REAL folosit; suprascrie cu env dacă vrei) ----
RG="${RG:-intusion-detection-project}"
LOCATION="${LOCATION:-northeurope}"
AKS="${AKS:-intrusion-detection-aks}"
LAW="${LAW:-law-ids-aks}"
NODE_SIZE="${NODE_SIZE:-Standard_DS2_v2}"   # 2 vCPU / 7GB
NODE_COUNT="${NODE_COUNT:-2}"

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$REPO"

echo ">> [1/5] resource group $RG ($LOCATION)"
az group create -n "$RG" -l "$LOCATION" -o none

echo ">> [2/5] Log Analytics workspace $LAW"
az monitor log-analytics workspace create -g "$RG" -n "$LAW" -l "$LOCATION" -o none
LAW_ID="$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query customerId -o tsv)"
LAW_RID="$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query id -o tsv)"

echo ">> [3/5] AKS $AKS ($NODE_COUNT x $NODE_SIZE)"
az aks create -g "$RG" -n "$AKS" --node-count "$NODE_COUNT" --node-vm-size "$NODE_SIZE" \
  --generate-ssh-keys -o none
az aks get-credentials -g "$RG" -n "$AKS" --overwrite-existing

echo ">> [4/5] diagnostic settings: kube-audit + kube-audit-admin → Log Analytics (CRITIC pt ingestie audit)"
AKS_ID="$(az aks show -g "$RG" -n "$AKS" --query id -o tsv)"
az monitor diagnostic-settings create --name ids-audit -o none \
  --resource "$AKS_ID" --workspace "$LAW_RID" \
  --logs '[{"category":"kube-audit","enabled":true},{"category":"kube-audit-admin","enabled":true}]'

echo ">> [5/5] rol Log Analytics Reader pt identitatea KUBELET (managed identity, fara SP)"
echo "   (SP create-for-rbac e blocat pe Azure for Students -> adapterul foloseste managed identity via IMDS)"
KID="$(az aks show -g "$RG" -n "$AKS" --query identityProfile.kubeletidentity.objectId -o tsv)"
az role assignment create --assignee-object-id "$KID" --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" --scope "$LAW_RID" -o none

# valori pt deploy_obs_aks.sh (configmap ids-azure-config). NICIUN secret SP (managed identity).
cat > runtime_ids/deploy/azure/env.generated <<EOF
REGISTRY=docker.io/andreeagrigore
LA_WORKSPACE_ID=$LAW_ID
EOF
chmod 600 runtime_ids/deploy/azure/env.generated

echo ""
echo "=================================================================="
echo " GATA provisioning. LA_WORKSPACE_ID=$LAW_ID (scris în env.generated)."
echo " URMĂTORUL PAS: bash runtime_ids/deploy/azure/deploy_obs_aks.sh   (IDS v2.x + obs + adapter)"
echo " Imaginile vin din Docker Hub (andreeagrigore/*, digest-pinned) — nu se rebuild-uiesc aici."
echo " ATENȚIE COST: șterge tot la final cu:  az group delete -n $RG --yes --no-wait"
echo "=================================================================="
