#!/bin/bash
# Create the actor population: six benign identities and two attackers, each with its own client
# certificate and RBAC binding, plus two token-based service accounts further down.
#
# The label comes from the name - anything adversary-* is an attack - so the naming scheme is not
# cosmetic, export_v2.py keys off it.
set -euo pipefail
RG="${RG:-intusion-detection-project}"
AKS="${AKS:-intrusion-detection-aks}"
WORK="${WORK:-/tmp/ids_collect}"
mkdir -p "$WORK"; cd "$WORK"

# roster: "name:clusterrole"
ACTORS=(
  # benign
  "sre-oncall:view"
  "devops-pipeline:edit"
  "platform-engineer:edit"
  "security-auditor:view"
  "ci-deployer:edit"
  "platform-admin:cluster-admin"
  # attackers
  "adversary-external:cluster-admin"
  "adversary-insider:edit"
)

echo ">> admin credentials"
az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing -o none
CTX="$(kubectl config current-context)"; KA="kubectl --context $CTX"
SERVER="$($KA config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
$KA config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt

make_user () {
  local U="$1" ROLE="$2"
  openssl genrsa -out "$U.key" 2048 2>/dev/null
  openssl req -new -key "$U.key" -out "$U.csr" -subj "/CN=$U/O=ids-org" 2>/dev/null
  $KA delete csr "$U" >/dev/null 2>&1 || true
  cat <<EOF | $KA apply -f - >/dev/null
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: { name: $U }
spec:
  request: $(base64 < "$U.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages: ["client auth"]
  expirationSeconds: 86400
EOF
  $KA certificate approve "$U" >/dev/null
  local CRT=""
  for i in $(seq 1 15); do
    CRT="$($KA get csr "$U" -o jsonpath='{.status.certificate}' 2>/dev/null || true)"
    [ -n "$CRT" ] && break; sleep 1
  done
  echo "$CRT" | base64 -d > "$U.crt"
  $KA delete clusterrolebinding "ids-$U" >/dev/null 2>&1 || true
  $KA create clusterrolebinding "ids-$U" --clusterrole="$ROLE" --user="$U" >/dev/null
  local KC="$WORK/kubeconfig-$U"
  kubectl --kubeconfig "$KC" config set-cluster aks --server="$SERVER" \
    --certificate-authority="$WORK/ca.crt" --embed-certs=true >/dev/null
  kubectl --kubeconfig "$KC" config set-credentials "$U" \
    --client-certificate="$WORK/$U.crt" --client-key="$WORK/$U.key" --embed-certs=true >/dev/null
  kubectl --kubeconfig "$KC" config set-context aks --cluster=aks --user="$U" >/dev/null
  kubectl --kubeconfig "$KC" config use-context aks >/dev/null
  echo "    $U ($ROLE)"
}

for a in "${ACTORS[@]}"; do make_user "${a%%:*}" "${a##*:}"; done

# Token-based service accounts, created before any session starts so their own setup traffic falls
# outside the measured spans. compliance-scanner-sa exists to stop the model cheating: it issues
# can-i at high volume and is benign, so a service account doing permission checks cannot by itself
# mean attack.
$KA create serviceaccount recon-sa -n default >/dev/null 2>&1 || true
$KA create clusterrolebinding recon-view --clusterrole=view --serviceaccount=default:recon-sa >/dev/null 2>&1 || true
$KA create serviceaccount compliance-scanner-sa -n default >/dev/null 2>&1 || true
$KA create clusterrolebinding compliance-scanner-view --clusterrole=view --serviceaccount=default:compliance-scanner-sa >/dev/null 2>&1 || true
echo "    service accounts: recon-sa (attack) + compliance-scanner-sa (benign, high volume)"
echo "done: ${#ACTORS[@]} certificate actors + 2 service accounts in $WORK"
