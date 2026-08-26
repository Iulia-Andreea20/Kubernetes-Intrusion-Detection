#!/bin/bash
# Creează doi actori distincți pe AKS pentru colectarea unui dataset de audit etichetat:
#   alice   -> rol 'view' (read-only)        => activitate BENIGNĂ
#   mallory -> rol 'cluster-admin' (compromis) => activitate de ATAC
# Folosește CSR-uri semnate de CA-ul clusterului (mecanism standard K8s, merge pe AKS).
# Scrie kubeconfig-uri separate în WORK pentru a rula kubectl ca fiecare utilizator.
set -euo pipefail
RG="${RG:-intusion-detection-project}"
AKS="${AKS:-intrusion-detection-aks}"
WORK="${WORK:-/tmp/ids_collect}"
mkdir -p "$WORK"; cd "$WORK"

echo ">> credentiale admin (necesare pt aprobare CSR + RBAC)"
az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing -o none
CTX="$(kubectl config current-context)"
echo "   context admin: $CTX"
KA="kubectl --context $CTX"

# date de conectare la cluster (refolosite în kubeconfig-urile utilizatorilor)
SERVER="$($KA config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
$KA config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > ca.crt

make_user () {
  local U="$1" ROLE="$2"
  echo ">> [$U] generez cheie + CSR (CN=$U)"
  openssl genrsa -out "$U.key" 2048 2>/dev/null
  openssl req -new -key "$U.key" -out "$U.csr" -subj "/CN=$U/O=ids-demo" 2>/dev/null
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
  # aștept emiterea certificatului
  for i in $(seq 1 15); do
    CRT="$($KA get csr "$U" -o jsonpath='{.status.certificate}' 2>/dev/null || true)"
    [ -n "$CRT" ] && break; sleep 1
  done
  echo "$CRT" | base64 -d > "$U.crt"
  echo ">> [$U] RBAC -> $ROLE"
  $KA delete clusterrolebinding "ids-$U" >/dev/null 2>&1 || true
  $KA create clusterrolebinding "ids-$U" --clusterrole="$ROLE" --user="$U" >/dev/null
  # construiesc kubeconfig dedicat
  local KC="$WORK/kubeconfig-$U"
  kubectl --kubeconfig "$KC" config set-cluster aks --server="$SERVER" \
    --certificate-authority="$WORK/ca.crt" --embed-certs=true >/dev/null
  kubectl --kubeconfig "$KC" config set-credentials "$U" \
    --client-certificate="$WORK/$U.crt" --client-key="$WORK/$U.key" --embed-certs=true >/dev/null
  kubectl --kubeconfig "$KC" config set-context aks --cluster=aks --user="$U" >/dev/null
  kubectl --kubeconfig "$KC" config use-context aks >/dev/null
  echo "    kubeconfig: $KC"
}

make_user alice   view           # benign: monitorizare (read/list)
make_user dev     edit           # benign: developer (deploy/scale/logs/exec propriu)
make_user mallory cluster-admin  # atac: cont compromis

echo ""
echo ">> utilizatori creați:"
for u in alice dev mallory; do
  echo -n "   $u -> "; kubectl --kubeconfig "$WORK/kubeconfig-$u" auth whoami 2>/dev/null | tail -1 || echo "(ok)"
done
echo "GATA: utilizatori creați în $WORK"
