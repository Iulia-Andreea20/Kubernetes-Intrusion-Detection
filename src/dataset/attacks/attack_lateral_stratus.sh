#!/usr/bin/env bash
# Lateral movement via token reuse, run by Stratus.
#
# Token reuse is the only lateral sub-case an external tool covers - no public tool does the
# impersonation variant - so this is the tool-disjoint half of the lateral result.
# Modules: steal-serviceaccount-token and create-token (TokenRequest abuse).
set -uo pipefail
BIN=/tmp/rtbin
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create sa redteam-lat-ext -n default >/dev/null 2>&1||true
kubectl create clusterrolebinding rt-redteam-lat-ext --clusterrole=cluster-admin --serviceaccount=default:redteam-lat-ext >/dev/null 2>&1||true
T=$(kubectl create token redteam-lat-ext -n default --duration=2h 2>/dev/null); KC=/tmp/kc-redteam-lat-ext
kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
kubectl config --kubeconfig="$KC" use-context c >/dev/null
N=$(grep -cE "SESSION [0-9]+ START" "$SF"); N=$((N+1)); echo "  S$N LATERAL-EXTERN (Stratus token-reuse)"
KUBECONFIG=$KC "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
echo "SESSION $N START $(nowZ)" >> "$SF"
for cycle in 1 2 3; do
  KUBECONFIG=$KC "$BIN/stratus" detonate k8s.credential-access.steal-serviceaccount-token >/dev/null 2>&1 || true
  KUBECONFIG=$KC "$BIN/stratus" detonate k8s.persistence.create-token >/dev/null 2>&1 || true
  KUBECONFIG=$KC "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
done
echo "SESSION $N END $(nowZ)" >> "$SF"
kubectl delete clusterrolebinding rt-redteam-lat-ext >/dev/null 2>&1||true
kubectl delete sa redteam-lat-ext -n default >/dev/null 2>&1||true
echo ">> done, session $N"; tail -2 "$SF"
