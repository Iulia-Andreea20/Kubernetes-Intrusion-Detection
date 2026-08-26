#!/usr/bin/env bash
# Persistence run by Stratus Red Team, a real third-party tool, under its own identity.
#
# This is the strongest kind of evidence in the set: a tactic the model has never seen, produced by
# an implementation nobody here wrote.
set -uo pipefail
BIN=/tmp/rtbin
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create sa redteam-persist -n default >/dev/null 2>&1||true
kubectl create clusterrolebinding rt-redteam-persist --clusterrole=cluster-admin --serviceaccount=default:redteam-persist >/dev/null 2>&1||true
T=$(kubectl create token redteam-persist -n default --duration=2h 2>/dev/null); KC=/tmp/kc-redteam-persist
kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
kubectl config --kubeconfig="$KC" use-context c >/dev/null

N=$(grep -cE "SESSION [0-9]+ START" "$SF"); N=$((N+1)); echo "  S$N PERSISTENCE (Stratus extern)"
KUBECONFIG=$KC "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
echo "SESSION $N START $(nowZ)" >> "$SF"
for cycle in 1 2; do
  KUBECONFIG=$KC "$BIN/stratus" detonate k8s.persistence.create-admin-clusterrole >/dev/null 2>&1 || true
  KUBECONFIG=$KC "$BIN/stratus" detonate k8s.persistence.create-token >/dev/null 2>&1 || true
  KUBECONFIG=$KC "$BIN/stratus" detonate k8s.persistence.create-client-certificate >/dev/null 2>&1 || true
  KUBECONFIG=$KC "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
done
echo "SESSION $N END $(nowZ)" >> "$SF"

echo ">> cleanup..."
kubectl delete clusterrolebinding rt-redteam-persist >/dev/null 2>&1||true
kubectl delete sa redteam-persist -n default >/dev/null 2>&1||true
echo ">> done, session $N"; tail -2 "$SF"