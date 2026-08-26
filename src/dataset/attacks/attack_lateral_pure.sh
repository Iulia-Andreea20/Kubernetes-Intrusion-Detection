#!/usr/bin/env bash
# Pure impersonation: `kubectl --as=<privileged SA>` plus ordinary list/get, nothing else.
#
# No secret reads, no can-i, no deletions, so has_impersonation is the only thing separating this
# from benign traffic. That is the point: it tests whether the feature is doing real work.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
SA=adversary-lateral2
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create sa $SA -n default >/dev/null 2>&1 || true
kubectl create clusterrolebinding rt-$SA --clusterrole=cluster-admin --serviceaccount=default:$SA >/dev/null 2>&1 || true
T=$(kubectl create token $SA -n default --duration=2h 2>/dev/null); KC=/tmp/kc-$SA
kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
kubectl config --kubeconfig="$KC" use-context c >/dev/null
KAS(){ kubectl --kubeconfig "$KC" --as="$1" "${@:2}" >/dev/null 2>&1 || true; }

N=$(grep -cE "SESSION [0-9]+ START" "$SF"); N=$((N+1)); echo "  S$N pure lateral movement (impersonation only)"
echo "SESSION $N START $(nowZ)" >> "$SF"
for r in 1 2 3 4; do
  KAS system:serviceaccount:kube-system:namespace-controller       get pods -A
  KAS system:serviceaccount:kube-system:generic-garbage-collector  get deployments -A
  KAS system:serviceaccount:kube-system:replicaset-controller      get namespaces
  KAS system:serviceaccount:kube-system:deployment-controller      get services -A
  KAS system:serviceaccount:kube-system:endpointslice-controller   get nodes
  KAS system:admin                                                  get pods -n kube-system
done
echo "SESSION $N END $(nowZ)" >> "$SF"

echo ">> cleanup..."
kubectl delete clusterrolebinding rt-$SA >/dev/null 2>&1 || true
kubectl delete sa $SA -n default >/dev/null 2>&1 || true
echo ">> done, session $N"; tail -2 "$SF"