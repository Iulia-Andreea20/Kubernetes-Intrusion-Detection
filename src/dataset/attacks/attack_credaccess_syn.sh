#!/usr/bin/env bash
# Credential access (T1552.007, secret dumping) written in plain kubectl.
#
# This is the training half of a pair: Stratus dump-secrets is the held-out half. Deliberately
# implemented differently - our own enumeration, top-N per namespace, different volume and shape -
# because mimicking the tool byte for byte would collapse the distance the split is meant to test.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
SECNS="kube-system cert-manager argocd monitoring default"
KC=""
mkkc(){ # creeaza identitate + kubeconfig dedicat (cluster-admin, ca sa poata citi secretele)
  kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole=cluster-admin --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=2h 2>/dev/null); KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null
}
K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
cleanup(){ kubectl delete clusterrolebinding "rt-$1" >/dev/null 2>&1||true; kubectl delete sa "$1" -n default >/dev/null 2>&1||true; }

for id in adversary-creddump-1 adversary-creddump-2 adversary-creddump-3; do
  mkkc "$id"
  N=$(grep -cE "SESSION [0-9]+ START" "$SF"); N=$((N+1)); echo "  S$N CRED-ACCESS SINTETIC ($id)"
  echo "SESSION $N START $(nowZ)" >> "$SF"
  for cycle in 1 2 3; do
    # dump PROPRIU (diferit de Stratus): enumereaza apoi citeste CONTINUTUL secretelor in mai multe ns (T1552.007)
    for ns in $SECNS; do
      K get secrets -n "$ns"
      for s in $(kubectl get secrets -n "$ns" -o name 2>/dev/null | head -3 | cut -d/ -f2); do
        K get secret "$s" -n "$ns" -o yaml
      done
    done
    K get secrets -A -o yaml
  done
  echo "SESSION $N END $(nowZ)" >> "$SF"
  cleanup "$id"
done
echo ">> done, tagged credsyn (train half; Stratus dump-secrets is the held-out half)"; tail -3 "$SF"
