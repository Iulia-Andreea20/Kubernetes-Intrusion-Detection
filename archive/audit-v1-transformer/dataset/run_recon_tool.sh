#!/bin/bash
# HELD-OUT TOOL-DISJOINT (pattern rakkess/kdigger): recon de PERMISIUNI via `auth can-i` în masă
# (SelfSubjectAccessReview/RulesReview) + enumerare resurse, ca un token compromis read-only.
# TTP de recon pe care scripturile noastre de antrenare NU l-au folosit (ele atacau secrete/exec/RBAC).
# Replic pattern-ul uneltei (semnătură audit identică), nu binarul (uneltele n-au imagini fiabile).
set -uo pipefail
OUT="$(cd "$(dirname "$0")" && pwd)/reference_dataset"
kubectl create serviceaccount recon-sa -n default >/dev/null 2>&1 || true
kubectl create clusterrolebinding recon-view --clusterrole=view --serviceaccount=default:recon-sa >/dev/null 2>&1 || true
TOKEN=$(kubectl create token recon-sa -n default --duration=2h)
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
KC=/tmp/recon.kc
kubectl config --kubeconfig=$KC set-cluster a --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig=$KC set-credentials r --token="$TOKEN" >/dev/null
kubectl config --kubeconfig=$KC set-context a --cluster=a --user=r >/dev/null; kubectl config --kubeconfig=$KC use-context a >/dev/null
R(){ kubectl --kubeconfig=$KC "$@" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-6}"
# GRID-ONLY: doar SelfSubjectAccessReview în masă (pattern rakkess). Am scos `auth can-i --list`,
# `api-resources` și `get -A` deoarece (a) `--list`/api-resources se suprapun cu tooling benign și
# (b) ordinea grilei e în request body (invizibil la Metadata) -> reordonarea ar fi byte-identică.
# Held-out tool-disjoint REAL = run_recon_tool_v2.sh (enumerare prin list/get = altă regiune observabilă).
echo "RECON_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/recon_window.txt"
for r in $(seq 1 "$ROUNDS"); do
  for v in get list create delete watch update patch; do
    for res in pods secrets services deployments configmaps nodes clusterroles rolebindings serviceaccounts jobs; do
      R auth can-i "$v" "$res"             # SelfSubjectAccessReview în masă (semnătura tool-loop)
    done
  done
  echo "   recon $r/$ROUNDS"
done
echo "RECON_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/recon_window.txt"
kubectl delete clusterrolebinding recon-view >/dev/null 2>&1 || true
kubectl delete sa recon-sa -n default >/dev/null 2>&1 || true
echo "GATA recon (pattern rakkess/kdigger)."
