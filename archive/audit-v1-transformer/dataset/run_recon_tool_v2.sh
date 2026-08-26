#!/bin/bash
# HELD-OUT TOOL-DISJOINT (v2) — enumerare prin LIST/GET REAL (NU grilă can-i), ca un token compromis cu
# drepturi mici. Ocupă o REGIUNE OBSERVABILĂ DIFERITĂ de reconul din train (run_recon_tool.sh = grilă can-i):
#   - n_distinct_resource MARE (atinge multe feluri de resurse via list/get real)
#   - forbid_ratio NENUL (drepturi mici -> multe 403 pe resursele interzise)
#   - selfsubject* doar dintr-un SINGUR `auth can-i --list` pe rundă (rules-review) -> burst_max ~1
# Identitate DIFERITĂ (recon-v2-sa) ca să nu re-măsoare un leak de identitate.
# NOTĂ ONESTĂ: ordinea pură a unei grile can-i e în request body (invizibil la Metadata) -> "disjuncție de
# secvență" e fără sens; facem v2 disjunct în REGIUNEA DE FEATURE observabilă, și o spunem explicit.
set -uo pipefail
OUT="$(cd "$(dirname "$0")" && pwd)/reference_dataset"
kubectl create serviceaccount recon-v2-sa -n default >/dev/null 2>&1 || true
kubectl create role rv2-podget --verb=get,list --resource=pods -n default >/dev/null 2>&1 || true
kubectl create rolebinding rv2-rb --role=rv2-podget --serviceaccount=default:recon-v2-sa -n default >/dev/null 2>&1 || true
TOKEN=$(kubectl create token recon-v2-sa -n default --duration=2h)
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
KC=/tmp/recon_v2.kc
kubectl config --kubeconfig=$KC set-cluster a --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig=$KC set-credentials u --token="$TOKEN" >/dev/null
kubectl config --kubeconfig=$KC set-context a --cluster=a --user=u >/dev/null; kubectl config --kubeconfig=$KC use-context a >/dev/null
R(){ kubectl --kubeconfig=$KC "$@" >/dev/null 2>&1 || true; }
NS=(default kube-system kube-public kube-node-lease)
KIND=(pods secrets services deployments configmaps endpoints serviceaccounts roles rolebindings clusterroles clusterrolebindings jobs cronjobs daemonsets statefulsets ingresses networkpolicies persistentvolumeclaims events replicasets)
ROUNDS="${ROUNDS:-5}"
echo "RECON_V2_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/recon_v2_window.txt"
for r in $(seq 1 "$ROUNDS"); do
  R auth can-i --list                      # UN SINGUR rules-review pe rundă (selfsubjectrulesreviews) -> burst~1
  for ns in "${NS[@]}"; do
    for k in "${KIND[@]}"; do
      R get "$k" -n "$ns"                   # enumerare LIST/GET REALĂ -> breadth mare + forbid (drepturi mici)
    done
  done
  R get nodes; R get namespaces; R get persistentvolumes   # cluster-scoped (forbid)
  echo "   recon-v2 $r/$ROUNDS"
done
echo "RECON_V2_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/recon_v2_window.txt"
kubectl delete rolebinding rv2-rb -n default >/dev/null 2>&1 || true
kubectl delete role rv2-podget -n default >/dev/null 2>&1 || true
kubectl delete serviceaccount recon-v2-sa -n default >/dev/null 2>&1 || true
echo "GATA recon-v2 (held-out tool-disjoint: enumerare list/get reală)."
