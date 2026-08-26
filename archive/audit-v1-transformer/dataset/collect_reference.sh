#!/bin/bash
# Colectare CURATĂ (opțiunea 1: time-scoping). Marchează CLEAN_START/END în reference_dataset/window.txt.
# Benign: actori umani + platform-admin + operatorii (rulează deja în fundal, benign realist).
# Atac (DOAR API): token SA furat slab -> recon -> forbid trail (attack_realistic.sh).
# Pentru SCALĂ: rulează scriptul de mai multe ori (sesiuni); export_rich.py ia DOAR fereastra marcată.
set -uo pipefail
W=/tmp/ids_collect
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/../reference"; mkdir -p "$OUT"
K(){ kubectl --kubeconfig "$W/kubeconfig-$1" "${@:2}" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-10}"

echo "CLEAN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/window.txt"
echo ">> benign (actori umani + platform-admin; operatorii dau fundal continuu)..."
for r in $(seq 1 "$ROUNDS"); do
  K sre-oncall get pods -A; K sre-oncall get events -A; K sre-oncall get nodes; K sre-oncall get pods -n kube-system
  K devops-pipeline create deployment ap-$r --image=nginx -n default; K devops-pipeline get pods -n default
  K security-auditor get roles -A; K security-auditor get clusterroles; K security-auditor get clusterrolebindings
  K data-engineer create job dj-$r --image=busybox -n default -- echo hi; K data-engineer get jobs -n default
  K platform-admin create serviceaccount pm-$r -n default
  K platform-admin create clusterrolebinding pmb-$r --clusterrole=view --serviceaccount=default:pm-$r
  K platform-admin get secrets -n default; K platform-admin create token pm-$r -n default
  echo "   benign $r/$ROUNDS"
done

echo ">> atac realist (token SA furat  forbid trail)..."
ROUNDS="$ROUNDS" bash "$HERE/attack_realistic.sh" 2>&1 | grep -E "recon furat [0-9]+/|GATA" | tail -2
echo "CLEAN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/window.txt"

echo ">> curățenie artefacte ACESTEI sesiuni..."
for r in $(seq 1 "$ROUNDS"); do
  kubectl delete clusterrolebinding pmb-$r >/dev/null 2>&1 || true
  kubectl delete sa pm-$r -n default >/dev/null 2>&1 || true
  kubectl delete deploy ap-$r -n default >/dev/null 2>&1 || true
  kubectl delete job dj-$r -n default >/dev/null 2>&1 || true
done
echo "GATA colectare referință (fereastră curată marcată)."; cat "$OUT/window.txt"
