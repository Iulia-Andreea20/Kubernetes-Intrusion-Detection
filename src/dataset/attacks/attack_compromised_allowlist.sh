#!/usr/bin/env bash
# Demonstrate the hole in the trust boundary: an allowlisted kube-system identity that has been
# compromised escapes every rule that exempts the allowlist.
#
# Creates real service accounts in kube-system and acts with their own tokens rather than by
# impersonation, so the audit log keys the window on the kube-system identity itself. The tactics
# are rate-based only - nothing flagrant - so the severity rule cannot quietly cover for the gap.
#
# Destructive actions stay inside lab-victim and its decoys; the kube-system accounts are removed
# at the end.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim; nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create namespace $VNS >/dev/null 2>&1 || true
# SA in KUBE-SYSTEM (allowlistat prin prefix) + token
mkkc(){ kubectl create sa "$1" -n kube-system >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rtks-$1" --clusterrole=cluster-admin --serviceaccount=kube-system:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n kube-system --duration=2h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
SS(){ N=$(grep -cE "SESSION [0-9]+ START" "$SF"); echo $((N+1)); }
sess(){ local S; S=$(SS); echo "  S$S $1"; echo "SESSION $S START $(nowZ)" >> "$SF"; }
ends(){ echo "SESSION $(grep -cE 'SESSION [0-9]+ START' "$SF") END $(nowZ)" >> "$SF"; }
CREATED=""
NSP="default kube-system cert-manager argocd monitoring lab-victim"

run(){ local n=$1 prof=$2; local SA=compromised-ctrl-$n; local KC; KC=$(mkkc $SA); CREATED="$CREATED $SA"
  K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  # pre-populeaza decoys pt delete-spree
  for i in $(seq 1 40); do kubectl create configmap kk-$SA-$i --from-literal=k=v -n $VNS >/dev/null 2>&1; done
  sess "COMPROMISED kube-system #$n ($prof)"
  case $prof in
    delete)   for i in $(seq 1 40); do K delete configmap kk-$SA-$i -n $VNS; done;;                       # destruct gated -> exempt
    recon)    for r in $(seq 1 45); do K auth can-i create pods -n $VNS; K auth can-i '*' '*'; done;;       # recon gated -> exempt
    workload) for i in $(seq 1 8); do K create deployment miner-$SA-$i --image=nginx -n $VNS; done; for i in $(seq 1 8); do K delete deployment miner-$SA-$i -n $VNS; done;;  # hijack gated -> exempt
    persist)  for i in $(seq 1 6); do K create serviceaccount tok-$SA-$i -n $VNS; K create token tok-$SA-$i -n $VNS; done;;  # persist gated -> exempt
    delrec)   for i in $(seq 1 25); do K delete configmap kk-$SA-$i -n $VNS; done; for r in $(seq 1 25); do K auth can-i list secrets -n $VNS; done;;
    tokflood) for i in $(seq 1 12); do K create serviceaccount tk-$SA-$i -n $VNS; K create token tk-$SA-$i -n $VNS; done;;
  esac
  ends
}

run 1 delete
run 2 recon
run 3 workload
run 4 persist
run 5 delrec
run 6 tokflood

echo ">> cleanup..."
kubectl get clusterrolebinding -o name 2>/dev/null | grep -E "rtks-compromised-ctrl" | xargs -r kubectl delete >/dev/null 2>&1||true
for s in $CREATED; do kubectl delete sa $s -n kube-system >/dev/null 2>&1||true; done
kubectl delete namespace $VNS >/dev/null 2>&1||true
echo ">> done. sessions so far: $(grep -cE 'SESSION [0-9]+ START' "$SF")"
