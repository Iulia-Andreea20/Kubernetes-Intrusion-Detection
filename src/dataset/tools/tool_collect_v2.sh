#!/usr/bin/env bash
# Run the real attack tools - Stratus and rakkess - under dedicated identities and record their
# windows as sessions. Peirates stays held out and is run separately at evaluation time.
# Needs /tmp/rtbin/stratus and the krew access-matrix plugin.
set -uo pipefail
BIN=/tmp/rtbin
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"
SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
export PATH="$HOME/.krew/bin:$PATH"
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
mk(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole="$2" --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=3h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
N=$(grep -cE "SESSION [0-9]+ START" "$SF" 2>/dev/null || echo 0); N=${N:-0}
echo ">> existing sessions: $N"

# Stratus: escalation (train), 3 sessions = 3 episodes
KCA=$(mk redteam-stratus cluster-admin)
KUBECONFIG=$KCA "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
for k in 1 2 3; do
  N=$((N+1)); echo "SESSION $N START $(nowZ)" >> "$SF"
  KUBECONFIG=$KCA "$BIN/stratus" detonate k8s.credential-access.dump-secrets >/dev/null 2>&1 || true
  KUBECONFIG=$KCA "$BIN/stratus" detonate k8s.privilege-escalation.privileged-pod >/dev/null 2>&1 || true
  KUBECONFIG=$KCA "$BIN/stratus" detonate k8s.credential-access.steal-serviceaccount-token >/dev/null 2>&1 || true
  KUBECONFIG=$KCA "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
  echo "SESSION $N END $(nowZ)" >> "$SF"; echo "  stratus episod $k -> sesiune $N"
done

# rakkess: can-i recon, in training, 3 sessions
KCR=$(mk redteam-rakkess view)
for k in 1 2 3; do
  N=$((N+1)); echo "SESSION $N START $(nowZ)" >> "$SF"
  for i in $(seq 1 4); do
    KUBECONFIG=$KCR kubectl access-matrix >/dev/null 2>&1 || true
    KUBECONFIG=$KCR kubectl access-matrix -n default >/dev/null 2>&1 || true
    KUBECONFIG=$KCR kubectl access-matrix -n kube-system >/dev/null 2>&1 || true
  done
  echo "SESSION $N END $(nowZ)" >> "$SF"; echo "  rakkess episod $k -> sesiune $N"
done
echo ">> done: $N sessions total, Stratus and rakkess in train"