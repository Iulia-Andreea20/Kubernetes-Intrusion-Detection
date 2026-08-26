#!/usr/bin/env bash
# Regenerates the impact class with six genuinely different behaviour profiles.
#
# The previous version ran one deterministic deletion loop, so every run produced the same n_delete
# ramp and the held-out episodes were near-clones of the training ones - which made recall look far
# better than it was. The profiles here differ in volume, interleaving, create-churn and breadth,
# and the split is on behaviour: burst / multi-type / miner train, the other three are held out.
#
# Only touches the scratch namespaces lab-victim and decoy.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create namespace $VNS >/dev/null 2>&1 || true
mkkc(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole=cluster-admin --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=3h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
mkcm(){ for i in $(seq 1 $2); do kubectl create configmap $1-cm-$i --from-literal=k=v -n $VNS >/dev/null 2>&1; done; }
mksec(){ for i in $(seq 1 $2); do kubectl create secret generic $1-sec-$i --from-literal=p=x -n $VNS >/dev/null 2>&1; done; }
mkdep(){ for i in $(seq 1 $2); do kubectl create deployment $1-dep-$i --image=nginx -n $VNS >/dev/null 2>&1; done; }
SS(){ N=$(grep -cE "SESSION [0-9]+ START" "$SF"); echo $((N+1)); }
CREATED=""

run_profile(){  # $1=identitate $2=eticheta $3=functia-de-actiuni
  local SA=$1 KC; KC=$(mkkc $SA); CREATED="$CREATED $SA"
  K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
  local S; S=$(SS); echo "  S$S IMPACT/$2 ($SA)"; echo "SESSION $S START $(nowZ)" >> "$SF"
  $3 "$SA"
  echo "SESSION $S END $(nowZ)" >> "$SF"
}

# TRAIN profiles
p_burst1(){ mkcm $1 24; for i in $(seq 1 24); do K delete configmap $1-cm-$i -n $VNS; done; }                    # pur burst, 1 tip, volum mediu
p_multitype(){ mkcm $1 6; mksec $1 6; mkdep $1 5
  for i in 1 2 3 4 5; do K delete configmap $1-cm-$i -n $VNS; K delete secret $1-sec-$i -n $VNS; K delete deployment $1-dep-$i -n $VNS; K delete service nonexist-$i -n $VNS; done; }  # multi-tip, breadth mare
p_miner(){ K create deployment $1-miner --image=nginx --replicas=8 -n $VNS; K create deployment $1-pool --image=nginx --replicas=5 -n $VNS; mkdep $1 6
  for i in 1 2 3 4 5 6; do K delete deployment $1-dep-$i -n $VNS; done; K delete deployment $1-miner $1-pool -n $VNS; }  # miner (create fan-out) + delete

# HELD-OUT profiles (comportamental DIFERITE)
p_interleaved(){ mkcm $1 8   # slow deletion interleaved with reads: low n_delete per window, high verb variety
  for i in 1 2 3 4 5 6 7 8; do K delete configmap $1-cm-$i -n $VNS; K get pods -n $VNS; K get configmaps -n $VNS; K get services -n $VNS; K get deployments -n $VNS; done; }
p_churn(){ for i in $(seq 1 12); do K create configmap $1-ch-$i --from-literal=k=v -n $VNS; K delete configmap $1-ch-$i -n $VNS; K create secret generic $1-cs-$i --from-literal=p=x -n $VNS; K delete secret $1-cs-$i -n $VNS; done; }  # create-delete churn -> n_create≈n_delete
p_nuke(){ mkcm $1 20; mksec $1 16                                                                                # VOLUM mare, burst rapid (mai mult decat train)
  for i in $(seq 1 20); do K delete configmap $1-cm-$i -n $VNS; done; for i in $(seq 1 16); do K delete secret $1-sec-$i -n $VNS; done; }

run_profile adversary-impv-1 burst1     p_burst1
run_profile adversary-impv-2 multitype  p_multitype
run_profile adversary-impv-3 miner      p_miner
run_profile adversary-impv-4 interleaved p_interleaved
run_profile adversary-impv-5 churn      p_churn
run_profile adversary-impv-6 nuke       p_nuke

echo ">> cleanup..."
for s in $CREATED; do kubectl delete clusterrolebinding rt-$s >/dev/null 2>&1||true; kubectl delete sa $s -n default >/dev/null 2>&1||true; done
kubectl delete namespace $VNS >/dev/null 2>&1 || true
echo ">> done. new sessions:"; tail -6 "$SF"