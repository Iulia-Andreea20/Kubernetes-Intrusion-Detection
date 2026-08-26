#!/usr/bin/env bash
# Collect more held-out episodes so the Wilson lower bound is not dominated by tiny N.
# Five Stratus escalation runs (tool-disjoint) plus three fresh identities each for the classes
# that have no external tool. Only touches lab-victim and decoy.
set -uo pipefail
BIN=/tmp/rtbin
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim; nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create namespace $VNS >/dev/null 2>&1 || true
kubectl create clusterrole pod-reader --verb=get,list --resource=pods >/dev/null 2>&1||true
mkkc(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole="${2:-cluster-admin}" --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=3h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
SS(){ N=$(grep -cE "SESSION [0-9]+ START" "$SF"); echo $((N+1)); }
secname(){ kubectl get secrets -n $1 -o name 2>/dev/null | head -1 | cut -d/ -f2; }
CREATED=""
sess(){ local lbl=$1; local S; S=$(SS); echo "  S$S $lbl"; echo "SESSION $S START $(nowZ)" >> "$SF"; }
ends(){ echo "SESSION $(grep -cE 'SESSION [0-9]+ START' "$SF") END $(nowZ)" >> "$SF"; }

# Stratus escalation x5 (tool-disjoint)
KCA=$(mkkc redteam-stratus cluster-admin)
KUBECONFIG=$KCA "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
for k in 1 2 3 4 5; do
  sess "STRATUS-esc #$k (tool-disjunct)"
  KUBECONFIG=$KCA "$BIN/stratus" detonate k8s.credential-access.dump-secrets >/dev/null 2>&1 || true
  KUBECONFIG=$KCA "$BIN/stratus" detonate k8s.privilege-escalation.privileged-pod >/dev/null 2>&1 || true
  KUBECONFIG=$KCA "$BIN/stratus" detonate k8s.credential-access.steal-serviceaccount-token >/dev/null 2>&1 || true
  KUBECONFIG=$KCA "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
  ends
done

# lowslow, three new identities
NSP="default kube-system cert-manager argocd monitoring"
for n in 2 3 4; do
  SA=adversary-stealth-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  sn=$(secname kube-system)
  sess "LOWSLOW #$n (diluat)"
  for r in $(seq 1 7); do
    i=0; for ns in $NSP $NSP $NSP; do i=$((i+1)); [ $i -gt 16 ] && break
      case $((i%4)) in 0) K get serviceaccount default -n "$ns";; 1) K get configmap kube-root-ca.crt -n "$ns";; 2) K get namespace "$ns";; 3) K version;; esac; done
    case $((r%3)) in 0) [ -n "$sn" ] && K get secret "$sn" -n kube-system;; 1) K create clusterrolebinding sl-$SA-$r --clusterrole=cluster-admin --serviceaccount=default:$SA;; 2) K get nodes;; esac
  done
  ends
done

# lateral movement x3
SAS="system:serviceaccount:kube-system:namespace-controller system:serviceaccount:kube-system:generic-garbage-collector system:serviceaccount:kube-system:replicaset-controller system:admin system:serviceaccount:cert-manager:cert-manager"
for n in 8 9 10; do
  SA=adversary-lat-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; KAS(){ kubectl --kubeconfig "$KC" --as="$1" "${@:2}" >/dev/null 2>&1||true; }
  sess "lateral #$n"
  for r in 1 2 3 4; do for as in $SAS; do KAS "$as" get pods -A; KAS "$as" get namespaces; done; done
  ends
done

# impact (variat) x3
for n in 11 12 13; do
  SA=adversary-impv-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  for i in $(seq 1 16); do kubectl create configmap dz-$SA-$i --from-literal=k=v -n $VNS >/dev/null 2>&1; done
  sess "IMPACT #$n (variat)"
  case $((n%3)) in
    2) for i in $(seq 1 16); do K delete configmap dz-$SA-$i -n $VNS; done;;                                  # burst
    0) K create deployment m-$SA --image=nginx --replicas=7 -n $VNS; for i in $(seq 1 10); do K delete configmap dz-$SA-$i -n $VNS; done; K delete deployment m-$SA -n $VNS;;  # miner+delete
    1) for i in $(seq 1 12); do K delete configmap dz-$SA-$i -n $VNS; K get pods -n $VNS; done;;               # interleaved
  esac
  ends
done

# evasion (variat) x3
for n in 11 12 13; do
  SA=adversary-evav-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  for i in $(seq 1 6); do printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: nz-%s-%s, namespace: %s}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' "$SA" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; done
  sess "EVASION #$n (variat)"
  K delete events --all -n $VNS
  case $((n%3)) in
    2) for i in $(seq 1 6); do K delete networkpolicy nz-$SA-$i -n $VNS; done; K create clusterrolebinding ez-$SA --clusterrole=cluster-admin --serviceaccount=$VNS:default; K delete clusterrolebinding ez-$SA;;
    0) for i in 1 2 3; do K create rolebinding rz-$SA-$i --clusterrole=admin --serviceaccount=$VNS:default -n $VNS; K delete rolebinding rz-$SA-$i -n $VNS; done; for i in $(seq 1 6); do K delete networkpolicy nz-$SA-$i -n $VNS; done;;
    1) for i in $(seq 1 6); do K delete networkpolicy nz-$SA-$i -n $VNS; K get events -n $VNS; done;;
  esac
  ends
done

echo ">> cleanup..."
kubectl get clusterrolebinding -o name 2>/dev/null | grep -E "rt-adversary|rt-redteam-stratus|sl-adversary|ez-adversary" | xargs -r kubectl delete >/dev/null 2>&1||true
for s in $CREATED redteam-stratus; do kubectl delete sa $s -n default >/dev/null 2>&1||true; done
kubectl delete clusterrole pod-reader >/dev/null 2>&1||true
kubectl delete namespace $VNS >/dev/null 2>&1||true
echo ">> done. sessions so far: $(grep -cE 'SESSION [0-9]+ START' "$SF")"