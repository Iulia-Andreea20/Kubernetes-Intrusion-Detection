#!/usr/bin/env bash
# Bring every held-out category up to at least ten distinct episodes, so the Wilson lower bound is
# not crushed by tiny N - and do it with real behavioural variation rather than repeated detonations,
# which would inflate N without adding information.
#
#   Stratus escalation x5, rotating modules            tool-disjoint, strongest evidence
#   Stratus persistence x9, three distinct modules     tool-disjoint, new tactic
#   Stratus lateral token x5, one technique            tool-disjoint, limited variety
#   lowslow / lateral / impact / evasion / escv        identity-disjoint, synthetic
#
# Destructive actions stay inside lab-victim and its decoys.
set -uo pipefail
BIN=/tmp/rtbin
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim; nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
SECNS="kube-system cert-manager argocd monitoring"
kubectl create namespace $VNS >/dev/null 2>&1 || true
kubectl create clusterrole pod-reader --verb=get,list --resource=pods >/dev/null 2>&1||true
mkkc(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole="${2:-cluster-admin}" --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=4h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
SS(){ N=$(grep -cE "SESSION [0-9]+ START" "$SF"); echo $((N+1)); }
secname(){ kubectl get secrets -n $1 -o name 2>/dev/null | head -1 | cut -d/ -f2; }
CREATED=""
sess(){ local lbl=$1; local S; S=$(SS); echo "  S$S $lbl"; echo "SESSION $S START $(nowZ)" >> "$SF"; }
ends(){ echo "SESSION $(grep -cE 'SESSION [0-9]+ START' "$SF") END $(nowZ)" >> "$SF"; }

# Stratus ESCALADARE x5 (module ROTITE) -> 13
KCA=$(mkkc redteam-stratus cluster-admin)
KUBECONFIG=$KCA "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
em1="k8s.privilege-escalation.privileged-pod k8s.credential-access.dump-secrets"
em2="k8s.privilege-escalation.hostpath-volume k8s.credential-access.steal-serviceaccount-token"
em3="k8s.privilege-escalation.nodes-proxy k8s.credential-access.dump-secrets"
em4="k8s.credential-access.steal-serviceaccount-token k8s.privilege-escalation.privileged-pod"
em5="k8s.privilege-escalation.hostpath-volume k8s.privilege-escalation.nodes-proxy k8s.credential-access.dump-secrets"
k=1
for mods in "$em1" "$em2" "$em3" "$em4" "$em5"; do
  sess "stratus-esc #$k"
  for m in $mods; do KUBECONFIG=$KCA "$BIN/stratus" detonate $m >/dev/null 2>&1 || true; done
  KUBECONFIG=$KCA "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
  ends; k=$((k+1))
done

# Stratus PERSISTENCE x9 (3 module DISTINCTE x3) -> 10
KCP=$(mkkc redteam-persist cluster-admin)
KUBECONFIG=$KCP "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
pmods="k8s.persistence.create-admin-clusterrole k8s.persistence.create-client-certificate k8s.persistence.create-token"
n=1
for round in 1 2 3; do for m in $pmods; do
  sess "STRATUS-persist #$n ($m)"
  KUBECONFIG=$KCP "$BIN/stratus" detonate $m >/dev/null 2>&1 || true
  KUBECONFIG=$KCP "$BIN/stratus" cleanup $m >/dev/null 2>&1 || true
  ends; n=$((n+1))
done; done

# Stratus LATERALEXT x5 (steal-token + create-token) -> 6
KCL=$(mkkc redteam-lat-ext cluster-admin)
KUBECONFIG=$KCL "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
for j in 1 2 3 4 5; do
  sess "STRATUS-lateral-token #$j (token-reuse)"
  KUBECONFIG=$KCL "$BIN/stratus" detonate k8s.credential-access.steal-serviceaccount-token >/dev/null 2>&1 || true
  KUBECONFIG=$KCL "$BIN/stratus" detonate k8s.persistence.create-token >/dev/null 2>&1 || true
  [ $((j%2)) -eq 0 ] && KUBECONFIG=$KCL "$BIN/stratus" detonate k8s.credential-access.dump-secrets >/dev/null 2>&1 || true
  KUBECONFIG=$KCL "$BIN/stratus" cleanup --all >/dev/null 2>&1 || true
  ends
done

# LOWSLOW (diluat) x6 -> 10
NSP="default kube-system cert-manager argocd monitoring"
for n in 5 6 7 8 9 10; do
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

# lateral movement x5
SAS="system:serviceaccount:kube-system:namespace-controller system:serviceaccount:kube-system:generic-garbage-collector system:serviceaccount:kube-system:replicaset-controller system:admin system:serviceaccount:cert-manager:cert-manager"
for n in 11 12 13 14 15; do
  SA=adversary-lat-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; KAS(){ kubectl --kubeconfig "$KC" --as="$1" "${@:2}" >/dev/null 2>&1||true; }
  sess "lateral #$n"
  for r in 1 2 3 4; do for as in $SAS; do KAS "$as" get pods -A; KAS "$as" get namespaces; done; done
  ends
done

# IMPACT (variat) x4 -> 10
for n in 14 15 16 17; do
  SA=adversary-impv-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  for i in $(seq 1 16); do kubectl create configmap dz-$SA-$i --from-literal=k=v -n $VNS >/dev/null 2>&1; done
  sess "IMPACT #$n (variat)"
  case $((n%3)) in
    2) for i in $(seq 1 16); do K delete configmap dz-$SA-$i -n $VNS; done;;
    0) K create deployment m-$SA --image=nginx --replicas=7 -n $VNS; for i in $(seq 1 10); do K delete configmap dz-$SA-$i -n $VNS; done; K delete deployment m-$SA -n $VNS;;
    1) for i in $(seq 1 12); do K delete configmap dz-$SA-$i -n $VNS; K get pods -n $VNS; done;;
  esac
  ends
done

# EVASION (variat) x4 -> 10
mk_def(){ for i in $(seq 1 6); do printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: np-%s-%s, namespace: %s}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' "$1" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; done; }
for n in 14 15 16 17; do
  SA=adversary-evav-$n; KC=$(mkkc $SA); CREATED="$CREATED $SA"; K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  mk_def $SA
  sess "EVASION #$n (variat)"
  K delete events --all -n $VNS
  case $((n%4)) in
    2) for i in $(seq 1 6); do K delete networkpolicy np-$SA-$i -n $VNS; done; K create clusterrolebinding ez-$SA --clusterrole=cluster-admin --serviceaccount=$VNS:default; K delete clusterrolebinding ez-$SA;;
    3) for i in 1 2 3; do K create rolebinding rz-$SA-$i --clusterrole=admin --serviceaccount=$VNS:default -n $VNS; K delete rolebinding rz-$SA-$i -n $VNS; done; for i in $(seq 1 6); do K delete networkpolicy np-$SA-$i -n $VNS; done;;
    0) for i in $(seq 1 6); do K delete networkpolicy np-$SA-$i -n $VNS; K get events -n $VNS; done;;
    1) for i in $(seq 1 8); do printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: ch-%s-%s, namespace: %s}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' "$SA" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; K delete networkpolicy ch-$SA-$i -n $VNS; done;;
  esac
  ends
done

# escalation, behaviourally varied, x7
for p in 1 2 3; do kubectl run esc-target-$p --image=ubuntu:22.04 --restart=Never -n $VNS -- sleep 3600 >/dev/null 2>&1||true; done
kubectl wait --for=condition=Ready pod/esc-target-1 -n $VNS --timeout=90s >/dev/null 2>&1||true
e_forbid(){ for r in 1 2 3 4 5; do K get secrets -A; K create clusterrolebinding x-$1-$r --clusterrole=cluster-admin --serviceaccount=default:$1; K get nodes; K create serviceaccount sa-$1-$r -n kube-system; done; }
e_multins(){ for ns in $SECNS; do nm=$(secname $ns); [ -n "$nm" ] && K get secret $nm -n $ns; K get secrets -n $ns; done; for ns in $SECNS default; do K get secrets -n $ns; done; }
e_rbac(){ for r in 1 2 3 4 5; do K create clusterrolebinding cb-$1-$r --clusterrole=cluster-admin --serviceaccount=default:$1; K create clusterrole cr-$1-$r --verb=get --resource=secrets; K create rolebinding rb-$1-$r --clusterrole=admin --serviceaccount=default:$1 -n $VNS; done; }
e_exec(){ for r in 1 2 3 4 5 6; do for p in 1 2 3; do K exec esc-target-$p -n $VNS -- id; done; done; }
e_hoard(){ for r in 1 2 3; do K get secrets -n kube-system; for nm in $(kubectl get secrets -n kube-system -o name 2>/dev/null|head -8|cut -d/ -f2); do K get secret $nm -n kube-system; done; done; }
e_slow(){ for r in $(seq 1 6); do K get pods -n $VNS; K get configmaps -n $VNS; K get services -A; nm=$(secname kube-system); [ -n "$nm" ] && K get secret $nm -n kube-system; [ $((r%3)) -eq 0 ] && K create clusterrolebinding s-$1-$r --clusterrole=cluster-admin --serviceaccount=default:$1; done; }
escn=7
for spec in "pod-reader e_forbid" "cluster-admin e_multins" "cluster-admin e_rbac" "cluster-admin e_exec" "cluster-admin e_hoard" "cluster-admin e_slow" "cluster-admin e_rbac"; do
  set -- $spec; role=$1; fn=$2
  SA=adversary-escv-$escn; KC=$(mkkc $SA $role); CREATED="$CREATED $SA"; K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1||true; }
  sess "ESCV #$escn ($fn)"; $fn "$SA"; ends; escn=$((escn+1))
done

echo ">> cleanup..."
kubectl get clusterrolebinding -o name 2>/dev/null | grep -E "rt-adversary|rt-redteam|sl-adversary|ez-adversary|cb-adversary|x-adversary|s-adversary" | xargs -r kubectl delete >/dev/null 2>&1||true
kubectl get clusterrole -o name 2>/dev/null | grep -E "cr-adversary" | xargs -r kubectl delete >/dev/null 2>&1||true
for s in $CREATED redteam-stratus redteam-persist redteam-lat-ext; do kubectl delete sa $s -n default >/dev/null 2>&1||true; done
kubectl delete clusterrole pod-reader >/dev/null 2>&1||true
kubectl delete namespace $VNS >/dev/null 2>&1||true
echo ">> done. sessions so far: $(grep -cE 'SESSION [0-9]+ START' "$SF")"
