#!/usr/bin/env bash
# Regenerate escalation (escv) and evasion (evav) with genuine behavioural variation.
#
# The templated versions were 88% byte-identical between train and held-out, which made recall look
# far better than it was. Six distinct profiles each, split on behaviour rather than identity.
# Destructive actions stay inside lab-victim and its decoys.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create namespace $VNS >/dev/null 2>&1 || true
SECNS="kube-system cert-manager argocd monitoring"
mkkc(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole="${2:-cluster-admin}" --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=3h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
SS(){ N=$(grep -cE "SESSION [0-9]+ START" "$SF"); echo $((N+1)); }
CREATED=""
run_profile(){ local SA=$1 lbl=$2 role=$3 fn=$4 KC; KC=$(mkkc $SA $role); CREATED="$CREATED $SA"
  K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
  local S; S=$(SS); echo "  S$S $lbl ($SA)"; echo "SESSION $S START $(nowZ)" >> "$SF"; $fn "$SA"; echo "SESSION $S END $(nowZ)" >> "$SF"; }
secname(){ kubectl get secrets -n $1 -o name 2>/dev/null | head -1 | cut -d/ -f2; }

# rol low-priv pt forbid-trail (escv-1)
kubectl create clusterrole pod-reader --verb=get,list --resource=pods >/dev/null 2>&1||true
# pod-uri tinta pt exec (escv-4)
for p in 1 2 3; do kubectl run esc-target-$p --image=ubuntu:22.04 --restart=Never -n $VNS -- sleep 3600 >/dev/null 2>&1||true; done
kubectl wait --for=condition=Ready pod/esc-target-1 -n $VNS --timeout=90s >/dev/null 2>&1||true

# ESCALADARE — 6 profile
e_forbid(){ for r in 1 2 3 4 5; do K get secrets -A; K create clusterrolebinding x-$1-$r --clusterrole=cluster-admin --serviceaccount=default:$1; K get nodes; K delete pod kube-system-x -n kube-system; K create serviceaccount sa-$1-$r -n kube-system; done; }  # LOW-priv -> forbid trail
e_multins(){ for ns in $SECNS; do n=$(secname $ns); [ -n "$n" ] && K get secret $n -n $ns; K get secrets -n $ns; done; for ns in $SECNS default; do K get secrets -n $ns; done; }  # secrete in MULTE ns
e_rbac(){ for r in 1 2 3 4 5; do K create clusterrolebinding cb-$1-$r --clusterrole=cluster-admin --serviceaccount=default:$1; K create clusterrole cr-$1-$r --verb=get --resource=secrets; K create rolebinding rb-$1-$r --clusterrole=admin --serviceaccount=default:$1 -n $VNS; done; }  # RBAC create
e_exec(){ for r in 1 2 3 4 5 6; do for p in 1 2 3; do K exec esc-target-$p -n $VNS -- id; done; done; }  # EXEC-focus
e_hoard(){ for r in 1 2 3; do K get secrets -n kube-system; for n in $(kubectl get secrets -n kube-system -o name 2>/dev/null|head -8|cut -d/ -f2); do K get secret $n -n kube-system; done; done; }  # secrete MULTE intr-UN ns
e_slow(){ for r in $(seq 1 6); do K get pods -n $VNS; K get configmaps -n $VNS; K get services -A; n=$(secname kube-system); [ -n "$n" ] && K get secret $n -n kube-system; [ $((r%3)) -eq 0 ] && K create clusterrolebinding s-$1-$r --clusterrole=cluster-admin --serviceaccount=default:$1; done; }  # diluat/mixt

run_profile adversary-escv-1 ESC/forbid   pod-reader e_forbid
run_profile adversary-escv-2 ESC/multins  cluster-admin e_multins
run_profile adversary-escv-3 ESC/rbac     cluster-admin e_rbac
run_profile adversary-escv-4 ESC/exec     cluster-admin e_exec
run_profile adversary-escv-5 ESC/hoard    cluster-admin e_hoard
run_profile adversary-escv-6 ESC/slow     cluster-admin e_slow

# EVASION — 6 profile (adversary-evav-*)
mk_def(){ for i in $(seq 1 6); do printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: np-%s-%s, namespace: %s}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' "$1" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; done
  for i in 1 2; do printf 'apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata: {name: wh-%s-%s}\nwebhooks:\n- name: w%s.example.com\n  failurePolicy: Ignore\n  sideEffects: None\n  admissionReviewVersions: [v1]\n  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: %s}}\n  rules: [{apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [configmaps]}]\n  clientConfig: {url: "https://127.0.0.1:1/x"}\n' "$1" "$i" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; done; }
v_npevt(){ mk_def $1; K delete events --all -n $VNS; for i in 1 2 3 4 5 6; do K delete networkpolicy np-$1-$i -n $VNS; done; }
v_whcrb(){ mk_def $1; K delete validatingwebhookconfiguration wh-$1-1 wh-$1-2; K create clusterrolebinding ev-$1 --clusterrole=cluster-admin --serviceaccount=$VNS:default; K delete clusterrolebinding ev-$1; K delete events --all -n $VNS; }
v_rbevt(){ mk_def $1; for i in 1 2 3; do K create rolebinding rb-$1-$i --clusterrole=admin --serviceaccount=$VNS:default -n $VNS; K delete rolebinding rb-$1-$i -n $VNS; done; K delete events --all -n $VNS; K delete networkpolicy np-$1-1 np-$1-2 -n $VNS; }
v_churn(){ for i in $(seq 1 8); do printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: ch-%s-%s, namespace: %s}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' "$1" "$i" "$VNS" | kubectl --kubeconfig "/tmp/kc-$1" apply -f - >/dev/null 2>&1||true; K delete networkpolicy ch-$1-$i -n $VNS; done; }
v_highvol(){ mk_def $1; mk_def ${1}b; K delete events --all -n $VNS; for i in 1 2 3 4 5 6; do K delete networkpolicy np-$1-$i -n $VNS; K delete networkpolicy np-${1}b-$i -n $VNS; done; K delete validatingwebhookconfiguration wh-$1-1 wh-$1-2 wh-${1}b-1 wh-${1}b-2; }
v_slow(){ mk_def $1; for i in 1 2 3 4 5 6; do K delete networkpolicy np-$1-$i -n $VNS; K get events -n $VNS; K get networkpolicies -A; K get pods -n $VNS; done; }

run_profile adversary-evav-1 EVA/npevt   cluster-admin v_npevt
run_profile adversary-evav-2 EVA/whcrb   cluster-admin v_whcrb
run_profile adversary-evav-3 EVA/rbevt   cluster-admin v_rbevt
run_profile adversary-evav-4 EVA/churn   cluster-admin v_churn
run_profile adversary-evav-5 EVA/highvol cluster-admin v_highvol
run_profile adversary-evav-6 EVA/slow    cluster-admin v_slow

echo ">> cleanup..."
kubectl get clusterrolebinding -o name 2>/dev/null | grep -E "rt-adversary-(escv|evav)|cb-adversary|x-adversary|ev-adversary" | xargs -r kubectl delete >/dev/null 2>&1||true
kubectl get clusterrole -o name 2>/dev/null | grep -E "cr-adversary" | xargs -r kubectl delete >/dev/null 2>&1||true
kubectl get validatingwebhookconfiguration -o name 2>/dev/null | grep -E "wh-adversary" | xargs -r kubectl delete >/dev/null 2>&1||true
for s in $CREATED; do kubectl delete sa $s -n default >/dev/null 2>&1||true; done
kubectl delete clusterrole pod-reader >/dev/null 2>&1||true
kubectl delete namespace $VNS >/dev/null 2>&1 || true
echo ">> done. new sessions:"; tail -12 "$SF"