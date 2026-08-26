#!/usr/bin/env bash
# Escalation paced out thin: roughly 18 innocuous actions per dangerous one.
#
# This is the regime where a density-driven model gives up - the window barely differs from benign
# traffic - while the dangerous primitive is still there to be seen. Held out, under an attacker
# identity that appears nowhere in training. The benign filler reads a single object at a time so
# it does not inflate n_list.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
SA=adversary-stealth; NS=default
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }

# identitate atacator NOUA: token privilegiat furat, abuzat lent
kubectl create sa $SA -n $NS >/dev/null 2>&1 || true
kubectl create clusterrolebinding rt-$SA --clusterrole=cluster-admin --serviceaccount=$NS:$SA >/dev/null 2>&1 || true
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
T=$(kubectl create token $SA -n $NS --duration=2h 2>/dev/null); KC=/tmp/kc-$SA
kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
kubectl config --kubeconfig="$KC" use-context c >/dev/null
K(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }

# pod tinta pt exec (creat de atacator = deploy container, realist)
kubectl --kubeconfig "$KC" run stealth-target --image=ubuntu:22.04 --restart=Never -n $NS -- sleep 3600 >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready pod/stealth-target -n $NS --timeout=90s >/dev/null 2>&1 || true

# Look up one real secret name per namespace before the session starts, so these reads do not
# land inside the measured windows.
SEC_ks=$(kubectl get secrets -n kube-system  -o name 2>/dev/null | head -1 | cut -d/ -f2)
SEC_cm=$(kubectl get secrets -n cert-manager -o name 2>/dev/null | head -1 | cut -d/ -f2)
SEC_ag=$(kubectl get secrets -n argocd       -o name 2>/dev/null | head -1 | cut -d/ -f2)
SEC_mo=$(kubectl get secrets -n monitoring   -o name 2>/dev/null | head -1 | cut -d/ -f2)
NSP="default kube-system cert-manager argocd monitoring"

echo "SESSION 14 START $(nowZ)" >> "$SF"
benign_filler(){  # ~18 gets on a single object, never a list, so n_list stays low
  i=0
  for ns in $NSP $NSP $NSP $NSP; do
    i=$((i+1)); [ $i -gt 18 ] && break
    case $((i % 4)) in
      0) K get serviceaccount default -n "$ns" ;;
      1) K get configmap kube-root-ca.crt -n "$ns" ;;
      2) K get namespace "$ns" ;;
      3) K version ;;
    esac
  done
}
secret_read(){ # one secret at a time, rotating namespace: presence without volume
  case $1 in
    0) [ -n "$SEC_ks" ] && K get secret "$SEC_ks" -n kube-system ;;
    1) [ -n "$SEC_cm" ] && K get secret "$SEC_cm" -n cert-manager ;;
    2) [ -n "$SEC_ag" ] && K get secret "$SEC_ag" -n argocd ;;
    *) [ -n "$SEC_mo" ] && K get secret "$SEC_mo" -n monitoring ;;
  esac
}
for r in $(seq 1 8); do
  benign_filler
  # 1 primitiva periculoasa, rotita (secret single / CRB / exec) — densitate 1/19
  case $((r % 3)) in
    0) secret_read $((r % 4)) ;;
    1) K create clusterrolebinding stealth-crb-$r --clusterrole=cluster-admin --serviceaccount=$NS:$SA ;;
    2) K exec stealth-target -n $NS -- id ;;
  esac
  echo "  runda $r/8 (18 benign + 1 periculoasa)"
done
echo "SESSION 14 END $(nowZ)" >> "$SF"

echo ">> done; cleaning up artefacts"
kubectl delete clusterrolebinding $(kubectl get clusterrolebinding -o name 2>/dev/null | grep -E "stealth-crb|rt-adversary-stealth" | cut -d/ -f2) >/dev/null 2>&1 || true
kubectl delete pod stealth-target -n $NS >/dev/null 2>&1 || true
kubectl delete sa $SA -n $NS >/dev/null 2>&1 || true
tail -2 "$SF"