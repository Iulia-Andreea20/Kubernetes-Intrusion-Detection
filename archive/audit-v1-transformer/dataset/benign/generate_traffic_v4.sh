#!/bin/bash
# v4 — #2-partea-2: 'platform-admin' apare în AMBELE clase (benign + malițios), aceeași identitate.
# Etichetare pe timp (cauzală): ce face în [PA_MAL_START,PA_MAL_END] = atac; restul = benign.
# => baseline-ul pe identitate nu mai poate prezice eticheta; modelul separă pur comportamental.
set -uo pipefail
W=/tmp/ids_collect
K(){ kubectl --kubeconfig "$W/kubeconfig-$1" "${@:2}" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-6}"
WIN=$W/windows.txt; : > "$WIN"
for ns in apps data; do kubectl create namespace "$ns" >/dev/null 2>&1 || true; done

echo "BENIGN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for r in $(seq 1 "$ROUNDS"); do
  echo "  benign $r/$ROUNDS"
  # context benign (câteva roluri)
  K sre-oncall get pods -A; K sre-oncall get events -A; K sre-oncall get nodes
  K devops-pipeline create deployment app-$r --image=nginx -n apps; K devops-pipeline get pods -n apps
  K security-auditor get roles -A; K security-auditor get clusterroles; K security-auditor get clusterrolebindings
  K data-engineer create job job-$r --image=busybox -n data -- echo hi; K data-engineer get jobs -A
  # platform-admin BENIGN (acțiuni-semnătură LEGITIME)
  K platform-admin create serviceaccount mon-$r -n default
  K platform-admin create clusterrolebinding monitoring-$r --clusterrole=view --serviceaccount=default:mon-$r
  K platform-admin create serviceaccount ci-$r -n default; K platform-admin create token ci-$r -n default
  K platform-admin get secrets -n default
  K platform-admin run debug-$r --image=alpine --restart=Never -- sleep 60
done
echo "BENIGN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo "ATTACK_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
# platform-admin MALIȚIOS — ACEEAȘI identitate, dar lanț de atac (etichetat pe timp)
echo "PA_MAL_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for ep in $(seq 1 "$ROUNDS"); do
  echo "  platform-admin malițios $ep/$ROUNDS"
  K platform-admin get secrets -A; K platform-admin get serviceaccounts -A; K platform-admin get clusterroles; K platform-admin get clusterrolebindings; K platform-admin get pods -A -o wide
  for sx in $(kubectl --kubeconfig $W/kubeconfig-platform-admin get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -6); do
    K platform-admin get secret "${sx#*/}" -n "${sx%/*}" -o yaml
  done
  K platform-admin run paevil-$ep --image=alpine --restart=Never -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-platform-admin wait --for=condition=ready pod/paevil-$ep --timeout=30s >/dev/null 2>&1 || true
  K platform-admin exec paevil-$ep -- sh -c "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K platform-admin create clusterrolebinding paevil-$ep --clusterrole=cluster-admin --serviceaccount=default:default
  K platform-admin delete pod paevil-$ep --force --grace-period=0
done
echo "PA_MAL_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

# atacatorii dedicați (clasa atac)
for ep in $(seq 1 "$ROUNDS"); do
  echo "  adversari $ep/$ROUNDS"
  K adversary-external get secrets -A; K adversary-external get serviceaccounts -A; K adversary-external get clusterroles; K adversary-external get pods -A -o wide
  for sx in $(kubectl --kubeconfig $W/kubeconfig-adversary-external get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -5); do
    K adversary-external get secret "${sx#*/}" -n "${sx%/*}" -o yaml; done
  K adversary-external run pwn-$ep --image=alpine --restart=Never -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-adversary-external wait --for=condition=ready pod/pwn-$ep --timeout=30s >/dev/null 2>&1 || true
  K adversary-external exec pwn-$ep -- sh -c "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K adversary-external create clusterrolebinding pwn-$ep --clusterrole=cluster-admin --serviceaccount=default:default
  K adversary-external delete pod pwn-$ep --force --grace-period=0
  K adversary-insider get secrets -A; K adversary-insider create serviceaccount backdoor-$ep -n default; K adversary-insider create token backdoor-$ep -n default
done
echo "ATTACK_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo ">> curățenie"
for ns in apps data; do kubectl delete namespace "$ns" >/dev/null 2>&1 || true; done
for r in $(seq 1 "$ROUNDS"); do
  kubectl delete clusterrolebinding monitoring-$r paevil-$r pwn-$r >/dev/null 2>&1 || true
  kubectl delete serviceaccount mon-$r ci-$r backdoor-$r -n default >/dev/null 2>&1 || true
  kubectl delete pod debug-$r -n default --force --grace-period=0 >/dev/null 2>&1 || true
done
echo "GATA v4."; grep -E "_START|_END" "$WIN"
