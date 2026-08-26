#!/usr/bin/env bash
# Close three MITRE gaps the dataset had no coverage for, each under a fresh attacker identity:
#   impact           workload hijack (miner replicas) plus mass resource deletion
#   defense evasion  delete events, networkpolicies, an admission webhook and its own binding
#   lateral movement impersonate privileged identities (kubectl --as) and exec across namespaces
#
# Everything destructive is confined to the scratch namespace lab-victim and its decoys. The
# admission webhook uses failurePolicy: Ignore and a namespaceSelector, so it cannot affect the
# rest of the cluster even while it exists. Full cleanup at the end.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
mkkc(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole=cluster-admin --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=2h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }

# Setup as admin, before any session starts
kubectl create namespace $VNS >/dev/null 2>&1 || true
populate(){ for i in $(seq 1 10); do kubectl create configmap decoy-cm-$i --from-literal=k=v -n $VNS >/dev/null 2>&1; done
  for i in $(seq 1 8); do kubectl create secret generic decoy-sec-$i --from-literal=p=x -n $VNS >/dev/null 2>&1; done
  kubectl create deployment decoy-app1 --image=nginx -n $VNS >/dev/null 2>&1; kubectl create deployment decoy-app2 --image=nginx -n $VNS >/dev/null 2>&1; }
KIMP=$(mkkc adversary-impact); KEV=$(mkkc adversary-evasion); KLAT=$(mkkc adversary-lateral)

# S15 IMPACT
populate
N=$(grep -cE "SESSION [0-9]+ START" "$SF"); N=$((N+1)); echo "  S$N IMPACT (adversary-impact)"
echo "SESSION $N START $(nowZ)" >> "$SF"
KI(){ kubectl --kubeconfig "$KIMP" "$@" >/dev/null 2>&1 || true; }
KI create deployment crypto-miner --image=nginx --replicas=6 -n $VNS    # resource hijack (workload + fan-out)
KI create deployment xmrig-pool  --image=nginx --replicas=4 -n $VNS
KI scale deployment crypto-miner --replicas=8 -n $VNS
KI get pods -n $VNS; KI get deployments -n $VNS
for i in $(seq 1 10); do KI delete configmap decoy-cm-$i -n $VNS; done   # mass deletion
for i in $(seq 1 8);  do KI delete secret decoy-sec-$i -n $VNS; done
KI delete deployment decoy-app1 -n $VNS; KI delete deployment decoy-app2 -n $VNS
KI delete deployment crypto-miner -n $VNS; KI delete deployment xmrig-pool -n $VNS
echo "SESSION $N END $(nowZ)" >> "$SF"

# S16 DEFENSE EVASION
# defensive decoys, created as admin before the session starts
for i in 1 2 3 4 5; do
cat <<EOF | kubectl apply -f - >/dev/null 2>&1 || true
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: decoy-np-$i, namespace: $VNS}
spec: {podSelector: {}, policyTypes: [Ingress]}
EOF
done
for i in 1 2; do
cat <<EOF | kubectl apply -f - >/dev/null 2>&1 || true
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata: {name: decoy-policy-$i}
webhooks:
- name: decoy$i.example.com
  failurePolicy: Ignore
  sideEffects: None
  admissionReviewVersions: [v1]
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $VNS}}
  rules: [{apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [configmaps]}]
  clientConfig: {url: "https://127.0.0.1:1/nope"}
EOF
done
N=$((N+1)); echo "  S$N DEFENSE EVASION (adversary-evasion)"
echo "SESSION $N START $(nowZ)" >> "$SF"
KE(){ kubectl --kubeconfig "$KEV" "$@" >/dev/null 2>&1 || true; }
KE delete events --all -n $VNS                                          # anti-forensic
for i in 1 2 3 4 5; do KE delete networkpolicy decoy-np-$i -n $VNS; done # remove network defenses
KE delete validatingwebhookconfiguration decoy-policy-1                  # disable admission control
KE delete validatingwebhookconfiguration decoy-policy-2
KE create clusterrolebinding evade-crb --clusterrole=cluster-admin --serviceaccount=$VNS:default
KE delete clusterrolebinding evade-crb                                   # cover tracks: sterge propriul CRB
KE delete clusterrolebinding rt-adversary-impact                         # sterge urma altui atacator
KE get events -n $VNS; KE get networkpolicies -A; KE delete pod --all -n $VNS
echo "SESSION $N END $(nowZ)" >> "$SF"

# lateral movement
kubectl run pivot-target --image=ubuntu:22.04 --restart=Never -n $VNS -- sleep 3600 >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready pod/pivot-target -n $VNS --timeout=90s >/dev/null 2>&1 || true
N=$((N+1)); echo "  S$N lateral movement (adversary-lateral)"
echo "SESSION $N START $(nowZ)" >> "$SF"
KAS(){ kubectl --kubeconfig "$KLAT" --as="$1" "${@:2}" >/dev/null 2>&1 || true; }
# impersonate several privileged identities: drives has_impersonation and n_distinct_impersonated
for r in 1 2 3; do
  KAS system:serviceaccount:kube-system:namespace-controller get secrets -A
  KAS system:serviceaccount:kube-system:generic-garbage-collector get pods -A
  KAS system:serviceaccount:kube-system:replicaset-controller get deployments -A
  KAS system:serviceaccount:cert-manager:cert-manager get secrets -n cert-manager
  KAS system:masters get secrets -A
  KAS system:admin get nodes
done
# exec cross-namespace (pivot in alt ns) + portforward
kubectl --kubeconfig "$KLAT" exec pivot-target -n $VNS -- id >/dev/null 2>&1 || true
kubectl --kubeconfig "$KLAT" exec pivot-target -n $VNS -- hostname >/dev/null 2>&1 || true
echo "SESSION $N END $(nowZ)" >> "$SF"

# CLEANUP COMPLET
echo ">> cleanup..."
kubectl delete validatingwebhookconfiguration decoy-policy-1 decoy-policy-2 >/dev/null 2>&1 || true
kubectl delete clusterrolebinding evade-crb rt-adversary-impact rt-adversary-evasion rt-adversary-lateral >/dev/null 2>&1 || true
kubectl delete sa adversary-impact adversary-evasion adversary-lateral -n default >/dev/null 2>&1 || true
kubectl delete namespace $VNS >/dev/null 2>&1 || true
echo ">> done. new sessions:"; tail -6 "$SF"