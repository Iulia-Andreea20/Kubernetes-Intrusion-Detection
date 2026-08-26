#!/bin/bash
# Deploy three real operators so the benign half of the dataset contains traffic that legitimately
# looks alarming - otherwise "reads secrets" or "creates clusterrolebindings" would be a perfect
# attack signature by accident:
#   cert-manager         secrets, serviceaccounts
#   ArgoCD               broad discovery, clusterrolebindings, serviceaccounts
#   kube-prometheus      clusterrolebindings, heavy list/watch
# Trimmed down to fit on a DS2_v2 node.
set -uo pipefail
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1
helm repo update >/dev/null 2>&1

echo ">> [1/3] cert-manager..."
helm upgrade --install cert-manager jetstack/cert-manager -n cert-manager --create-namespace \
  --set crds.enabled=true \
  --set resources.requests.cpu=20m --set resources.requests.memory=64Mi \
  --wait --timeout 6m 2>&1 | tail -2

echo ">> [2/3] ArgoCD (no dex, notifications or applicationset)"
helm upgrade --install argocd argo/argo-cd -n argocd --create-namespace \
  --set dex.enabled=false --set notifications.enabled=false --set applicationSet.enabled=false \
  --set controller.resources.requests.cpu=50m --set controller.resources.requests.memory=256Mi \
  --set repoServer.resources.requests.cpu=20m --set repoServer.resources.requests.memory=128Mi \
  --set server.resources.requests.cpu=20m --set server.resources.requests.memory=128Mi \
  --set redis.resources.requests.cpu=20m --set redis.resources.requests.memory=64Mi \
  --wait --timeout 8m 2>&1 | tail -2

echo ">> [3/3] kube-prometheus-stack (operator + kube-state-metrics + a small Prometheus)"
helm upgrade --install kps prometheus-community/kube-prometheus-stack -n monitoring --create-namespace \
  --set grafana.enabled=false --set alertmanager.enabled=false --set nodeExporter.enabled=false \
  --set prometheus.prometheusSpec.retention=2h \
  --set prometheus.prometheusSpec.resources.requests.cpu=50m --set prometheus.prometheusSpec.resources.requests.memory=400Mi \
  --set prometheusOperator.resources.requests.cpu=20m --set prometheusOperator.resources.requests.memory=128Mi \
  --set kube-state-metrics.resources.requests.cpu=20m --set kube-state-metrics.resources.requests.memory=64Mi \
  --wait --timeout 8m 2>&1 | tail -2

echo ""
echo ">> stare operatori (toate namespace-urile):"
kubectl get pods -n cert-manager -n argocd 2>/dev/null | head -1
for ns in cert-manager argocd monitoring; do
  echo "  [$ns]"; kubectl get pods -n "$ns" --no-headers 2>/dev/null | awk '{print "    ",$1,$3}'
done
echo ">> operators deployed"