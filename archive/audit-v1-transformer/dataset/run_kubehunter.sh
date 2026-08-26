#!/bin/bash
# HELD-OUT TOOL-DISJOINT (#9): rulează kube-hunter (unealtă REALĂ de pentest, NU scriptul nostru)
# ca un SA compromis read-only (rol view). Activitatea ei de recon -> audit API -> test de generalizare.
set -uo pipefail
OUT="$(cd "$(dirname "$0")" && pwd)/reference_dataset"
kubectl create namespace pentest >/dev/null 2>&1 || true
kubectl create serviceaccount kube-hunter -n pentest >/dev/null 2>&1 || true
kubectl create clusterrolebinding kh-view --clusterrole=view --serviceaccount=pentest:kube-hunter >/dev/null 2>&1 || true

echo "KH_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$OUT/kh_window.txt"
kubectl delete pod kube-hunter -n pentest >/dev/null 2>&1 || true
kubectl run kube-hunter -n pentest --image=aquasec/kube-hunter --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"kube-hunter","containers":[{"name":"kube-hunter","image":"aquasec/kube-hunter","args":["--pod","--report","json"]}]}}' >/dev/null 2>&1 || true
echo ">> aștept kube-hunter să termine probing-ul..."
for i in $(seq 1 30); do
  ph=$(kubectl get pod kube-hunter -n pentest -o jsonpath='{.status.phase}' 2>/dev/null || echo "?")
  echo "   kube-hunter: $ph"
  { [ "$ph" = "Succeeded" ] || [ "$ph" = "Failed" ]; } && break
  sleep 10
done
echo "KH_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT/kh_window.txt"
echo ">> ce a raportat kube-hunter (ultimele linii):"
kubectl logs kube-hunter -n pentest 2>/dev/null | grep -iE "vulnerab|service account|token|found|location" | head -10 || true
kubectl delete pod kube-hunter -n pentest >/dev/null 2>&1 || true
kubectl delete clusterrolebinding kh-view >/dev/null 2>&1 || true
kubectl delete sa kube-hunter -n pentest >/dev/null 2>&1 || true
echo "GATA kube-hunter."
