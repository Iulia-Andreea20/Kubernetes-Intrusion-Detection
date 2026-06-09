#!/bin/bash
# Deploy stack observability + IDS v2.2 pe AKS managed: audit HIBRID (XGBoost + 6 reguli) + flow +
# Prometheus + Alertmanager + MailHog + Grafana. Feed-ul LIVE real = adapter Log Analytics (30-adapter.yaml),
# aliniat la /predict/raw v2.2 (NU mai e modelul vechi Transformer / inject_demo).
set -uo pipefail
# az/kubectl se strică dacă venv-ul Python (detection) e activ pe PATH -> îl neutralizăm pe durata scriptului (subshell):
if [ -n "${VIRTUAL_ENV:-}" ]; then
  PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v "^${VIRTUAL_ENV}/bin$" | paste -sd: -)"
  unset VIRTUAL_ENV PYTHONHOME; export PATH PYTHONNOUSERSITE=1
fi
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
RID="$REPO/runtime_ids"; K="kubectl"
GP="$RID/observability/grafana"
HERE="$RID/deploy/azure"

echo ">> [1/5] namespace"
$K apply -f "$RID/deploy/k8s/00-namespace.yaml"

echo ">> [2/5] ConfigMaps Grafana (datasource + dashboards SOC/MLOps)"
$K -n runtime-ids create configmap grafana-datasource \
  --from-file="$GP/provisioning/datasources/datasource.yml" --dry-run=client -o yaml | $K apply -f -
$K -n runtime-ids create configmap grafana-provider \
  --from-file="$GP/provisioning/dashboards/provider.yml" --dry-run=client -o yaml | $K apply -f -
$K -n runtime-ids create configmap grafana-dashboards \
  --from-file="$GP/dashboards/ids_soc.json" --from-file="$GP/dashboards/ids_mlops.json" \
  --dry-run=client -o yaml | $K apply -f -

echo ">> [3/5] IDS v2.2: audit HIBRID (imagine imuabilă digest-pinned) + flow + observability"
$K apply -f "$HERE/k8s/11-audit-xgb.yaml" -f "$HERE/k8s/20-flow.yaml"
$K apply -f "$RID/deploy/k8s/40-prometheus.yaml" \
         -f "$RID/deploy/k8s/50-alertmanager.yaml" \
         -f "$RID/deploy/k8s/60-mailhog.yaml" \
         -f "$RID/deploy/k8s/70-grafana.yaml"
# NB: Falco (a 3-a componentă) NU se mai deployează automat — pe kernelul nod AKS (5.15-azure) engine-ul nu capturează
# syscall-uri (modern_ebpf respins de verificator; kmod se încarcă dar nu emite alerte). Assets păstrate în repo:
# `setup_falco.sh` (rulabil manual dacă se rezolvă pe alt nod). Demo = 2 componente: Audit (control-plane) + Flow (rețea).

echo ">> [4/5] feed LIVE: adapter Log Analytics → /predict/raw (necesită env.generated de la setup_aks.sh)"
if [ -f "$HERE/env.generated" ]; then
  set -a; . "$HERE/env.generated"; set +a
  $K -n runtime-ids create configmap ids-azure-config \
    --from-literal=LA_WORKSPACE_ID="$LA_WORKSPACE_ID" --dry-run=client -o yaml | $K apply -f -
  $K -n runtime-ids create secret generic ids-azure-sp \
    --from-literal=AZURE_TENANT_ID="$AZURE_TENANT_ID" \
    --from-literal=AZURE_CLIENT_ID="$AZURE_CLIENT_ID" \
    --from-literal=AZURE_CLIENT_SECRET="$AZURE_CLIENT_SECRET" --dry-run=client -o yaml | $K apply -f -
  $K apply -f "$HERE/k8s/30-adapter.yaml"
  echo "   adapter aplicat (poll Log Analytics; lag de ingestie ~minute — vezi testul DevOps MTTD)."
else
  echo "   (env.generated lipsește → adapter LIVE sărit. Rulează setup_aks.sh întâi, SAU testează serviciul direct: POST /predict/raw)"
fi

echo ">> [5/5] aștept serviciul Audit v2.2 (ids-audit-xgb)..."
$K -n runtime-ids rollout status deploy/ids-audit-xgb --timeout=300s || true
echo ""
$K -n runtime-ids get pods -o wide
echo ""
# --- deschide AUTOMAT UI-urile (port-forward în FUNDAL + browser) ca demonstrația să fie gata ---
echo ">> deschid Grafana + MailHog (port-forward în fundal)..."
pkill -f "port-forward.*svc/grafana 3000:3000" 2>/dev/null || true
pkill -f "port-forward.*svc/mailhog 8025:8025" 2>/dev/null || true
$K -n runtime-ids rollout status deploy/grafana --timeout=90s >/dev/null 2>&1 || true
nohup $K -n runtime-ids port-forward svc/grafana 3000:3000 >/tmp/pf-grafana.log 2>&1 &
nohup $K -n runtime-ids port-forward svc/mailhog 8025:8025 >/tmp/pf-mailhog.log 2>&1 &
sleep 4
if command -v open >/dev/null 2>&1; then open http://localhost:3000 2>/dev/null || true; open http://localhost:8025 2>/dev/null || true; fi
echo "=================================================================="
echo " UI DESCHISE (port-forward în fundal):"
echo "   Grafana → http://localhost:3000 (admin/admin) · MailHog → http://localhost:8025"
echo " Dashboard SOC: alerte pe audit_xgb_alerts_total{rule=...} (clasif/F/recon/destruct/hijack/persist/anom)"
echo " Oprire tuneluri: pkill -f 'port-forward.*svc/(grafana 3000|mailhog 8025)'"
echo "=================================================================="
