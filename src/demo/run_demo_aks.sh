#!/usr/bin/env bash
# End-to-end demo on the managed AKS cluster.
#
# The phases are separate because two of them are slow for reasons outside our control:
# AKS provisioning takes ~10 min, and audit events need ~5 min to land in Log Analytics.
# Run those ahead of time; keep --train and --attack for the live walkthrough.
#
#   ./run_demo_aks.sh --provision   AKS + Log Analytics + kube-audit diagnostic setting   (~10 min)
#   ./run_demo_aks.sh --deploy      detector + adapter + Prometheus/Grafana/Alertmanager  (~3-5 min)
#   ./run_demo_aks.sh --dataset     re-run the collection pipeline (actors, attacks, export)
#   ./run_demo_aks.sh --train       reproduce the held-out evaluation table from the CSV   (~30 s)
#   ./run_demo_aks.sh --attack      launch real attacks, watch them surface in Grafana
#   ./run_demo_aks.sh --status      live pod / image / healthz state
#   ./run_demo_aks.sh --grafana     port-forward Grafana + MailHog
#
# With no argument: --status followed by --train.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SRC="$REPO/src"
NS=runtime-ids
hr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

phase_provision(){ hr "1 - Provision the managed AKS cluster"
  echo "Creates: resource group, Log Analytics workspace, AKS, kube-audit diagnostic setting,"
  echo "and the kubelet identity role assignment the adapter needs. ~10 min and it costs money."
  bash "$SRC/cluster/aks/setup_aks.sh"; }

phase_deploy(){ hr "2 - Deploy the IDS and the observability stack"
  bash "$SRC/deploy/scripts/deploy_obs_aks.sh"; }

phase_dataset(){ hr "3 - Re-run the dataset collection pipeline"
  # Re-running reproduces the pipeline, not the CSV: the audit stream carries real timing and real
  # infrastructure chatter, so a fresh collection is comparable but never byte-identical.
  bash "$SRC/dataset/actors/setup_actors.sh" || true
  echo ">> launching one short attack scenario as an example..."
  bash "$SRC/dataset/attacks/attack_wilson_push.sh" || true
  echo ">> wait ~5 min for Log Analytics ingestion, then:"
  echo "   (cd $SRC/dataset/export && python export_v2.py)"; }

phase_train(){ hr "4 - Reproduce the held-out evaluation table"
  # random_state=0 everywhere, so this prints the same numbers as the report.
  ( cd "$REPO" && source detection/bin/activate 2>/dev/null; python "$SRC/model/train/train_v2.py" ) | tail -24; }

phase_attack(){ hr "5 - Live attack -> adapter -> alert"
  phase_ui   # open the dashboards first, otherwise the alerts arrive before anyone is looking
  echo "Attacks run as real kubectl calls. The adapter reads them back out of Log Analytics and"
  echo "POSTs the windows to /predict/raw, so an alert lags the attack by the ingestion delay."
  echo ">> follow the adapter: kubectl -n $NS logs -l app=ids-audit-adapter -f"
  bash "$SRC/dataset/attacks/attack_esc_eva_varied.sh" || true
  bash "$SRC/dataset/attacks/attack_compromised_allowlist.sh" || true
  echo ">> in Grafana: audit_xgb_alerts_total"; }

phase_status(){ hr "Live state"
  kubectl get pods -n $NS -o wide 2>/dev/null | grep -E "audit|adapter|flow|grafana|prometheus" \
    || echo "(cluster unreachable or stopped)"
  echo ""; echo ">> deployed image:"
  kubectl get deploy ids-audit-xgb -n $NS -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}' 2>/dev/null || true
  POD=$(kubectl get pod -n $NS -l app=ids-audit-xgb -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "${POD:-}" ] && kubectl exec -n $NS "$POD" -- \
    python -c "import urllib.request,json;print('healthz:',json.load(urllib.request.urlopen('http://localhost:8080/healthz')))" 2>/dev/null || true; }

phase_ui(){ hr "Port-forward Grafana + MailHog"
  # Kill stale forwards first, otherwise the second run dies on 'address already in use'.
  pkill -f "port-forward.*svc/grafana 3000:3000" 2>/dev/null || true
  pkill -f "port-forward.*svc/mailhog 8025:8025" 2>/dev/null || true
  kubectl -n monitoring rollout status deploy/grafana --timeout=90s >/dev/null 2>&1 || true
  nohup kubectl -n monitoring port-forward svc/grafana 3000:3000 >/tmp/pf-grafana.log 2>&1 &
  nohup kubectl -n monitoring port-forward svc/mailhog 8025:8025 >/tmp/pf-mailhog.log 2>&1 &
  sleep 4
  echo "  Grafana -> http://localhost:3000  (admin/admin)"
  echo "  MailHog -> http://localhost:8025"
  if command -v open >/dev/null 2>&1; then open http://localhost:3000 2>/dev/null || true; open http://localhost:8025 2>/dev/null || true; fi
  echo "  (stop: pkill -f 'port-forward.*svc/(grafana 3000|mailhog 8025)')"; }

[ $# -eq 0 ] && { phase_status; phase_train; exit 0; }
for arg in "$@"; do case $arg in
  --provision) phase_provision;; --deploy) phase_deploy;; --dataset) phase_dataset;;
  --train) phase_train;;         --attack) phase_attack;; --status) phase_status;;
  --ui|--grafana) phase_ui;;
  *) echo "unknown argument: $arg"; exit 1;; esac; done
