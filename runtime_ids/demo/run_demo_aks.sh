#!/usr/bin/env bash
# ============================================================================================
# DEMO „from zero" pe AKS MANAGED — fluxul REAL al sistemului IDS v2.2 (NU kind; kind nu poate
# reproduce un cluster managed: audit-ul merge în Log Analytics, nu într-un fișier local).
#
# Fazat (rulezi DOAR ce încape în timpul prezentării). AKS provisioning + ingestia Log Analytics
# au LATENȚĂ de minute — de aceea fazele lente (--provision, --dataset) se rulează ÎNAINTE, iar
# la apărare arăți fazele rapide/vizuale (--train tabelul Wilson, --attack→Grafana).
#
# Utilizare:
#   ./run_demo_aks.sh --provision   # [~10 min] AKS+ACR+Log Analytics+audit diagnostic+SP (setup_aks.sh)
#   ./run_demo_aks.sh --deploy      # [~3-5 min] IDS v2.2 (audit hibrid digest-pinned)+flow+Prometheus+Grafana+adapter LIVE
#   ./run_demo_aks.sh --dataset     # [LENT] recreează setul: actori benigni + atacuri + export_v2 (Log Analytics)
#   ./run_demo_aks.sh --train       # [~30s] reproduce tabelul Wilson din ref_v2_all.csv (DETERMINIST, random_state=0)
#   ./run_demo_aks.sh --attack      # [~1 min colectare + lag LA] lansează atacuri reale -> adapter -> alerte (Grafana)
#   ./run_demo_aks.sh --status      # arată starea live (poduri, healthz, imagine digest-pinned)
#   ./run_demo_aks.sh --grafana     # port-forward Grafana (SOC dashboard: audit_xgb_alerts_total{rule})
# Fără argument: --status + --train (partea sigură + științifică).
# ============================================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"   # runtime_ids/
REPO="$(cd "$ROOT/.." && pwd)"
AZ="$ROOT/deploy/azure"; COLLECT="$AZ/collect"; NS=runtime-ids
hr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

phase_provision(){ hr "FAZA 1 — PROVISIONING AKS managed (setup_aks.sh)"
  echo "Creează: resource group + ACR + Log Analytics + AKS + diagnostic kube-audit→LA + SP (Log Analytics Reader)."
  echo "ATENȚIE: ~10 min + cost. Pe un cluster managed audit-ul NU e fișier local — de-aceea Log Analytics."
  bash "$AZ/setup_aks.sh"; }

phase_deploy(){ hr "FAZA 2 — DEPLOY IDS v2.2 + OBSERVABILITY (deploy_obs_aks.sh)"
  echo "Audit HIBRID (XGBoost + 6 reguli, imagine IMUABILĂ @sha256) + Flow + Prometheus + Grafana + adapter LIVE (Log Analytics→/predict/raw)."
  bash "$AZ/deploy_obs_aks.sh"; }

phase_dataset(){ hr "FAZA 3 — RECREARE SET DE DATE (pipeline reproductibil; date dependente de cluster)"
  echo "Actori benigni (setup_actors.sh) + scenarii de atac (attack_*.sh) -> kube-audit -> Log Analytics -> export_v2.py -> ref_v2_all.csv."
  echo "ONEST: recreează PIPELINE-ul (date noi, similare), NU setul bit-cu-bit (telemetrie reală + timing). Vezi DATASHEET §6-7."
  bash "$COLLECT/setup_actors.sh" || true
  echo ">> lansează un scenariu de atac scurt (exemplu)..."; bash "$COLLECT/attack_wilson_push.sh" || true
  echo ">> ATENȚIE: așteaptă ingestia Log Analytics (~5 min) ÎNAINTE de export_v2.py."
  echo ">> apoi: (cd $COLLECT && python export_v2.py)  # interoghează LA -> ferestre 20 -> 34 trăsături -> CSV"; }

phase_train(){ hr "FAZA 4 — REPRODUCE TABELUL Wilson (train_v2.py, DETERMINIST)"
  echo "Din ref_v2_all.csv versionat -> clasificator + 6 reguli, Wilson DUBLU (ML-pur vs hibrid). random_state=0 -> bit-cu-bit."
  ( cd "$REPO" && source detection/bin/activate 2>/dev/null; cd "$COLLECT" && python train_v2.py ) | tail -24; }

phase_attack(){ hr "FAZA 5 — ATAC LIVE -> ADAPTER -> ALERTĂ (end-to-end pe cluster)"
  phase_ui   # deschide Grafana + MailHog ÎNAINTE de demonstrație (ca să vezi alertele live)
  echo "Lansează atacuri reale kubectl; adapterul (30-adapter.yaml) le citește din Log Analytics și POST /predict/raw -> alertă."
  echo ">> log-uri adapter (urmărește 'ids_alert' cu reasons):"
  echo "   kubectl -n $NS logs -l app=ids-audit-adapter -f"
  bash "$COLLECT/attack_compromised_allowlist.sh" || true
  echo ">> ONEST: alerta apare după lag-ul de ingestie Log Analytics (~minute). Urmărește în Grafana (panel audit_xgb_alerts_total)."; }

phase_status(){ hr "STARE LIVE (cluster managed) — componente: Audit (control-plane) + Flow (rețea)"
  kubectl get pods -n $NS -o wide 2>/dev/null | grep -E "audit|adapter|flow|grafana|prometheus" || echo "(cluster inaccesibil / oprit)"
  echo ""; echo ">> imagine audit (digest-pinned?):"
  kubectl get deploy ids-audit-xgb -n $NS -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}' 2>/dev/null || true
  POD=$(kubectl get pod -n $NS -l app=ids-audit-xgb -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "${POD:-}" ] && kubectl exec -n $NS "$POD" -- python -c "import urllib.request,json;print('healthz:',json.load(urllib.request.urlopen('http://localhost:8080/healthz')))" 2>/dev/null || true; }

phase_ui(){ hr "UI: deschid Grafana + MailHog (port-forward în FUNDAL + browser)"
  # idempotent: omoară orice port-forward vechi pe 3000/8025 (evită 'address already in use')
  pkill -f "port-forward.*svc/grafana 3000:3000" 2>/dev/null || true
  pkill -f "port-forward.*svc/mailhog 8025:8025" 2>/dev/null || true
  kubectl -n $NS rollout status deploy/grafana --timeout=90s >/dev/null 2>&1 || true
  nohup kubectl -n $NS port-forward svc/grafana 3000:3000 >/tmp/pf-grafana.log 2>&1 &
  nohup kubectl -n $NS port-forward svc/mailhog 8025:8025 >/tmp/pf-mailhog.log 2>&1 &
  sleep 4   # lasă tunelurile să se stabilească
  echo "  Grafana → http://localhost:3000  (admin/admin) — SOC: audit_xgb_alerts_total{rule}"
  echo "  MailHog → http://localhost:8025"
  if command -v open >/dev/null 2>&1; then open http://localhost:3000 2>/dev/null || true; open http://localhost:8025 2>/dev/null || true; fi
  echo "  (oprire tuneluri: pkill -f 'port-forward.*svc/(grafana 3000|mailhog 8025)')"; }

[ $# -eq 0 ] && { phase_status; phase_train; exit 0; }
for arg in "$@"; do case $arg in
  --provision) phase_provision;; --deploy) phase_deploy;; --dataset) phase_dataset;;
  --train) phase_train;; --attack) phase_attack;; --status) phase_status;;
  --ui|--grafana) phase_ui;;
  *) echo "argument necunoscut: $arg"; exit 1;; esac; done
