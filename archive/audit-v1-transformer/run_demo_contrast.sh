#!/bin/bash
#  LEGACY (faza inițială kind + model Transformer) — NU sistemul actual v2.2/2.4. NU rula la apărare ca „IDS-ul meu". Sistemul curent (XGBoost + 6 reguli, AKS managed) = demo/run_demo_aks.sh. Vezi demo/README.md + SCENARIU_PREZENTARE.md.
# Demo de CONTRAST — trafic normal vs. atac.
# Demonstrează că IDS-ul NU sună din orice: tace pe operații legitime
# (inclusiv acțiuni admin care seamănă cu atacuri) și reacționează doar la atac.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$REPO/detection/bin/python3"
cd "$REPO/runtime_ids"
CTX="kind-runtime-ids"
SLOG="/tmp/ids_streamer_contrast.log"

B="\033[94m"; G="\033[92m"; R="\033[91m"; BOLD="\033[1m"; DIM="\033[2m"; X="\033[0m"
banner(){ echo -e "\n${BOLD}${B}================================================================${X}";
          echo -e "${BOLD}${B}  $1${X}";
          echo -e "${BOLD}${B}================================================================${X}"; }
alerts(){ grep -c ids_alert "$SLOG" 2>/dev/null || true; }

# --- serviciu + cluster + streamer ---------------------------------------- #
banner "Pregătire (serviciu + cluster + streamer)"
if ! curl -s http://localhost:8080/readyz >/dev/null 2>&1; then
  ( cd service && "$PY" -m uvicorn ids_service:app --host 0.0.0.0 --port 8080 \
      >/tmp/ids_service.log 2>&1 & )
  curl --retry 40 --retry-delay 1 --retry-connrefused -s http://localhost:8080/readyz >/dev/null
fi
echo -e "${G} serviciu activ${X}"
if ! kind get clusters 2>/dev/null | grep -qx runtime-ids; then
  ./cluster/setup_kind.sh
fi
echo -e "${G} cluster activ${X}"
pkill -f "audit_streamer.py" 2>/dev/null || true
: > "$SLOG"
RUNTIME_IDS_AUDIT_LOG=audit-logs/audit.log \
RUNTIME_IDS_SERVICE_URL=http://localhost:8080 \
RUNTIME_IDS_STREAMER_METRICS_PORT=9091 \
  "$PY" streamer/audit_streamer.py >"$SLOG" 2>&1 &
SPID=$!
curl --retry 15 --retry-delay 1 --retry-connrefused -s http://localhost:9091/metrics >/dev/null 2>&1
echo -e "${G} streamer activ${X}"
cp data/labels.jsonl data/labels.jsonl.bak 2>/dev/null || true

# --- FAZA A: trafic normal ------------------------------------------------- #
banner "FAZA A — TRAFIC NORMAL (operații legitime, inclusiv admin)"
a0=$(alerts)
echo -e "  ${DIM}deploy app + 2 runde: get pods/configmaps/logs, scale, ȘI acțiuni admin"
echo -e "  legitime: get secrets, create token, create role/clusterrole...${X}"
bash attacks/benign_workload.sh all 2 >/dev/null 2>&1
"$PY" -c "import time; time.sleep(4)"
a1=$(alerts)
bev=$(curl -s http://localhost:9091/metrics | grep 'events_total{verdict="benign"}' | awk '{print $2}')
echo -e "  ${G} procesat ~${bev%.*} evenimente benign${X}    ${BOLD}$((a1-a0)) alerte${X}"

# --- FAZA B: atac ---------------------------------------------------------- #
banner "FAZA B — ATAC (scenarii MITRE reale)"
for sc in scenario_recon scenario_secret_access scenario_sa_token \
          scenario_malicious_pod scenario_rbac_escalation; do
  echo -e "  ${DIM}>> $sc${X}"
  bash attacks/attack_scenarios.sh "$sc" >/dev/null 2>&1
done
"$PY" -c "import time; time.sleep(3)"
a2=$(alerts)
echo -e "  ${R} atac procesat${X}    ${BOLD}$((a2-a1)) alerte${X}"

# --- CONTRAST -------------------------------------------------------------- #
banner "CONTRAST — IDS-ul nu sună din orice"
echo -e "  ${G}TRAFIC NORMAL${X} : $((a1-a0)) alerte"
echo -e "      ${DIM}(zeci de operații legitime, inclusiv get secrets / create token /"
echo -e "       create clusterrole — aceleași TIPURI de acțiuni ca atacurile)${X}"
echo -e "  ${R}ATAC${X}          : $((a2-a1)) alerte"
echo
echo -e "  ${BOLD}=> Modelul tace pe trafic legitim și reacționează la pattern-ul de atac,${X}"
echo -e "  ${BOLD}   nu la simpla prezență a unei acțiuni 'sensibile'.${X}"
kill "$SPID" 2>/dev/null || true
banner "DEMO CONTRAST COMPLET "
