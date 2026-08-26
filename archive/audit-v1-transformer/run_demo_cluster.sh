#!/bin/bash
#  LEGACY (faza inițială kind + model Transformer) — NU sistemul actual v2.2/2.4. NU rula la apărare ca „IDS-ul meu". Sistemul curent (XGBoost + 6 reguli, AKS managed) = demo/run_demo_aks.sh. Vezi demo/README.md + SCENARIU_PREZENTARE.md.
# Demo LIVE pe cluster kind — Componenta Audit (IDS runtime Kubernetes).
#
# Lanțul complet, pe infrastructură reală:
#   cluster kind    atacuri kubectl reale    audit log    streamer
#     serviciu IDS (/predict)    ALERTE LIVE cu severitate
#
# Reutilizează clusterul 'runtime-ids' dacă există; altfel îl creează.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$REPO/detection/bin/python3"
RID="$REPO/runtime_ids"
cd "$RID"
CTX="kind-runtime-ids"
SLOG="/tmp/ids_streamer_demo.log"

B="\033[94m"; G="\033[92m"; R="\033[91m"; BOLD="\033[1m"; DIM="\033[2m"; X="\033[0m"
banner(){ echo -e "\n${BOLD}${B}================================================================${X}";
          echo -e "${BOLD}${B}  $1${X}";
          echo -e "${BOLD}${B}================================================================${X}"; }

# --- 1. serviciu ----------------------------------------------------------- #
banner "1. Serviciu IDS"
if ! curl -s http://localhost:8080/readyz >/dev/null 2>&1; then
  echo ">> pornesc serviciul..."
  ( cd service && "$PY" -m uvicorn ids_service:app --host 0.0.0.0 --port 8080 \
      >/tmp/ids_service.log 2>&1 & )
  curl --retry 40 --retry-delay 1 --retry-connrefused -s http://localhost:8080/readyz >/dev/null
fi
echo -e "${G} serviciu activ pe :8080${X}"

# --- 2. cluster ------------------------------------------------------------ #
banner "2. Cluster Kubernetes (kind)"
if ! kind get clusters 2>/dev/null | grep -qx runtime-ids; then
  echo ">> clusterul nu există — îl creez (poate dura 1-2 min)..."
  ./cluster/setup_kind.sh
else
  echo -e "${G} cluster 'runtime-ids' există — îl refolosesc${X}"
fi
kubectl --context "$CTX" get nodes 2>/dev/null | tail -n +1

# --- 3. streamer ----------------------------------------------------------- #
banner "3. Streamer (tail audit.log  serviciu /predict)"
pkill -f "audit_streamer.py" 2>/dev/null || true
: > "$SLOG"
RUNTIME_IDS_AUDIT_LOG=audit-logs/audit.log \
RUNTIME_IDS_SERVICE_URL=http://localhost:8080 \
RUNTIME_IDS_STREAMER_METRICS_PORT=9091 \
  "$PY" streamer/audit_streamer.py >"$SLOG" 2>&1 &
SPID=$!
curl --retry 15 --retry-delay 1 --retry-connrefused -s http://localhost:9091/metrics >/dev/null 2>&1
echo -e "${G} streamer activ${X} (PID $SPID, log: $SLOG)"

# --- 4. atacuri ------------------------------------------------------------ #
banner "4. Atacuri reale pe cluster (scenarii MITRE ATT&CK)"
cp data/labels.jsonl data/labels.jsonl.bak 2>/dev/null || true
for sc in scenario_recon scenario_secret_access scenario_sa_token \
          scenario_malicious_pod scenario_rbac_escalation; do
  echo -e "  ${DIM}>> $sc${X}"
  bash attacks/attack_scenarios.sh "$sc"
done
# lasă streamerul să termine de procesat liniile noi
"$PY" -c "import time; time.sleep(3)"

# --- 5. alerte detectate live ---------------------------------------------- #
banner "5. ALERTE DETECTATE LIVE de model"
"$PY" - "$SLOG" <<'PYEOF'
import json, sys
lines = [l for l in open(sys.argv[1]) if '"ids_alert"' in l]
print(f"  \033[91m\033[1m{len(lines)} alerte\033[0m ridicate de model pe traficul de atac live.\n")
print("  Ultimele detecții (severitate · probabilitate · secvență de token-uri):")
for l in lines[-10:]:
    try:
        d = json.loads(l).get("msg", {})
    except Exception:
        continue
    if d.get("event") != "ids_alert":
        continue
    toks = "  ".join(d.get("tokens_tail", []))
    print(f"    \033[91m[{d['severity']:8s}]\033[0m p={d['probability']:.3f}  \033[2m{toks}\033[0m")
PYEOF
echo
echo "  Metrici streamer:"
curl -s http://localhost:9091/metrics | grep -E "audit_streamer_(events|alerts)_total" \
  | grep -v "^#" | sed 's/^/    /'

# --- 6. cleanup ------------------------------------------------------------ #
kill "$SPID" 2>/dev/null || true
banner "DEMO LIVE COMPLET   (cluster real  atac  audit  detecție live)"
echo -e "${DIM}Clusterul rămâne pornit. Oprire: kind delete cluster --name runtime-ids${X}"
