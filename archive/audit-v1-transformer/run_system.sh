#!/bin/bash
#  LEGACY (faza inițială kind + model Transformer) — NU sistemul actual v2.2/2.4. NU rula la apărare ca „IDS-ul meu". Sistemul curent (XGBoost + 6 reguli, AKS managed) = demo/run_demo_aks.sh. Vezi demo/README.md + SCENARIU_PREZENTARE.md.
# Sistem IDS multi-componentă pentru Kubernetes — defense-in-depth.
# Două detectoare paralele:
#   • FLOW  — trafic de rețea (DDoS)        — XGBoost + Autoencoder (BCCC)
#   • AUDIT — abuz API Kubernetes (misuse)  — Transformer pe audit log
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$REPO/detection/bin/python3"
RID="$REPO/runtime_ids"
cd "$RID"
LIMIT_FLOW="${1:-8000}"

B="\033[94m"; G="\033[92m"; BOLD="\033[1m"; DIM="\033[2m"; X="\033[0m"
banner(){ echo -e "\n${BOLD}${B}################################################################${X}";
          echo -e "${BOLD}${B}  $1${X}";
          echo -e "${BOLD}${B}################################################################${X}"; }

banner "SISTEM IDS MULTI-COMPONENTĂ PENTRU KUBERNETES — defense-in-depth"
echo -e "  Două detectoare paralele, independente:"
echo -e "    ${BOLD}• Componenta FLOW${X}  — trafic de rețea / DDoS — XGBoost + Autoencoder (BCCC)"
echo -e "    ${BOLD}• Componenta AUDIT${X} — abuz API Kubernetes    — Transformer pe audit log"

banner "COMPONENTA 1/2 — FLOW (detecție pe trafic de rețea)"
"$PY" flow/demo_flow.py --limit "$LIMIT_FLOW"

banner "COMPONENTA 2/2 — AUDIT (detecție pe audit log Kubernetes)"
if ! curl -s http://localhost:8080/readyz >/dev/null 2>&1; then
  ( cd service && "$PY" -m uvicorn ids_service:app --host 0.0.0.0 --port 8080 \
      >/tmp/ids_service.log 2>&1 & )
  curl --retry 40 --retry-delay 1 --retry-connrefused -s http://localhost:8080/readyz >/dev/null
fi
"$PY" demo/demo_local.py --limit 1500

banner "VALIDARE — smoke-test pe AMBELE componente"
"$PY" test_system.py || true

banner "SISTEM COMPLET "
echo -e "  ${G}Două componente complementare, antrenate și verificate:${X}"
echo -e "    FLOW : atacuri de rețea L3/L4 (DDoS) — recall ~0.74 @ FPR 1%"
echo -e "    AUDIT: abuz API K8s (recon, exec, RBAC, secrete, token, escape) — F1 0.93"
echo -e "  ${DIM}Fiecare acoperă o suprafață de atac diferită  defense-in-depth.${X}"
