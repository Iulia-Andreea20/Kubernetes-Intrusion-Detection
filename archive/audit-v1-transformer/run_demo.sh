#!/bin/bash
#  LEGACY (faza inițială kind + model Transformer) — NU sistemul actual v2.2/2.4. NU rula la apărare ca „IDS-ul meu". Sistemul curent (XGBoost + 6 reguli, AKS managed) = demo/run_demo_aks.sh. Vezi demo/README.md + SCENARIU_PREZENTARE.md.
# Demo local end-to-end — Componenta Audit (IDS runtime pentru Kubernetes).
# Pornește serviciul IDS (dacă nu rulează deja) și rulează demo-ul.
#
#   ./demo/run_demo.sh                # complet (~75s)
#   ./demo/run_demo.sh --delay 0.2    # cu pauze, pentru prezentare live
#   ./demo/run_demo.sh --limit 1000   # rapid, pe un eșantion (~10s)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$REPO/detection/bin/python3"
cd "$REPO/runtime_ids"

if ! curl -s http://localhost:8080/readyz >/dev/null 2>&1; then
  echo ">> Pornesc serviciul IDS (uvicorn :8080)..."
  ( cd service && "$PY" -m uvicorn ids_service:app --host 0.0.0.0 --port 8080 \
      >/tmp/ids_service.log 2>&1 & )
  echo ">> Aștept serviciul..."
  curl --retry 40 --retry-delay 1 --retry-connrefused -s http://localhost:8080/readyz >/dev/null
  echo ">> Serviciu gata (log: /tmp/ids_service.log)."
else
  echo ">> Serviciul rulează deja."
fi

echo ">> Rulez demo-ul..."
exec "$PY" demo/demo_local.py "$@"
