#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-serve}"

case "$ROLE" in
  train)
    echo "[IDS] running trainer…"
    exec python ids_pipeline.py
    ;;
  serve)
    echo "[IDS] running scorer API…"
    exec uvicorn server:app --host 0.0.0.0 --port 8000
    ;;
  *)
    echo "Usage: $0 [train|serve]"
    exit 1
    ;;
esac
