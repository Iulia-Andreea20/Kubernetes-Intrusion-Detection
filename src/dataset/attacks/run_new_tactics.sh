#!/usr/bin/env bash
# Collect the synthetic credential-access and persistence tactics, then rebuild and re-score the set.
#
#   --collect   run the attacks (needs a running cluster); they append to sessions.txt
#   --export    after the Log Analytics ingestion lag, re-export the CSV and re-evaluate
#
# export_v2.py shells out to `az`, which breaks inside the project venv, so the export runs without
# it and only the evaluation runs with it.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
hr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

case "${1:-}" in
  --collect)
    hr "1 - running the new attack scenarios"
    bash "$HERE/attack_credaccess_syn.sh"
    bash "$HERE/attack_persistence_syn.sh"
    echo ""
    echo ">> collected; new sessions appended to sessions.txt"
    echo ">> wait ~5 min for Log Analytics ingestion, then: bash $HERE/run_new_tactics.sh --export"
    ;;
  --export)
    hr "2a - re-exporting the dataset from Log Analytics"
    ( cd "$REPO/src/dataset/export" && python export_v2.py ) \
      || { echo "!! export failed - check LA_WORKSPACE_ID and that the cluster is up"; exit 1; }
    hr "2b - re-evaluating"
    ( cd "$REPO" && source detection/bin/activate 2>/dev/null; python src/model/eval/eval_model_only_standalone.py )
    echo ""
    echo ">> to retrain the deployed model:"
    echo "   cd $REPO && source detection/bin/activate && python src/model/train/train_production.py"
    ;;
  *)
    echo "usage:"
    echo "  $0 --collect   run the new attacks"
    echo "  $0 --export    re-export from Log Analytics and re-evaluate"
    ;;
esac
