#!/bin/bash
# Pipeline post-colectare: așteaptă ingestia LA, exportă (17 feats + poarta de stratificare),
# reantrenează XGBoost, rulează toate porțile de validare. Output complet pe stdout.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
CID=$(cat /tmp/ids_law_cid.txt)

echo "### [1] Aștept ingestia LA (poll recon_v2)..."
for i in $(seq 1 12); do
  sleep 45
  KQL="AzureDiagnostics | where TimeGenerated > datetime(2026-06-04T14:48:00Z) | where Category startswith 'kube-audit' | extend u=tostring(parse_json(log_s).user.username) | where u contains 'recon-v2-sa' | count"
  N=$(az rest --method post --url "https://api.loganalytics.io/v1/workspaces/$CID/query" --resource "https://api.loganalytics.io" --headers "Content-Type=application/json" --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "$KQL")" 2>/dev/null | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['tables'][0]['rows'][0][0])" 2>/dev/null || echo 0)
  echo "  [poll $i] recon-v2 events în LA: $N"
  if [ "$N" -gt 50 ] 2>/dev/null; then echo "  >> ingestie OK"; break; fi
done

echo; echo "### [2] EXPORT (17 feats + stratificare)"
python3 export_scale.py 2>&1 || { echo ">>> EXPORT A EȘUAT (stratificare?) — opresc."; exit 1; }

echo; echo "### [3] TRAIN XGBoost"
python3 train_xgb_audit.py 2>&1 || { echo ">>> TRAIN A EȘUAT."; exit 1; }

echo; echo "### [4] PORȚĂ leakage_xgb (anti-artefact)"
python3 leakage_xgb.py 2>&1

echo; echo "### [5] PORȚĂ overlap_check (suprapunere distribuții)"
python3 overlap_check.py 2>&1

echo; echo "### [6] CI episod + histerezis K"
python3 ci_episode.py 2>&1

echo; echo "### [7] HELD-OUT recon_v2 (tool-disjoint)"
python3 eval_heldout.py recon_v2_window.txt RECON_V2_START RECON_V2_END recon-v2-sa 2>&1

echo; echo "### GATA pipeline validare"
