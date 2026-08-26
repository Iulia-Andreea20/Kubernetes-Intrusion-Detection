#!/bin/bash
# Așteaptă ingestia LA (alice/dev/mallory stabile), apoi export_finetune.py + fine_tune.py.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CID="$(cat /tmp/ids_law_cid.txt)"
start="$(grep BENIGN_START /tmp/ids_collect/windows.txt | cut -d= -f2)"
url="https://api.loganalytics.io/v1/workspaces/${CID}/query"

count_events () {
  local kql="AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') | where TimeGenerated > datetime(${start}) - 5m | extend u = tostring(parse_json(log_s).user.username) | where u in ('alice','dev','mallory') | count"
  az rest --method post --url "$url" --resource "https://api.loganalytics.io" \
    --headers "Content-Type=application/json" \
    --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "$kql")" 2>/dev/null \
    | python3 -c 'import json,sys
try:
    print(int(json.load(sys.stdin)["tables"][0]["rows"][0][0]))
except Exception: print(0)'
}

prev=-1; ready=0; cnt=0
for i in $(seq 1 30); do
  cnt="$(count_events)"
  echo "[poll $i] evenimente alice/dev/mallory în LA: $cnt"
  if [ "$cnt" -gt 0 ] 2>/dev/null && [ "$cnt" = "$prev" ]; then
    ready=1; echo ">> ingestie stabilă ($cnt) — export + fine-tuning"; break
  fi
  prev="$cnt"; sleep 60
done

if [ "$ready" != 1 ]; then
  echo "!! TIMEOUT ingestie (cnt=$cnt). Re-rulează manual."; exit 1
fi

echo ""; echo "########## EXPORT (cloud_train/cloud_test) ##########"
python3 "$HERE/export_finetune.py" || exit 1

echo ""; echo "########## FINE-TUNING ##########"
PY="$REPO/detection/bin/python3"; [ -x "$PY" ] || PY=python3
"$PY" "$HERE/fine_tune.py" 2>&1 | grep -v "_nested_tensor\|Warning\|warn"
