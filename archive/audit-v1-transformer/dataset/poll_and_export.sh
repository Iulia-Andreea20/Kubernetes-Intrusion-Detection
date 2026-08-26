#!/bin/bash
# Așteaptă ingestia LA (verifică la 60s dacă evenimentele alice/mallory au sosit
# și s-au stabilizat), apoi rulează export_dataset.py automat.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CID="$(cat /tmp/ids_law_cid.txt)"
start="$(grep BENIGN_START /tmp/ids_collect/windows.txt | cut -d= -f2)"
url="https://api.loganalytics.io/v1/workspaces/${CID}/query"

count_events () {
  local kql="AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') | where TimeGenerated > datetime(${start}) - 5m | extend u = tostring(parse_json(log_s).user.username) | where u in ('alice','mallory') | count"
  az rest --method post --url "$url" --resource "https://api.loganalytics.io" \
    --headers "Content-Type=application/json" --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "$kql")" 2>/dev/null \
    | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(int(d["tables"][0]["rows"][0][0]))
except Exception: print(0)'
}

prev=-1; ready=0
for i in $(seq 1 30); do
  cnt="$(count_events)"
  echo "[poll $i] evenimente alice/mallory ingerate în LA: $cnt"
  if [ "$cnt" -gt 0 ] 2>/dev/null && [ "$cnt" = "$prev" ]; then
    ready=1; echo ">> ingestie stabilă ($cnt evenimente) — exportez"; break
  fi
  prev="$cnt"
  sleep 60
done

if [ "$ready" = 1 ]; then
  python3 "$HERE/export_dataset.py"
else
  echo "!! TIMEOUT: ingestia LA nu s-a stabilizat în ~30 min (cnt=$cnt). Re-rulează manual export_dataset.py."
fi
