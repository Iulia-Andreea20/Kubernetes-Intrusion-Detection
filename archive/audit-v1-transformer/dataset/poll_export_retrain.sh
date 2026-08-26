#!/bin/bash
# Așteaptă ingestia LA (cei 12 actori noi), apoi export_finetune.py + retrain_pool.py (max-pool).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CID="$(cat /tmp/ids_law_cid.txt)"
start="$(grep BENIGN_START /tmp/ids_collect/windows.txt | cut -d= -f2)"
url="https://api.loganalytics.io/v1/workspaces/${CID}/query"

count_events () {
  local kql="AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') | where TimeGenerated > datetime(${start}) - 5m | extend u = tostring(parse_json(log_s).user.username) | where u matches regex '^(sre|devops|platform|system|security|backend|data|adversary)-' | count"
  az rest --method post --url "$url" --resource "https://api.loganalytics.io" \
    --headers "Content-Type=application/json" \
    --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "$kql")" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(int(json.load(sys.stdin)["tables"][0]["rows"][0][0]))
except Exception: print(0)'
}

prev=-1; ready=0; cnt=0
for i in $(seq 1 30); do
  cnt="$(count_events)"
  echo "[poll $i] evenimente actori în LA: $cnt"
  if [ "$cnt" -gt 0 ] 2>/dev/null && [ "$cnt" = "$prev" ]; then ready=1; echo ">> stabil ($cnt)"; break; fi
  prev="$cnt"; sleep 60
done
[ "$ready" = 1 ] || { echo "!! TIMEOUT ingestie (cnt=$cnt)"; exit 1; }

echo ""; echo "########## EXPORT ##########"
python3 "$HERE/export_finetune.py" || exit 1

echo ""; echo "########## RETRAIN max-pool ##########"
PY="$REPO/detection/bin/python3"; [ -x "$PY" ] || PY=python3
"$PY" "$HERE/retrain_pool.py" --pool max 2>&1 | grep -v "_nested_tensor\|Warning\|warn"
echo ""; echo "########## RETRAIN attention-pool ##########"
"$PY" "$HERE/retrain_pool.py" --pool attn 2>&1 | grep -v "_nested_tensor\|Warning\|warn"
