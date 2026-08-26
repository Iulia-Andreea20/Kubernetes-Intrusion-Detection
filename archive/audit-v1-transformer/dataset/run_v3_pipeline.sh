#!/bin/bash
# Testul #2-fix complet: poll LA -> export -> verifică ruperea vocabularului -> retrain -> leakage analysis.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../.." && pwd)"
CID="$(cat /tmp/ids_law_cid.txt)"
start="$(grep BENIGN_START /tmp/ids_collect/windows.txt | cut -d= -f2)"
url="https://api.loganalytics.io/v1/workspaces/${CID}/query"
PY="$REPO/detection/bin/python3"; [ -x "$PY" ] || PY=python3

count(){ az rest --method post --url "$url" --resource "https://api.loganalytics.io" --headers "Content-Type=application/json" \
  --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' \
  "AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') | where TimeGenerated > datetime(${start}) - 5m | extend u=tostring(parse_json(log_s).user.username) | where u matches regex '^(sre|devops|platform|system|security|backend|data|adversary)-' | count")" 2>/dev/null \
  | python3 -c 'import json,sys
try: print(int(json.load(sys.stdin)["tables"][0]["rows"][0][0]))
except Exception: print(0)'; }

prev=-1
for i in $(seq 1 30); do c="$(count)"; echo "[poll $i] evenimente: $c"
  if [ "$c" -gt 0 ] 2>/dev/null && [ "$c" = "$prev" ]; then echo ">> stabil ($c)"; break; fi
  prev="$c"; sleep 60; done

echo ""; echo "########## EXPORT v3 ##########"
python3 "$HERE/export_finetune.py" || exit 1

echo ""; echo "########## VERIFICARE: tokeni-semnătură benign vs atac (după fix) ##########"
python3 <<PY
import json
from collections import defaultdict
allr=[json.loads(l) for l in open("$HERE/cloud_train.jsonl")]+[json.loads(l) for l in open("$HERE/cloud_test.jsonl")]
sig=["get:secrets:","list:secrets:","create:clusterrolebindings:","create:serviceaccounts:token","create:serviceaccounts:","create:pods:"]
c=defaultdict(lambda:[0,0])
for r in allr:
    for s in set(r["tokens"]):
        if s in sig: c[s][r["label"]]+=1
print(f"  {'token':32s} BENIGN  ATAC")
for s in sig: print(f"  {s:32s} {c[s][0]:>5}  {c[s][1]:>5}")
PY

echo ""; echo "########## RETRAIN max-pool pe noul dataset ##########"
"$PY" "$HERE/retrain_pool.py" --pool max 2>&1 | grep -vE "_nested_tensor|Warning|warn"

echo ""; echo "########## LEAKAGE ANALYSIS (model nou vs keyword vs identitate) ##########"
"$PY" "$HERE/leakage_analysis.py" 2>&1 | grep -vE "_nested_tensor|Warning|warn"
