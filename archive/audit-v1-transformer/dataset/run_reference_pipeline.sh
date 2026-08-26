#!/bin/bash
# poll ingestie LA (fereastra curată) -> export_rich -> CSV -> train_xgb_audit. Pe ambele profiluri de atac.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../.." && pwd)"
PY="$REPO/detection/bin/python3"; [ -x "$PY" ] || PY=python3
CID="$(cat /tmp/ids_law_cid.txt)"
start="$(grep CLEAN_START "$HERE/reference_dataset/window.txt" | cut -d= -f2)"
url="https://api.loganalytics.io/v1/workspaces/${CID}/query"

prev=-1
for i in $(seq 1 25); do
  c=$(az rest --method post --url "$url" --resource "https://api.loganalytics.io" --headers "Content-Type=application/json" \
    --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') | where TimeGenerated > datetime(${start}) | extend u=tostring(parse_json(log_s).user.username) | where u=='system:serviceaccount:default:victim-sa' or u=='adversary-external' | count")" 2>/dev/null \
    | python3 -c 'import json,sys
try:print(int(json.load(sys.stdin)["tables"][0]["rows"][0][0]))
except:print(0)')
  echo "[poll $i] evenimente atac ingerate: $c"
  if [ "${c:-0}" -gt 0 ] 2>/dev/null && [ "$c" = "$prev" ]; then echo ">> stabil ($c)"; break; fi
  prev="$c"; sleep 60
done

echo ""; echo "########## EXPORT RICH ##########"
python3 "$HERE/export_rich.py" || exit 1

echo ""; echo "########## CSV ##########"
cd "$HERE/reference_dataset"
python3 <<'PY'
import json, csv
FEATS=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns",
       "n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_distinct_srcip"]
for split in ("train","test"):
    rows=[json.loads(l) for l in open(f"ref_{split}.jsonl")]
    with open(f"ref_{split}.csv","w",newline="") as f:
        w=csv.writer(f); w.writerow(["label"]+FEATS+["user"])
        for r in rows: w.writerow([r["label"]]+[r["features"].get(k,"") for k in FEATS]+[r["user"]])
    print(f"  ref_{split}.csv: {len(rows)} rânduri")
PY
cd "$REPO"

echo ""; echo "########## TRAIN XGBoost (2 profiluri) ##########"
"$PY" "$HERE/train_xgb_audit.py" 2>&1 | grep -vE "Warning|warn"
