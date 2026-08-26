#!/bin/bash
# Pipeline SCALĂ: colectare N sesiuni -> poll ingestie -> export sesiune-disjoint -> XGBoost -> recall pe profiluri (incl. stealth).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../.." && pwd)"
PY="$REPO/detection/bin/python3"; [ -x "$PY" ] || PY=python3
N="${N:-6}"; CID="$(cat /tmp/ids_law_cid.txt)"
url="https://api.loganalytics.io/v1/workspaces/${CID}/query"

echo "########## COLECTARE SCALĂ ($N sesiuni) ##########"
N="$N" bash "$HERE/scale_collect.sh" 2>&1 | grep -E "SESIUNE|sesiune .* gata|GATA scale"

g0=$(grep "SESSION 1 START" "$HERE/reference_dataset/sessions.txt" | awk '{print $4}')
prev=-1
for i in $(seq 1 25); do
  c=$(az rest --method post --url "$url" --resource "https://api.loganalytics.io" --headers "Content-Type=application/json" \
    --body "$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') | where TimeGenerated > datetime(${g0}) | extend u=tostring(parse_json(log_s).user.username) | where u in ('adversary-external','adversary-insider') | count")" 2>/dev/null \
    | python3 -c 'import json,sys
try:print(int(json.load(sys.stdin)["tables"][0]["rows"][0][0]))
except:print(0)')
  echo "[poll $i] evenimente atac ingerate: $c"
  if [ "${c:-0}" -gt 0 ] 2>/dev/null && [ "$c" = "$prev" ]; then echo ">> stabil ($c)"; break; fi
  prev="$c"; sleep 60
done

echo ""; echo "########## EXPORT SCALĂ (sesiune-disjoint) ##########"
python3 "$HERE/export_scale.py" || exit 1

echo ""; echo "########## TRAIN XGBoost ##########"
"$PY" "$HERE/train_xgb_audit.py" 2>&1 | grep -vE "Warning|warn"

echo ""; echo "########## RECALL pe profiluri în TEST (incl. low-and-slow) ##########"
"$PY" - "$HERE" "$REPO" <<'PY' 2>&1 | grep -vE "Warning|warn"
import csv, sys
import numpy as np, xgboost as xgb
HERE, REPO = sys.argv[1], sys.argv[2]
rows=list(csv.reader(open(f"{HERE}/reference_dataset/ref_test.csv")))[1:]
X=np.array([[float(c) for c in r[1:15]] for r in rows]); y=np.array([int(r[0]) for r in rows]); users=[r[15] for r in rows]
clf=xgb.XGBClassifier(); clf.load_model(f"{REPO}/data/models/audit_api_xgb/model.json")
pred=(clf.predict_proba(X)[:,1]>=0.5).astype(int)
print(f"  benign FPR: {pred[y==0].mean()*100:.1f}%  ({int(pred[y==0].sum())}/{int((y==0).sum())})")
for grp,lbl in [("adversary-external","DENS valid-abuzat"),("system:serviceaccount:default:victim-sa","DENS token-furat"),("adversary-insider","LOW-AND-SLOW")]:
    idx=[i for i,u in enumerate(users) if u==grp and y[i]==1]
    if idx: print(f"  recall {lbl:20s} ({grp}): {sum(int(pred[i]) for i in idx)}/{len(idx)} = {100*sum(int(pred[i]) for i in idx)/len(idx):.1f}%")
PY
echo "GATA pipeline scală."
