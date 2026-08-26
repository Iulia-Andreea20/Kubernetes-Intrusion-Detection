#!/usr/bin/env python3
"""Export kube-audit din Log Analytics -> dataset AKS etichetat.

Interoghează LA (prin `az rest`, ca să ocolim modulul `az monitor` stricat local),
parsează evenimentele de audit în tokeni verb:resource:subresource, le grupează pe
actor și construiește ferestre glisante de SEQ_LEN — exact cum face adapterul la runtime
(o fereastră per eveniment). Etichetare pe actor: alice=0 (benign), mallory=1 (atac).

Rulează DUPĂ ce a trecut lag-ul de ingestie al LA (~5-15 min de la generarea activității).
"""
import json
import os
import subprocess
import sys
from collections import defaultdict, deque

CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = int(os.environ.get("SEQ_LEN", "20"))
OUT = os.environ.get("OUT", os.path.join(os.path.dirname(__file__), "aks_audit_dataset.jsonl"))
LABELS = {"alice": 0, "mallory": 1}   # actorii noștri etichetați

# ferestre de timp generate de scripturile de activitate
W = {}
for line in open("/tmp/ids_collect/windows.txt"):
    line = line.strip()
    for k in ("BENIGN_START", "BENIGN_END", "ATTACK_START", "ATTACK_END"):
        if line.startswith(k + "="):
            W[k] = line.split("=", 1)[1]
start, end = W["BENIGN_START"], W["ATTACK_END"]

KQL = (
    "AzureDiagnostics "
    "| where Category in ('kube-audit','kube-audit-admin') "
    f"| where TimeGenerated between (datetime({start}) - 2m .. datetime({end}) + 6m) "
    "| project TimeGenerated, log_s "
    "| order by TimeGenerated asc"
)

print(f">> interoghez Log Analytics (workspace {CID})...")
url = f"https://api.loganalytics.io/v1/workspaces/{CID}/query"
res = subprocess.run(
    ["az", "rest", "--method", "post", "--url", url,
     "--resource", "https://api.loganalytics.io",
     "--headers", "Content-Type=application/json",
     "--body", json.dumps({"query": KQL})],
    capture_output=True, text=True)
if res.returncode != 0:
    print("!! az rest a eșuat:\n", res.stderr[-800:]); sys.exit(1)

data = json.loads(res.stdout)
table = data["tables"][0]
cols = [c["name"] for c in table["columns"]]
ti, li = cols.index("TimeGenerated"), cols.index("log_s")
rows = table["rows"]
print(f">> {len(rows)} rânduri brute de audit returnate")
if not rows:
    print("!! NICIUN rând — probabil ingestia LA nu e gata încă. Mai așteaptă câteva minute și re-rulează.")
    sys.exit(2)

# parse evenimente -> token per actor, dedup pe auditID
def actor_of(e):
    imp = (e.get("impersonatedUser") or {}).get("username")
    return imp or (e.get("user") or {}).get("username", "")

seen = set()
streams = defaultdict(list)   # actor -> [(ts, token)]
all_actors = defaultdict(int)
for r in rows:
    try:
        e = json.loads(r[li])
    except Exception:
        continue
    aid = e.get("auditID")
    if aid and aid in seen:
        continue
    if aid:
        seen.add(aid)
    actor = actor_of(e)
    all_actors[actor] += 1
    if actor not in LABELS:
        continue
    obj = e.get("objectRef") or {}
    token = f"{e.get('verb','')}:{obj.get('resource','')}:{obj.get('subresource','')}"
    streams[actor].append((r[ti], token))

print("\n>> evenimente per actor (top 8):")
for a, n in sorted(all_actors.items(), key=lambda kv: -kv[1])[:8]:
    mark = "  <-- ETICHETAT" if a in LABELS else ""
    print(f"   {n:5d}  {a}{mark}")

# ferestre glisante (mirror runtime) + scriere dataset
samples = []
for actor, evs in streams.items():
    hist = deque(maxlen=SEQ_LEN)
    for _ts, token in evs:
        hist.append(token)
        samples.append({"actor": actor, "label": LABELS[actor], "tokens": list(hist)})

with open(OUT, "w") as f:
    for s in samples:
        f.write(json.dumps(s) + "\n")

n_ben = sum(1 for s in samples if s["label"] == 0)
n_atk = sum(1 for s in samples if s["label"] == 1)
print(f"\n>> dataset scris: {OUT}")
print(f"   ferestre benigne (alice):  {n_ben}")
print(f"   ferestre atac    (mallory): {n_atk}")
print(f"   tokeni unici alice:  {sorted(set(t for s in samples if s['label']==0 for t in s['tokens']))[:12]}")
print(f"   tokeni unici mallory:{sorted(set(t for s in samples if s['label']==1 for t in s['tokens']))[:15]}")
