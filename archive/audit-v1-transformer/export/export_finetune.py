#!/usr/bin/env python3
"""Export kube-audit din LA -> cloud_train.jsonl + cloud_test.jsonl (format sequences.jsonl).

Ferestre glisante de 20 (padate la stânga cu <PAD>, exact ca dataset-ul original),
etichetare pe actor (alice/dev=0, mallory=1), split TEMPORAL 70/30 PER ACTOR
(astfel încât atât train cât și test conțin și benign și atac).
"""
import json
import os
import subprocess
import sys
from collections import defaultdict, deque

CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = int(os.environ.get("SEQ_LEN", "20"))
HERE = os.path.dirname(__file__)
TRAIN_FRAC = 0.7
BENIGN = ["sre-oncall", "sre-reliability", "devops-pipeline", "devops-release",
          "platform-engineer", "platform-networking", "system-administrator",
          "security-auditor", "backend-developer", "data-engineer",
          "platform-admin"]   # benign, dar produce LEGITIM tokenii-semnătură (test #2-fix)
ATTACK = ["adversary-external", "adversary-insider"]
LABELS = {**{a: 0 for a in BENIGN}, **{a: 1 for a in ATTACK}}
ATTACK_TYPE = {**{a: "" for a in BENIGN},
               "adversary-external": "external_compromise",
               "adversary-insider": "insider_threat"}

W = {}
for line in open("/tmp/ids_collect/windows.txt"):
    line = line.strip()
    for k in ("BENIGN_START", "ATTACK_END", "PA_MAL_START", "PA_MAL_END"):
        if line.startswith(k + "="):
            W[k] = line.split("=", 1)[1]
start, end = W["BENIGN_START"], W["ATTACK_END"]
PA_S, PA_E = W.get("PA_MAL_START", "")[:19], W.get("PA_MAL_END", "")[:19]  # #2-partea-2: dual-rol pe timp

KQL = (
    "AzureDiagnostics "
    "| where Category in ('kube-audit','kube-audit-admin') "
    f"| where TimeGenerated between (datetime({start}) - 2m .. datetime({end}) + 8m) "
    "| project TimeGenerated, log_s | order by TimeGenerated asc"
)
print(f">> interoghez LA (workspace {CID})...")
res = subprocess.run(
    ["az", "rest", "--method", "post",
     "--url", f"https://api.loganalytics.io/v1/workspaces/{CID}/query",
     "--resource", "https://api.loganalytics.io",
     "--headers", "Content-Type=application/json",
     "--body", json.dumps({"query": KQL})],
    capture_output=True, text=True)
if res.returncode != 0:
    print("!! az rest a eșuat:\n", res.stderr[-800:]); sys.exit(1)
table = json.loads(res.stdout)["tables"][0]
cols = [c["name"] for c in table["columns"]]
ti, li = cols.index("TimeGenerated"), cols.index("log_s")
rows = table["rows"]
print(f">> {len(rows)} rânduri brute")
if not rows:
    print("!! niciun rând — ingestia LA nu e gata. Re-rulează mai târziu."); sys.exit(2)

def actor_of(e):
    imp = (e.get("impersonatedUser") or {}).get("username")
    return imp or (e.get("user") or {}).get("username", "")

seen = set()
streams = defaultdict(list)
counts = defaultdict(int)
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
    a = actor_of(e)
    counts[a] += 1
    if a not in LABELS:
        continue
    obj = e.get("objectRef") or {}
    tok = f"{e.get('verb','')}:{obj.get('resource','')}:{obj.get('subresource','')}"
    streams[a].append((r[ti], tok))

print(">> evenimente per actor (cei etichetați):")
for a in LABELS:
    print(f"   {a:8s} {len(streams.get(a, [])):5d}")

def windows(evs):
    hist = deque(maxlen=SEQ_LEN)
    out = []
    for ts, tok in evs:
        hist.append(tok)
        padded = ["<PAD>"] * (SEQ_LEN - len(hist)) + list(hist)
        out.append((ts, padded))
    return out

def add_split(sub, a, lab, atk, train, test):
    cut = int(len(sub) * TRAIN_FRAC)
    for i, (ts, toks) in enumerate(sub):
        rec = {"timestamp": ts, "user": a, "tokens": toks, "label": lab, "attack_type": atk}
        (train if i < cut else test).append(rec)

train, test = [], []
for a, evs in streams.items():
    wins = windows(evs)
    if a == "platform-admin" and PA_S:   # actor DUAL-ROL: etichetare cauzală pe timp
        ben = [(ts, t) for ts, t in wins if not (PA_S <= str(ts)[:19] <= PA_E)]
        mal = [(ts, t) for ts, t in wins if PA_S <= str(ts)[:19] <= PA_E]
        add_split(ben, a, 0, "", train, test)                       # munca legitimă -> benign
        add_split(mal, a, 1, "compromised_operator", train, test)   # lanțul de atac -> atac (aceeași identitate)
    else:
        add_split(wins, a, LABELS[a], ATTACK_TYPE[a], train, test)

def dedup(recs):
    """Elimină ferestrele identice (același șir de tokeni + etichetă) — evită inflația."""
    seen, out = set(), []
    for r in recs:
        key = (r["label"], tuple(r["tokens"]))
        if key in seen:
            continue
        seen.add(key); out.append(r)
    return out

before = (len(train), len(test))
train, test = dedup(train), dedup(test)
print(f">> dedup ferestre: train {before[0]}->{len(train)}, test {before[1]}->{len(test)}")

def dump(recs, name):
    p = os.path.join(HERE, name)
    with open(p, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    n1 = sum(r["label"] for r in recs)
    print(f"   {name}: {len(recs)} ferestre  (benign={len(recs)-n1}, atac={n1})")
    return p

print(">> scriu dataset-urile cloud:")
dump(train, "cloud_train.jsonl")
dump(test, "cloud_test.jsonl")
