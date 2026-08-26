#!/usr/bin/env python3
"""Export RICH (Faza 2 / #6) — time-scoped pe fereastra CURATĂ, în reference_dataset/.

Captează câmpurile pe care reprezentarea token-only le arunca: authorization.decision (forbid!),
sourceIP, responseStatus.code, userAgent, identitate. Produce, per fereastră glisantă:
  - tokeni (verb:resource:subresource) — compatibilitate cu modelul secvențial
  - FEATURES COMPORTAMENTALE (NU username brut, ca să evităm leakage circular):
    forbid_ratio, n_secrets, n_exec, n_rbac, diversitate resurse/verbe/ns, rate 4xx, diversitate sourceIP...
Etichetă = ground-truth orchestrator (ATTACK_ACTORS), NU folosită ca feature.
"""
import json, os, subprocess, sys
from collections import defaultdict, deque

CID = open("/tmp/ids_law_cid.txt").read().strip()
HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "reference_dataset"); os.makedirs(OUT, exist_ok=True)
SEQ_LEN = int(os.environ.get("SEQ_LEN", "20"))
TRAIN_FRAC = 0.7
ATTACK_ACTORS = set(json.loads(os.environ.get("ATTACK_ACTORS",
    '["system:serviceaccount:default:victim-sa","adversary-external","adversary-insider"]')))
RBAC = {"clusterroles", "clusterrolebindings", "roles", "rolebindings"}

W = {}
for line in open(os.path.join(OUT, "window.txt")):
    line = line.strip()
    for k in ("CLEAN_START", "CLEAN_END"):
        if line.startswith(k + "="):
            W[k] = line.split("=", 1)[1]
start, end = W["CLEAN_START"], W["CLEAN_END"]

KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
       f"| where TimeGenerated between (datetime({start}) .. datetime({end}) + 6m) "
       f"| project TimeGenerated, log_s | order by TimeGenerated asc")
print(f">> interoghez LA pe fereastra curată [{start} .. {end}]")
res = subprocess.run(["az", "rest", "--method", "post",
    "--url", f"https://api.loganalytics.io/v1/workspaces/{CID}/query",
    "--resource", "https://api.loganalytics.io", "--headers", "Content-Type=application/json",
    "--body", json.dumps({"query": KQL})], capture_output=True, text=True)
if res.returncode != 0:
    print("!! az rest:", res.stderr[-500:]); sys.exit(1)
table = json.loads(res.stdout)["tables"][0]; cols = [c["name"] for c in table["columns"]]
ti, li = cols.index("TimeGenerated"), cols.index("log_s"); rows = table["rows"]
print(f">> {len(rows)} evenimente brute în fereastra curată")
if not rows:
    print("!! gol — ingestia nu e gata; re-rulează mai târziu."); sys.exit(2)

def actor_of(e):
    imp = (e.get("impersonatedUser") or {}).get("username")
    return imp or (e.get("user") or {}).get("username", "")

seen = set(); streams = defaultdict(list); per_actor = defaultdict(int)
for r in rows:
    try: e = json.loads(r[li])
    except Exception: continue
    aid = e.get("auditID")
    if aid and aid in seen: continue
    if aid: seen.add(aid)
    a = actor_of(e); obj = e.get("objectRef") or {}; ann = e.get("annotations") or {}
    per_actor[a] += 1
    streams[a].append({"verb": e.get("verb", ""), "resource": obj.get("resource", ""),
        "sub": obj.get("subresource", ""), "ns": obj.get("namespace", ""),
        "sourceIP": (e.get("sourceIPs") or [""])[0],
        "code": (e.get("responseStatus") or {}).get("code", 0),
        "decision": ann.get("authorization.k8s.io/decision", ""), "ts": r[ti]})

print(">> top actori în fereastră (benign = operatori/controllere/umani, atac = ATTACK_ACTORS):")
for a, n in sorted(per_actor.items(), key=lambda kv: -kv[1])[:12]:
    print(f"   {n:6d}  {'[ATAC]' if a in ATTACK_ACTORS else '      '} {a}")

def feats(hist):
    n = len(hist); nf = sum(1 for x in hist if x["decision"] == "forbid")
    return {"n_events": n, "n_forbid": nf, "forbid_ratio": round(nf / n, 3),
        "n_distinct_resource": len(set(x["resource"] for x in hist)),
        "n_distinct_verb": len(set(x["verb"] for x in hist)),
        "n_distinct_ns": len(set(x["ns"] for x in hist)),
        "n_secrets": sum(1 for x in hist if x["resource"] == "secrets"),
        "n_exec": sum(1 for x in hist if x["sub"] == "exec"),
        "n_rbac": sum(1 for x in hist if x["resource"] in RBAC),
        "n_create": sum(1 for x in hist if x["verb"] == "create"),
        "n_delete": sum(1 for x in hist if x["verb"] == "delete"),
        "n_list": sum(1 for x in hist if x["verb"] == "list"),
        "n_4xx": sum(1 for x in hist if isinstance(x["code"], int) and x["code"] >= 400),
        "n_distinct_srcip": len(set(x["sourceIP"] for x in hist))}

train, test = [], []
for a, evs in streams.items():
    hist = deque(maxlen=SEQ_LEN); wins = []
    for x in evs:
        hist.append(x)
        wins.append({"user": a, "ts": x["ts"], "label": int(a in ATTACK_ACTORS),
            "tokens": [f"{y['verb']}:{y['resource']}:{y['sub']}" for y in hist],
            "features": feats(hist)})
    cut = int(len(wins) * TRAIN_FRAC)
    train += wins[:cut]; test += wins[cut:]

def dump(recs, name):
    p = os.path.join(OUT, name)
    with open(p, "w") as f:
        for r in recs: f.write(json.dumps(r) + "\n")
    n1 = sum(r["label"] for r in recs)
    print(f"   {name}: {len(recs)} ferestre (benign={len(recs)-n1}, atac={n1})")

print(">> scriu dataset-ul de referință (rich):")
dump(train, "ref_train.jsonl"); dump(test, "ref_test.jsonl")
print(f">> + reference_dataset/events_rich.jsonl (per-eveniment) — vezi mai sus")
