#!/usr/bin/env python3
"""Feeds the detector on AKS, where the audit log is not a file.

A managed control plane gives you no node to tail, so kube-audit goes to Log Analytics instead.
This polls it over KQL, rebuilds per-actor event histories and POSTs them to /predict/raw. On a
self-managed cluster the file-based streamer does the same job.

Parsing here mirrors dataset/export/export_v2.py: the window is keyed on the authenticated user,
with any impersonation carried in imp/is_imp. service accounts are deliberately not skipped -
that is exactly where the attacks live.

Env:
  LA_WORKSPACE_ID          Log Analytics workspace GUID (customerId)
  RUNTIME_IDS_SERVICE_URL  detector endpoint, e.g. http://ids-service-xgb:8080
  POLL_INTERVAL            seconds between queries (default 15)
  LOOKBACK_MIN             query window in minutes (default 10)
  RUNTIME_IDS_SEQ_LEN      per-actor window length (default 20)

Auth is DefaultAzureCredential - managed identity in-cluster, service principal or `az login`
locally. The identity needs the Log Analytics Reader role.

Detection is not sub-second: Log Analytics ingestion lags by minutes. Event Hub would close that
gap at the cost of more infrastructure.
"""
import json
import logging
import os
import time
from collections import defaultdict, deque
from datetime import timedelta

import requests
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

WORKSPACE = os.environ["LA_WORKSPACE_ID"]
SERVICE = os.environ.get("RUNTIME_IDS_SERVICE_URL", "http://ids-service-xgb:8080")
POLL = float(os.environ.get("POLL_INTERVAL", "15"))
LOOKBACK_MIN = float(os.environ.get("LOOKBACK_MIN", "10"))
SEQ_LEN = int(os.environ.get("RUNTIME_IDS_SEQ_LEN", "20"))

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger("azure").setLevel(logging.WARNING)   # the Azure SDK logs every HTTP call otherwise
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
log = logging.getLogger("audit-adapter")

QUERY = (
    "AzureDiagnostics "
    "| where Category == 'kube-audit' "
    "| where TimeGenerated > ago({lb}m) "
    "| project TimeGenerated, log_s "
    "| order by TimeGenerated asc"
)

def event_to_record(e: dict):
    """Flatten one audit event, keyed on the authenticated user rather than the impersonated one."""
    real = (e.get("user") or {}).get("username", "")
    imp = ((e.get("impersonatedUser") or {}).get("username") or "")
    is_imp = 1 if (imp and imp != real) else 0
    actor = real or imp
    if not actor:
        return None
    o = e.get("objectRef") or {}
    ann = e.get("annotations") or {}
    rec = {
        "verb": e.get("verb", ""),
        "resource": o.get("resource", ""),
        "sub": o.get("subresource", ""),
        "ns": o.get("namespace", ""),
        "code": (e.get("responseStatus") or {}).get("code", 0),
        "decision": ann.get("authorization.k8s.io/decision", ""),
        "imp": imp if is_imp else "",
        "is_imp": is_imp,
    }
    return actor, rec, e.get("auditID")

def main() -> None:
    client = LogsQueryClient(DefaultAzureCredential())
    session = requests.Session()
    histories: dict[str, deque] = defaultdict(lambda: deque(maxlen=SEQ_LEN))
    seen: set[str] = set()

    log.info(json.dumps({"event": "started", "workspace": WORKSPACE, "service": SERVICE,
                         "poll": POLL, "contract": "/predict/raw"}))
    while True:
        try:
            resp = client.query_workspace(
                WORKSPACE, QUERY.format(lb=LOOKBACK_MIN),
                timespan=timedelta(minutes=LOOKBACK_MIN))
            if resp.status == LogsQueryStatus.SUCCESS and resp.tables:
                new = 0
                for row in resp.tables[0].rows:
                    try:
                        e = json.loads(row[1])
                    except Exception:
                        continue
                    parsed = event_to_record(e)
                    if not parsed:
                        continue
                    actor, rec, aid = parsed
                    if aid and aid in seen:
                        continue
                    if aid:
                        seen.add(aid)
                    hist = histories[actor]
                    hist.append(rec)
                    new += 1
                    r = session.post(f"{SERVICE}/predict/raw",
                                     json={"user": actor, "events": list(hist)}, timeout=5)
                    if r.ok:
                        d = r.json()
                        if d.get("episode_alert"):
                            log.warning(json.dumps({
                                "event": "ids_alert", "actor": actor,
                                "reasons": d.get("reasons", []),
                                "max_prob": round(float(d.get("max_prob", 0.0)), 3),
                                "n_windows_fired": d.get("n_windows_fired", 0),
                                "last_verb_resource": f"{rec['verb']}:{rec['resource']}"}))
                if new:
                    log.info(json.dumps({"event": "polled", "new_events": new,
                                         "actors": len(histories)}))
            if len(seen) > 200000:   # bound the dedup set; the process is long-lived
                seen.clear()
        except Exception as exc:  # noqa: BLE001
            log.error(json.dumps({"event": "poll_error", "err": str(exc)}))
        time.sleep(POLL)

if __name__ == "__main__":
    main()
