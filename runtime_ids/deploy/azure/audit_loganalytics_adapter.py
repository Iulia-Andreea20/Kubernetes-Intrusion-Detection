#!/usr/bin/env python3
"""Adapter audit AKS → IDS v2.2: citește kube-audit din Log Analytics și hrănește serviciul HIBRID.

Pe AKS, audit log-ul API server-ului NU este un fișier (control-plane e managed) — merge
în Azure Monitor / Log Analytics. Streamer-ul file-based (kind) nu poate rula acolo. Acest
adapter este echivalentul lui pentru AKS managed, ALINIAT la serviciul v2.2 (XGBoost + 6 reguli):

  Log Analytics (kube-audit)  →  KQL poll  →  EVENIMENTE structurate per actor REAL
  →  fereastră glisantă (20)  →  POST /predict/raw  →  alertă pe episod (reasons)

Oglindește parsarea din export_v2.py (același featurizer rulează în serviciu): cheia ferestrei
e ATACATORUL REAL (user-ul autentificat), iar impersonarea (`impersonatedUser`) e capturată în
câmpul `imp`/`is_imp` — exact ca în set. NU sare peste `system:serviceaccount:*` (acolo sunt
atacurile: adversary-* în default, compromised-ctrl-* în kube-system) — allowlist-ul e aplicat
ÎN serviciu (regulile), nu aici.

Env:
  LA_WORKSPACE_ID          GUID-ul workspace-ului Log Analytics (customerId)
  RUNTIME_IDS_SERVICE_URL  ex. http://ids-service-xgb:8080 (serviciul audit v2.2)
  POLL_INTERVAL            secunde între interogări (default 15)
  LOOKBACK_MIN             fereastra de interogare în minute (default 10; LA are lag de ingestie)
  RUNTIME_IDS_SEQ_LEN      lungimea ferestrei per actor (default 20)

Auth: DefaultAzureCredential — managed identity (workload identity) în pod, service principal
(AZURE_CLIENT_ID/SECRET/TENANT_ID), sau `az login` local. Necesită rolul „Log Analytics Reader".

⚠️ ONEST: Log Analytics are lag de ingestie de câteva MINUTE — detecția nu e sub-secundă.
Pentru near-real-time s-ar folosi Event Hub (mai mult setup). Vezi RAPORT §6.5 / testul DevOps MTTD.
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
logging.getLogger("azure").setLevel(logging.WARNING)        # taci HTTP-ul verbose al SDK-ului Azure (loguri curate)
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
    """Oglindește export_v2.py: cheia = atacatorul REAL; impersonarea capturată în imp/is_imp."""
    real = (e.get("user") or {}).get("username", "")
    imp = ((e.get("impersonatedUser") or {}).get("username") or "")
    is_imp = 1 if (imp and imp != real) else 0
    actor = real or imp                      # cheia ferestrei = cine s-a autentificat (NU victima impersonată)
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
                         "poll": POLL, "contract": "/predict/raw (v2.2 hibrid)"}))
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
                    # POST /predict/raw: serviciul construiește ferestrele(20)+34 trăsături și aplică clasif + 6 reguli
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
            if len(seen) > 200000:   # cap memoria dedup
                seen.clear()
        except Exception as exc:  # noqa: BLE001
            log.error(json.dumps({"event": "poll_error", "err": str(exc)}))
        time.sleep(POLL)


if __name__ == "__main__":
    main()
