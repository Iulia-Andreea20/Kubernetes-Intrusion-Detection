#!/usr/bin/env python3
"""Audit log streamer — tails the Kubernetes API audit log and feeds the IDS.

Runs as a DaemonSet on the control-plane node, with the audit log mounted as a
hostPath (the same path the kind cluster writes to). For each non-system event
it appends a `verb:resource:subresource` token to that user's sliding window
and POSTs the window to the IDS service ``/predict`` endpoint.

When the service responds with ``label == 1`` the streamer:
  * logs a structured alert record on stdout (Loki scrapes stdout)
  * increments local Prometheus counters
  * optionally posts to a webhook (Slack/PagerDuty/Grafana OnCall)

Configuration via environment variables:
  RUNTIME_IDS_AUDIT_LOG       Path to audit.log (default /var/log/kubernetes/audit/audit.log).
  RUNTIME_IDS_SERVICE_URL     IDS service base URL (default http://ids-service.runtime-ids.svc:80).
  RUNTIME_IDS_SEQ_LEN         Sliding window length per actor (default 20).
  RUNTIME_IDS_BATCH_INTERVAL  Seconds between flush ticks (default 1.0).
  RUNTIME_IDS_WEBHOOK_URL     Optional alert webhook.
  RUNTIME_IDS_LOG_LEVEL       Default INFO.
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Iterable

import requests
from prometheus_client import Counter, Gauge, start_http_server

# --------------------------------------------------------------------------- #
# Logging (JSON to stdout — Loki/Promtail picks up directly)
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("RUNTIME_IDS_LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)
log = logging.getLogger("audit-streamer")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
AUDIT_LOG = Path(os.environ.get(
    "RUNTIME_IDS_AUDIT_LOG", "/var/log/kubernetes/audit/audit.log"))
SERVICE_URL = os.environ.get(
    "RUNTIME_IDS_SERVICE_URL", "http://ids-service.runtime-ids.svc:80")
SEQ_LEN = int(os.environ.get("RUNTIME_IDS_SEQ_LEN", "20"))
BATCH_INTERVAL = float(os.environ.get("RUNTIME_IDS_BATCH_INTERVAL", "1.0"))
WEBHOOK_URL = os.environ.get("RUNTIME_IDS_WEBHOOK_URL", "")
METRICS_PORT = int(os.environ.get("RUNTIME_IDS_STREAMER_METRICS_PORT", "9090"))

# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
EVENTS_SEEN = Counter("audit_streamer_events_total",
                       "Audit events processed by the streamer.",
                       labelnames=("verdict",))
ALERTS_FORWARDED = Counter("audit_streamer_alerts_total",
                            "Alerts forwarded (label=1) by severity.",
                            labelnames=("severity",))
WEBHOOK_ERRORS = Counter("audit_streamer_webhook_errors_total",
                          "Failed webhook posts.")
SERVICE_ERRORS = Counter("audit_streamer_service_errors_total",
                          "Failed IDS service calls.")
ACTORS = Gauge("audit_streamer_active_actors",
                "Distinct non-system actors with at least one event.")

# --------------------------------------------------------------------------- #
# Audit log tailing
# --------------------------------------------------------------------------- #

def tail(path: Path) -> Iterable[str]:
    """Generator that yields new lines from a file as they appear."""
    while not path.exists():
        log.info(json.dumps({"event": "waiting_for_log", "path": str(path)}))
        time.sleep(2.0)

    with path.open("r") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(BATCH_INTERVAL)

# --------------------------------------------------------------------------- #
# Event -> token
# --------------------------------------------------------------------------- #

def event_to_token(event: dict) -> tuple[str, str] | None:
    """Return (actor, token) for a relevant event, or None to skip."""
    user = (event.get("user") or {}).get("username", "")
    if not user or user.startswith("system:"):
        return None
    obj = event.get("objectRef") or {}
    token = (f"{event.get('verb','')}:"
             f"{obj.get('resource','')}:"
             f"{obj.get('subresource','')}")
    return user, token

# --------------------------------------------------------------------------- #
# Alert handling
# --------------------------------------------------------------------------- #

def post_to_webhook(payload: dict) -> None:
    if not WEBHOOK_URL:
        return
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=2.0)
    except requests.RequestException as exc:
        WEBHOOK_ERRORS.inc()
        log.error(json.dumps({"event": "webhook_failed", "err": str(exc)}))

def handle_response(actor: str, response: dict, tokens: list[str]) -> None:
    verdict = "attack" if response.get("label") == 1 else "benign"
    EVENTS_SEEN.labels(verdict=verdict).inc()
    if response.get("label") != 1:
        return

    severity = response.get("severity", "LOW")
    ALERTS_FORWARDED.labels(severity=severity).inc()

    alert = {
        "event": "ids_alert",
        "actor": actor,
        "probability": response.get("probability"),
        "severity": severity,
        "threshold": response.get("threshold"),
        "tokens_tail": tokens[-5:],
    }
    log.warning(json.dumps(alert))
    post_to_webhook(alert)

# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #

def main() -> None:
    start_http_server(METRICS_PORT)
    log.info(json.dumps({"event": "started",
                          "audit_log": str(AUDIT_LOG),
                          "service_url": SERVICE_URL,
                          "metrics_port": METRICS_PORT}))

    histories: dict[str, deque] = defaultdict(lambda: deque(maxlen=SEQ_LEN))
    session = requests.Session()

    for raw_line in tail(AUDIT_LOG):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        parsed = event_to_token(event)
        if parsed is None:
            continue
        actor, token = parsed

        history = histories[actor]
        history.append(token)
        ACTORS.set(len(histories))

        try:
            response = session.post(
                f"{SERVICE_URL}/predict",
                json={"tokens": list(history), "actor": actor},
                timeout=2.0,
            )
            if response.ok:
                handle_response(actor, response.json(), list(history))
            else:
                SERVICE_ERRORS.inc()
                log.error(json.dumps({"event": "service_bad_status",
                                       "status": response.status_code}))
        except requests.RequestException as exc:
            SERVICE_ERRORS.inc()
            log.error(json.dumps({"event": "service_unreachable",
                                   "err": str(exc)}))

if __name__ == "__main__":
    main()
