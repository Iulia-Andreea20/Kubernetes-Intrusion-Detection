#!/usr/bin/env python3
"""Bridges Falco's http_output to Prometheus. Mounted from a ConfigMap into the runtime-ids image."""
from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

ALERTS = Counter("falco_alerts_total", "Falco runtime alerts",
                 ["rule", "priority", "namespace", "pod"])
UP = Gauge("falco_exporter_up", "1 while the exporter is running")
UP.set(1)

app = FastAPI(title="Falco Exporter", version="1.0")

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/readyz")
def readyz():
    return {"status": "ready"}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/falco")
async def falco(req: Request):
    try:
        body = await req.json()
    except Exception:
        return {"received": 0}
    items = body if isinstance(body, list) else [body]
    n = 0
    for o in items:
        if not isinstance(o, dict) or "rule" not in o:
            continue
        of = o.get("output_fields", {}) or {}
        ALERTS.labels(
            rule=str(o.get("rule", ""))[:60],
            priority=str(o.get("priority", "")),
            namespace=of.get("k8s.ns.name") or "-",
            pod=of.get("k8s.pod.name") or "-",
        ).inc()
        n += 1
    return {"received": n}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9093)
