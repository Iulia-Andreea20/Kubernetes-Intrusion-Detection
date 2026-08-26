#!/usr/bin/env python3
"""Audit-plane detector: XGBoost classifier over kube-audit event windows.

The verdict is the classifier alone - no rule layer and no allowlist gating. Those existed
up to v2.4 and were removed in v2.6; see the report for why.

The feature code here must stay identical to dataset/export/export_v2.py, otherwise the
service scores windows that were built differently from the training ones.

    GET  /healthz /readyz /metrics
    POST /predict      {"features": [[32 floats], ...]}        -> per-vector probability
    POST /predict/raw  {"user": ..., "events": [{verb, resource, sub, ns, code, decision, imp}, ...]}
                       -> 20-event windows -> features -> episode verdict
"""
import os, json
from collections import deque
from pathlib import Path
import numpy as np
import xgboost as xgb
from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

XGBDIR = Path(os.environ.get("RUNTIME_IDS_XGB_DIR", "/app/xgb"))
MODEL_PATH = Path(os.environ.get("RUNTIME_IDS_XGB_MODEL", str(XGBDIR/"classifier.json")))
CFG = json.load(open(XGBDIR/"pipeline_config.json"))
FEAT = CFG["features"]; THR = CFG["thresholds"]["prob"]; K = CFG["thresholds"]["K"]
SEQ = 20
RBAC = {"clusterroles","clusterrolebindings","roles","rolebindings"}
SELF_REVIEW = {"selfsubjectaccessreviews","selfsubjectrulesreviews"}
WORKLOAD = {"deployments","daemonsets","replicasets","statefulsets","jobs","cronjobs","pods","replicationcontrollers"}
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
ALLFEAT = OLD+NEW

booster = xgb.Booster(); booster.load_model(str(MODEL_PATH))

PRED = Counter("audit_xgb_predictions_total","Audit predictions",["verdict"])
ALERTS = Counter("audit_xgb_alerts_total","Audit alerts, one per episode",["rule"])
UP = Gauge("audit_xgb_up","1 while the service is running"); UP.set(1)
app = FastAPI(title="Audit Detector", version="2.6")

def sec_read(x): return x.get("resource")=="secrets" and x.get("verb") in ("get","list","watch")
def rbac_w(x): return x.get("resource") in RBAC and x.get("verb") in ("create","update","patch","delete")
def crb_c(x): return x.get("resource") in ("clusterrolebindings","clusterroles") and x.get("verb")=="create"
def wl_create(x): return x.get("verb")=="create" and x.get("resource") in WORKLOAD
def is_csr(x): return x.get("resource")=="certificatesigningrequests"
def is_tokenreq(x): return x.get("verb")=="create" and x.get("resource")=="serviceaccounts" and x.get("sub")=="token"

def windows(events):
    """Sliding 20-event windows, one feature dict per window.

    Most counters are scoped to the window, but the cum_* ones accumulate over the actor's
    whole session: an attacker who paces themselves never fills a single window, yet the
    running totals keep climbing.
    """
    h=deque(maxlen=SEQ); cum=dict(sec=0,rbw=0,exe=0,crb=0); out=[]
    for x in events:
        h.append(x)
        cum["sec"]+=sec_read(x); cum["rbw"]+=rbac_w(x); cum["exe"]+=(x.get("sub")=="exec"); cum["crb"]+=crb_c(x)
        n=len(h); nf=sum(1 for y in h if y.get("decision")=="forbid")
        nsec=sum(1 for y in h if y.get("resource")=="secrets"); nrb=sum(1 for y in h if y.get("resource") in RBAC)
        ncr=sum(1 for y in h if y.get("verb")=="create"); nsr=sum(1 for y in h if y.get("verb")=="create" and y.get("resource") in SELF_REVIEW)
        nexe=sum(1 for y in h if y.get("sub")=="exec"); sns=len({y.get("ns") for y in h if sec_read(y)})
        hcrb=int(any(crb_c(y) for y in h)); hexe=int(nexe>0); hrw=int(any(rbac_w(y) for y in h))
        himp=int(any(y.get("is_imp") for y in h)); nimp=len({y.get("imp") for y in h if y.get("is_imp")})
        ncw=sum(1 for y in h if wl_create(y))
        hcsr=int(any(is_csr(y) for y in h)); htok=int(any(is_tokenreq(y) for y in h))
        old=[round(nf/n,3),nf,n,len(set(y.get("resource") for y in h)),len(set(y.get("verb") for y in h)),len(set(y.get("ns") for y in h)),
             nsec,nexe,nrb,ncr,sum(1 for y in h if y.get("verb")=="delete"),sum(1 for y in h if y.get("verb")=="list"),
             sum(1 for y in h if isinstance(y.get("code"),int) and y.get("code")>=400),nsr,round(nsr/n,3) if n>=SEQ else 0.0]
        new=[int(any(sec_read(y) for y in h)),hexe,hrw,hcrb,int(nf>0),round(nsec/n,3),round(nrb/n,3),round(ncr/n,3),
             sns,3*hcrb+2*hexe+2*(sns>=2)+hrw+2*himp,cum["sec"],cum["rbw"],cum["exe"],cum["crb"],himp,nimp,ncw,hcsr,htok]
        out.append(dict(zip(ALLFEAT, old+new)))
    return out

def score(X):
    return booster.predict(xgb.DMatrix(np.array(X,dtype=float))) if len(X) else np.array([])

@app.get("/healthz")
def healthz(): return {"status":"ok","version":"2.6-xgb","model":str(MODEL_PATH),"features":len(FEAT),"rules":[]}
@app.get("/readyz")
def readyz(): return {"status":"ready"}
@app.get("/metrics")
def metrics(): return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/predict")
async def predict(req: Request):
    body=await req.json(); probs=score(body.get("features",[]))
    out=[{"prob":float(p),"alert":bool(p>=THR)} for p in probs]
    for o in out: PRED.labels(verdict="attack" if o["alert"] else "benign").inc()
    return {"n":len(out),"results":out}

@app.post("/predict/raw")
async def predict_raw(req: Request):
    body=await req.json(); user=body.get("user",""); events=body.get("events",[])
    W=windows(events)
    X=[[w[c] for c in FEAT] for w in W]; probs=score(X)
    clf_fired=int((probs>=THR).sum()) if len(probs) else 0
    # K>1 is hysteresis: one window over the threshold is noise, K consecutive ones is an episode.
    alert = clf_fired>=K
    reasons=["classifier"] if alert else []
    for r in reasons: ALERTS.labels(rule=r).inc()
    PRED.labels(verdict="attack" if alert else "benign").inc()
    return {"n_events":len(events),"n_windows":len(W),"user":user,
            "max_prob":float(probs.max()) if len(probs) else 0.0,"n_windows_fired":clf_fired,
            "episode_alert":alert,"reasons":reasons,"hysteresis_k":K,
            "last_window":W[-1] if W else {}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
