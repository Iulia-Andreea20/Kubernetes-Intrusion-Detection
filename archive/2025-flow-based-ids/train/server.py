from fastapi import FastAPI
from pydantic import BaseModel
import joblib, numpy as np
import os

ART = os.environ.get("ART_DIR", "artifacts")

clf   = joblib.load(f"{ART}/ids_model.joblib")
mean  = np.load(f"{ART}/scaler_mean.npy")
scale = np.load(f"{ART}/scaler_scale.npy")
enc_s = joblib.load(f"{ART}/ip_src_encoder.joblib")
enc_d = joblib.load(f"{ART}/ip_dst_encoder.joblib")

THRESHOLD = float(os.environ.get("THRESHOLD", "0.90"))

app = FastAPI(title="K8s IDS Scorer")

class Packet(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: float

def enc_or_unknown(enc, value: str) -> int:
    try:
        return int(enc.transform([value])[0])
    except Exception:
        return -1  # unseen token

def scale_vec(x):
    return (x - mean) / scale

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/score")
def score(p: Packet):
    src = enc_or_unknown(enc_s, p.src_ip)
    dst = enc_or_unknown(enc_d, p.dst_ip)
    x = np.array([[src, dst, p.src_port, p.dst_port, p.length]], dtype=float)
    x = scale_vec(x)
    prob = float(clf.predict_proba(x)[0,1])
    return {"p_attack": prob, "alert": bool(prob >= THRESHOLD)}
