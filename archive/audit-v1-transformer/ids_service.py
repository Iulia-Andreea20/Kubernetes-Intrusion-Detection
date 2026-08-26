#!/usr/bin/env python3
"""Runtime IDS service — Audit-component detection over Kubernetes API events.

Loads the trained Transformer sequence model (``models/sequence_audit/``) and
exposes a small HTTP API:

  POST /predict      Classify a token sequence (already featurised).
  POST /predict/raw  Accept a list of raw audit events; service tokenises + predicts.
  GET  /healthz      Liveness probe.
  GET  /readyz       Readiness probe (model loaded).
  GET  /metrics      Prometheus metrics (alerts by severity, latency, model loaded).

The service is stateless per request; correlation across requests is performed
by the alert correlator module (``src/service/correlator/``), which can be run
in-process by setting ``RUNTIME_IDS_ENABLE_CORRELATOR=1``.

Configuration via environment variables:
  RUNTIME_IDS_MODEL_DIR   Path to the sequence model directory (default models/sequence_audit).
  RUNTIME_IDS_VOCAB_PATH  Path to vocab.json (default data/vocab.json).
  RUNTIME_IDS_THRESHOLD   Decision threshold (default 0.5).
  RUNTIME_IDS_SEVERITY    Comma-separated `label:threshold` pairs.
  RUNTIME_IDS_LOG_LEVEL   stdlib logging level (default INFO).
"""
from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
from fastapi import FastAPI, HTTPException, Response
from prometheus_client import (CONTENT_TYPE_LATEST, Counter, Gauge, Histogram,
                                generate_latest)
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=os.environ.get("RUNTIME_IDS_LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger("runtime-ids")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
WORKDIR = Path(__file__).resolve().parents[1]
MODEL_DIR = Path(os.environ.get("RUNTIME_IDS_MODEL_DIR",
                                  WORKDIR / "models/sequence_audit"))
VOCAB_PATH = Path(os.environ.get("RUNTIME_IDS_VOCAB_PATH",
                                  WORKDIR / "data/vocab.json"))
THRESHOLD = float(os.environ.get("RUNTIME_IDS_THRESHOLD", "0.5"))

def parse_severity_table(spec: str) -> list[tuple[str, float]]:
    """`"CRITICAL:0.95,HIGH:0.85,MEDIUM:0.7,LOW:0.5"` -> sorted list."""
    out = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        label, threshold = token.split(":")
        out.append((label.strip(), float(threshold)))
    return sorted(out, key=lambda kv: -kv[1])

SEVERITY_TABLE = parse_severity_table(os.environ.get(
    "RUNTIME_IDS_SEVERITY",
    "CRITICAL:0.95,HIGH:0.85,MEDIUM:0.70,LOW:0.50"))

# --------------------------------------------------------------------------- #
# Sequence model (replica of training architecture)
# --------------------------------------------------------------------------- #

class SeqClassifier(nn.Module):
    def __init__(self, vocab_size: int, d_model: int, seq_len: int,
                 nhead: int = 4, layers: int = 2, pool: str = "mean") -> None:
        super().__init__()
        self.pool = pool
        self.tok = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos = nn.Embedding(seq_len, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model, nhead, dim_feedforward=128, dropout=0.1, batch_first=True)
        self.encoder = nn.TransformerEncoder(encoder_layer, layers)
        if pool == "attn":
            self.q = nn.Linear(d_model, 1)
        self.head = nn.Linear(d_model, 2)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        positions = torch.arange(x.size(1), device=x.device).unsqueeze(0)
        h = self.tok(x) + self.pos(positions)
        pad = (x == 0)
        h = self.encoder(h, src_key_padding_mask=pad)
        if self.pool == "max":               # acțiunea malițioasă rară domină (nu se diluează)
            return self.head(h.masked_fill(pad.unsqueeze(-1), float("-inf")).max(1).values)
        if self.pool == "attn":
            score = self.q(h).squeeze(-1).masked_fill(pad, float("-inf"))
            w = torch.softmax(score, dim=1).unsqueeze(-1)
            return self.head((h * w).sum(1))
        keep = (~pad).float().unsqueeze(-1)  # mean-pool (implicit, compatibil cu modelul original)
        return self.head((h * keep).sum(1) / keep.sum(1).clamp(min=1.0))

# --------------------------------------------------------------------------- #
# Model loading
# --------------------------------------------------------------------------- #

class IDSModel:
    def __init__(self) -> None:
        self.model: SeqClassifier | None = None
        self.vocab: dict[str, int] = {}
        self.seq_len = 20
        self.loaded = False

    def load(self) -> None:
        config_path = MODEL_DIR / "config.json"
        weights_path = MODEL_DIR / "model.pt"
        if not config_path.exists() or not weights_path.exists():
            raise FileNotFoundError(
                f"Model artefacts missing under {MODEL_DIR}")
        if not VOCAB_PATH.exists():
            raise FileNotFoundError(f"Vocab missing at {VOCAB_PATH}")

        config = json.loads(config_path.read_text())
        self.vocab = json.loads(VOCAB_PATH.read_text())
        self.seq_len = int(config["seq_len"])

        self.model = SeqClassifier(
            vocab_size=int(config["vocab_size"]),
            d_model=int(config["d_model"]),
            seq_len=self.seq_len,
            nhead=int(config.get("nhead", 4)),
            layers=int(config.get("layers", 2)),
            pool=config.get("pool", "mean"),
        )
        state = torch.load(weights_path, map_location="cpu")
        self.model.load_state_dict(state)
        self.model.eval()
        self.loaded = True
        log.info("model loaded vocab_size=%d seq_len=%d",
                 int(config["vocab_size"]), self.seq_len)

    def tokenise_event(self, event: dict) -> str:
        verb = event.get("verb", "")
        resource = event.get("resource", "")
        subresource = event.get("subresource", "")
        return f"{verb}:{resource}:{subresource}"

    def encode(self, tokens: list[str]) -> torch.Tensor:
        unk = self.vocab.get("<UNK>", 1)
        # left-pad to seq_len with <PAD>=0
        window = tokens[-self.seq_len:]
        padded = ["<PAD>"] * (self.seq_len - len(window)) + window
        ids = [self.vocab.get(t, unk) for t in padded]
        return torch.tensor([ids], dtype=torch.long)

    def predict(self, tokens: list[str]) -> float:
        if not self.loaded or self.model is None:
            raise RuntimeError("model not loaded")
        x = self.encode(tokens)
        with torch.no_grad():
            logits = self.model(x)
            prob = torch.softmax(logits, dim=1)[0, 1].item()
        return float(prob)

# --------------------------------------------------------------------------- #
# Prometheus metrics
# --------------------------------------------------------------------------- #

MODEL_READY = Gauge("runtime_ids_model_ready",
                    "1 if the model is loaded and serving.")
PREDICTIONS = Counter("runtime_ids_predictions_total",
                       "Number of predictions served.",
                       labelnames=("verdict",))
ALERTS = Counter("runtime_ids_alerts_total",
                  "Number of alerts emitted (probability >= threshold).",
                  labelnames=("severity",))
LATENCY = Histogram("runtime_ids_predict_latency_seconds",
                     "Per-request prediction latency.")

# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #

def severity_for(probability: float) -> str:
    for label, threshold in SEVERITY_TABLE:
        if probability >= threshold:
            return label
    return "NONE"

# --------------------------------------------------------------------------- #
# FastAPI app
# --------------------------------------------------------------------------- #

ids = IDSModel()

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        ids.load()
        MODEL_READY.set(1)
    except Exception as exc:  # noqa: BLE001
        log.error("failed to load model: %s", exc)
        MODEL_READY.set(0)
    yield

app = FastAPI(title="Runtime IDS Service", version="1.0", lifespan=lifespan)

# --- request / response schemas -------------------------------------------- #

class TokenPredictRequest(BaseModel):
    tokens: list[str] = Field(..., min_length=1,
                              description='Tokens of form "verb:resource:subresource".')
    actor: str | None = None
    request_id: str | None = None

class RawEventsPredictRequest(BaseModel):
    events: list[dict] = Field(..., min_length=1,
                                description="Recent audit events (most recent last).")
    actor: str | None = None
    request_id: str | None = None

class PredictResponse(BaseModel):
    probability: float
    label: int
    severity: str
    threshold: float
    actor: str | None = None
    request_id: str | None = None

# --- routes ---------------------------------------------------------------- #

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/readyz")
def readyz():
    if not ids.loaded:
        raise HTTPException(status_code=503, detail="model not loaded")
    return {"status": "ready"}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/predict", response_model=PredictResponse)
def predict_tokens(req: TokenPredictRequest):
    if not ids.loaded:
        raise HTTPException(status_code=503, detail="model not loaded")
    with LATENCY.time():
        prob = ids.predict(req.tokens)
    return _build_response(prob, req.actor, req.request_id)

@app.post("/predict/raw", response_model=PredictResponse)
def predict_raw(req: RawEventsPredictRequest):
    if not ids.loaded:
        raise HTTPException(status_code=503, detail="model not loaded")
    tokens = [ids.tokenise_event(ev) for ev in req.events]
    with LATENCY.time():
        prob = ids.predict(tokens)
    return _build_response(prob, req.actor, req.request_id)

def _build_response(prob: float, actor: str | None,
                     request_id: str | None) -> PredictResponse:
    label = int(prob >= THRESHOLD)
    severity = severity_for(prob) if label == 1 else "NONE"
    PREDICTIONS.labels(verdict="attack" if label else "benign").inc()
    if label == 1:
        ALERTS.labels(severity=severity).inc()
        log.warning("alert prob=%.4f severity=%s actor=%s request_id=%s",
                    prob, severity, actor, request_id)
    return PredictResponse(
        probability=round(prob, 4),
        label=label,
        severity=severity,
        threshold=THRESHOLD,
        actor=actor,
        request_id=request_id,
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ids_service:app",
                host="0.0.0.0", port=8080,
                workers=1, log_level="info")
