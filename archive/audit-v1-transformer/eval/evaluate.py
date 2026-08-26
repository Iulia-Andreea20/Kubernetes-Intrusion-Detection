#!/usr/bin/env python3
"""Evaluează modelul Audit (Transformer) pe dataset-ul AKS colectat real.

Replică EXACT arhitectura și inferența din archive/audit-v1-kind-transformer/ids_service.py.
Raportează onest: detection rate pe ferestrele de atac, false positive rate pe
ferestrele benigne, și probabilitatea maximă per actor.
"""
import json
import os
from pathlib import Path

os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")
import torch
import torch.nn as nn

REPO = Path(__file__).resolve().parents[3]
MODEL_DIR = REPO / "data/models/sequence_audit"
VOCAB_PATH = REPO / "archive/audit-v1-kind-transformer/data/vocab.json"
DATASET = os.environ.get("DATASET", str(Path(__file__).parent / "aks_audit_dataset.jsonl"))
THRESHOLD = float(os.environ.get("RUNTIME_IDS_THRESHOLD", "0.5"))

class SeqClassifier(nn.Module):
    def __init__(self, vocab_size, d_model, seq_len, nhead=4, layers=2):
        super().__init__()
        self.tok = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos = nn.Embedding(seq_len, d_model)
        enc = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward=128,
                                         dropout=0.1, batch_first=True)
        self.encoder = nn.TransformerEncoder(enc, layers)
        self.head = nn.Linear(d_model, 2)

    def forward(self, x):
        positions = torch.arange(x.size(1), device=x.device).unsqueeze(0)
        h = self.tok(x) + self.pos(positions)
        pad = (x == 0)
        h = self.encoder(h, src_key_padding_mask=pad)
        keep = (~pad).float().unsqueeze(-1)
        return self.head((h * keep).sum(1) / keep.sum(1).clamp(min=1.0))

cfg = json.loads((MODEL_DIR / "config.json").read_text())
vocab = json.loads(VOCAB_PATH.read_text())
seq_len = int(cfg["seq_len"])
model = SeqClassifier(int(cfg["vocab_size"]), int(cfg["d_model"]), seq_len,
                      int(cfg.get("nhead", 4)), int(cfg.get("layers", 2)))
model.load_state_dict(torch.load(MODEL_DIR / "model.pt", map_location="cpu"))
model.eval()
unk = vocab.get("<UNK>", 1)

def predict(tokens):
    window = tokens[-seq_len:]
    padded = ["<PAD>"] * (seq_len - len(window)) + window
    ids = [vocab.get(t, unk) for t in padded]
    x = torch.tensor([ids], dtype=torch.long)
    with torch.no_grad():
        return torch.softmax(model(x), dim=1)[0, 1].item()

samples = [json.loads(l) for l in open(DATASET)]
by_actor = {}
unk_tokens = set()
for s in samples:
    p = predict(s["tokens"])
    by_actor.setdefault(s["actor"], {"label": s["label"], "probs": []})["probs"].append(p)
    for t in s["tokens"]:
        if t not in vocab:
            unk_tokens.add(t)

print("=" * 64)
print(f" EVALUARE MODEL AUDIT pe dataset AKS real (prag={THRESHOLD})")
print("=" * 64)
for actor, d in sorted(by_actor.items(), key=lambda kv: kv[1]["label"]):
    probs = d["probs"]
    n = len(probs)
    flagged = sum(1 for p in probs if p >= THRESHOLD)
    kind = "ATAC   " if d["label"] == 1 else "BENIGN "
    rate_name = "detection rate" if d["label"] == 1 else "false positive rate"
    print(f"\n actor={actor}  [{kind}]  ferestre={n}")
    print(f"   {rate_name}: {flagged}/{n} = {flagged/n*100:.1f}%")
    print(f"   prob: min={min(probs):.3f}  medie={sum(probs)/n:.3f}  max={max(probs):.3f}")
    if d["label"] == 1:
        print(f"   detectat cel puțin o dată: {'DA' if max(probs) >= THRESHOLD else 'NU'}")

if unk_tokens:
    print(f"\n  tokeni <UNK> (necunoscuți modelului): {sorted(unk_tokens)}")

# sweep de prag: compromis FPR(benign) vs detection(atac)
if "alice" in by_actor and "mallory" in by_actor:
    pb = by_actor["alice"]["probs"]; pa = by_actor["mallory"]["probs"]
    print("\n sweep de prag (compromis operațional):")
    print(f"   {'prag':>5} | {'FPR benign (alice)':>20} | {'detection atac (mallory)':>24}")
    print("   " + "-" * 55)
    for thr in [0.50, 0.70, 0.85, 0.90, 0.95]:
        fpr = sum(1 for p in pb if p >= thr) / len(pb)
        det = sum(1 for p in pa if p >= thr) / len(pa)
        print(f"   {thr:>5.2f} | {fpr*100:>18.1f}% | {det*100:>22.1f}%")
print("=" * 64)
