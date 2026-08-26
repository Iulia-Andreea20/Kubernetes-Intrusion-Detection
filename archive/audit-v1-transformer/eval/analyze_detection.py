#!/usr/bin/env python3
"""De ce detection=61%? Împart ferestrele de atac (cloud_test) în:
  - 'acțiune malițioasă' (conțin get:secrets:/exec/clusterrolebinding) vs
  - 'recon pur' (doar enumerare list/get pe resurse de discovery)
și arăt rata de detecție în fiecare grup, cu modelul FINE-TUNAT.
"""
import json, os
from pathlib import Path
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE"); os.environ.setdefault("OMP_NUM_THREADS", "1")
import torch, torch.nn as nn

REPO = Path(__file__).resolve().parents[3]
MD = REPO / "data/models/sequence_audit_cloud"
vocab = json.load(open(REPO / "archive/audit-v1-kind-transformer/data/vocab.json"))
cfg = json.load(open(MD / "config.json")); seq_len = int(cfg["seq_len"]); unk = vocab.get("<UNK>", 1)

class SeqClassifier(nn.Module):
    def __init__(s, v, d, sl, nh=4, ly=2):
        super().__init__(); s.tok=nn.Embedding(v,d,padding_idx=0); s.pos=nn.Embedding(sl,d)
        s.encoder=nn.TransformerEncoder(nn.TransformerEncoderLayer(d,nh,128,0.1,batch_first=True),ly); s.head=nn.Linear(d,2)
    def forward(s,x):
        p=torch.arange(x.size(1)).unsqueeze(0); h=s.tok(x)+s.pos(p); m=(x==0)
        h=s.encoder(h,src_key_padding_mask=m); k=(~m).float().unsqueeze(-1)
        return s.head((h*k).sum(1)/k.sum(1).clamp(min=1.0))

model = SeqClassifier(int(cfg["vocab_size"]), int(cfg["d_model"]), seq_len, int(cfg.get("nhead",4)), int(cfg.get("layers",2)))
model.load_state_dict(torch.load(MD/"model.pt", map_location="cpu")); model.eval()

def prob(toks):
    w=toks[-seq_len:]; pad=["<PAD>"]*(seq_len-len(w))+w
    x=torch.tensor([[vocab.get(t,unk) for t in pad]])
    with torch.no_grad(): return torch.softmax(model(x),1)[0,1].item()

DISTINCT = {"get:secrets:", "get:pods:exec", "create:clusterrolebindings:", "delete:clusterrolebindings:"}
atk = [json.loads(l) for l in open(Path(__file__).parent/"cloud_test.jsonl") if json.loads(l)["label"]==1]
mal, recon = [], []
for r in atk:
    (mal if DISTINCT & set(r["tokens"]) else recon).append(prob(r["tokens"]))

all_test = [json.loads(l) for l in open(Path(__file__).parent/"cloud_test.jsonl")]
ben = [prob(r["tokens"]) for r in all_test if r["label"]==0]
atkp = [prob(r["tokens"]) for r in all_test if r["label"]==1]
print("="*58)
print(" DE CE 61% la prag 0.5? — distribuția probabilităților")
print("="*58)
print(f" benign (n={len(ben)}):  prob max={max(ben):.2f}  >0.5: {sum(p>=0.5 for p in ben)}")
print(f" atac   (n={len(atkp)}): prob min={min(atkp):.2f} medie={sum(atkp)/len(atkp):.2f} max={max(atkp):.2f}")
print("\n sweep de prag (model FINE-TUNAT pe cloud_test):")
print(f"   {'prag':>5} | {'FPR benign':>11} | {'detection atac':>15}")
print("   " + "-"*40)
for thr in [0.50, 0.40, 0.30, 0.25, 0.20]:
    fpr = sum(p>=thr for p in ben)/len(ben)
    det = sum(p>=thr for p in atkp)/len(atkp)
    print(f"   {thr:>5.2f} | {fpr*100:>10.1f}% | {det*100:>14.1f}%")
print("="*58)
