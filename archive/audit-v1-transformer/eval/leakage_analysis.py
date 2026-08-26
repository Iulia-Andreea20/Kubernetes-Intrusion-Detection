#!/usr/bin/env python3
"""Ruta minimă #2+#4: cuantifică scurgerea (leakage) + baseline-uri + intervale de încredere.

Compară pe ACELAȘI test held-out:
  (A) MODELUL (Transformer max-pool)  vs
  (B) BASELINE KEYWORD: 'fereastra conține vreun token-semnătură (benign=0) => atac'  vs
  (C) BASELINE IDENTITATE: prezice eticheta DOAR din numele actorului.
Dacă (A) ≈ (B), modelul nu învață comportament, ci un regex. Dacă (C) e perfect, eticheta=actor (leakage).
Raportează recall/FPR cu CI bootstrap pe ferestre (proxy; corect ar fi pe episod — vezi #4).
"""
import json, os, random
from pathlib import Path
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE"); os.environ.setdefault("OMP_NUM_THREADS", "1")
import torch, torch.nn as nn

HERE = Path(__file__).parent
REPO = HERE.parents[2]
MD = REPO / "data/models/sequence_audit_cloud_max"
vocab = json.load(open(REPO / "archive/audit-v1-kind-transformer/data/vocab.json"))
cfg = json.load(open(MD / "config.json")); seq_len = int(cfg["seq_len"]); unk = vocab.get("<UNK>", 1)
SIGNATURE = {"get:secrets:", "list:secrets:", "create:clusterrolebindings:",
             "create:serviceaccounts:token", "create:serviceaccounts:", "create:pods:"}

class SC(nn.Module):
    def __init__(s,v,d,sl,nh,ly):
        super().__init__(); s.tok=nn.Embedding(v,d,padding_idx=0); s.pos=nn.Embedding(sl,d)
        s.encoder=nn.TransformerEncoder(nn.TransformerEncoderLayer(d,nh,128,0.1,batch_first=True),ly); s.head=nn.Linear(d,2)
    def forward(s,x):
        p=torch.arange(x.size(1)).unsqueeze(0); h=s.tok(x)+s.pos(p); m=(x==0)
        h=s.encoder(h,src_key_padding_mask=m)
        return s.head(h.masked_fill(m.unsqueeze(-1),float('-inf')).max(1).values)
model=SC(int(cfg["vocab_size"]),int(cfg["d_model"]),seq_len,int(cfg.get("nhead",4)),int(cfg.get("layers",2)))
model.load_state_dict(torch.load(MD/"model.pt",map_location="cpu")); model.eval()

def model_pred(toks):
    w=toks[-seq_len:]; ids=[vocab.get(t,unk) for t in (["<PAD>"]*(seq_len-len(w))+w)]
    with torch.no_grad(): return int(torch.softmax(model(torch.tensor([ids])),1)[0,1].item()>=0.5)

def kw_pred(toks): return int(any(t in SIGNATURE for t in toks))

test=[json.loads(l) for l in open(HERE/"cloud_test.jsonl")]
y=[r["label"] for r in test]
pm=[model_pred(r["tokens"]) for r in test]
pk=[kw_pred(r["tokens"]) for r in test]

def metrics(y,p):
    tp=sum(1 for a,b in zip(y,p) if a==1 and b==1); fn=sum(1 for a,b in zip(y,p) if a==1 and b==0)
    fp=sum(1 for a,b in zip(y,p) if a==0 and b==1); tn=sum(1 for a,b in zip(y,p) if a==0 and b==0)
    rec=tp/max(tp+fn,1); fpr=fp/max(fp+tn,1); acc=(tp+tn)/len(y)
    return rec,fpr,acc

def boot_ci(y,p,fn,n=2000):
    idx=list(range(len(y))); vals=[]
    for _ in range(n):
        s=[random.randint(0,len(y)-1) for _ in idx]
        vals.append(fn([y[i] for i in s],[p[i] for i in s]))
    vals.sort(); return vals[int(0.025*n)], vals[int(0.975*n)]

random.seed(42)
print("="*66)
print(f" CUANTIFICARE LEAKAGE — test held-out: {len(test)} ferestre ({sum(y)} atac / {len(y)-sum(y)} benign)")
print("="*66)
for name,p in [("(A) MODEL (Transformer max-pool)",pm),("(B) BASELINE KEYWORD (6 tokeni benign=0)",pk)]:
    rec,fpr,acc=metrics(y,p)
    rl,rh=boot_ci(y,p,lambda Y,P:metrics(Y,P)[0]); fl,fh=boot_ci(y,p,lambda Y,P:metrics(Y,P)[1])
    print(f"\n {name}")
    print(f"   recall(detection) = {rec*100:.1f}%   CI95 [{rl*100:.0f}, {rh*100:.0f}]")
    print(f"   FPR               = {fpr*100:.1f}%   CI95 [{fl*100:.0f}, {fh*100:.0f}]")
agree=sum(1 for a,b in zip(pm,pk) if a==b)/len(pm)
print(f"\n >> ACORD model vs keyword: {agree*100:.1f}% din ferestre clasificate IDENTIC")

# (C) identitate-only: eticheta din actor
actors=set(r["user"] for r in test)
amap={a:round(sum(r["label"] for r in test if r["user"]==a)/max(sum(1 for r in test if r["user"]==a),1)) for a in actors}
pid=[amap[r["user"]] for r in test]
rec,fpr,acc=metrics(y,pid)
print(f"\n (C) BASELINE IDENTITATE (doar numele actorului): accuracy={acc*100:.1f}%  recall={rec*100:.0f}%  FPR={fpr*100:.0f}%")
print("="*66)
print(" VERDICT: dacă (A)≈(B) și acordul ~100% => modelul ≈ regex pe vocabular (nu comportament).")
print("          dacă (C) e perfect => eticheta e determinată de actor (leakage de actor).")
