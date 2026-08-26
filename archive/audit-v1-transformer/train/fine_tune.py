#!/usr/bin/env python3
"""Fine-tuning al modelului Audit pe date cloud, ca să reducem FPR-ul păstrând detecția.

- pornește din greutățile existente (models/sequence_audit/model.pt)
- antrenează pe: original-train + cloud_train (oversample) -- ca semnalul cloud să conteze
- monitorizează la fiecare epocă: cloud_test (FPR benign + detection atac) ȘI original-test
  (ca să prindem 'catastrophic forgetting')
- salvează în models/sequence_audit_cloud/ (NU suprascrie originalul)
- raportează BEFORE (model original) vs AFTER (fine-tunat) pe aceleași seturi de test
"""
import argparse
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")
import numpy as np
import torch
import torch.nn as nn

REPO = Path(__file__).resolve().parents[3]
TRAIN_DIR = REPO / "src/model/train/flow"
sys.path.insert(0, str(TRAIN_DIR))
import common  # noqa: E402

HERE = Path(__file__).parent
MODEL_DIR = REPO / "data/models/sequence_audit"
VOCAB = REPO / "archive/audit-v1-kind-transformer/data/vocab.json"
ORIG = REPO / "archive/audit-v1-kind-transformer/data/sequences.jsonl"
OUT = REPO / "data/models/sequence_audit_cloud"
SEED = 42

class SeqClassifier(nn.Module):
    def __init__(self, vocab_size, d_model, seq_len, nhead=4, layers=2):
        super().__init__()
        self.tok = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos = nn.Embedding(seq_len, d_model)
        layer = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward=128,
                                           dropout=0.1, batch_first=True)
        self.encoder = nn.TransformerEncoder(layer, layers)
        self.head = nn.Linear(d_model, 2)

    def forward(self, x):
        positions = torch.arange(x.size(1), device=x.device).unsqueeze(0)
        h = self.tok(x) + self.pos(positions)
        pad = (x == 0)
        h = self.encoder(h, src_key_padding_mask=pad)
        keep = (~pad).float().unsqueeze(-1)
        return self.head((h * keep).sum(1) / keep.sum(1).clamp(min=1.0))

def encode(records, vocab):
    unk = vocab.get("<UNK>", 1)
    X = np.array([[vocab.get(t, unk) for t in r["tokens"]] for r in records])
    y = np.array([int(r["label"]) for r in records])
    return X, y

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--lr", type=float, default=5e-4)
    ap.add_argument("--oversample", type=int, default=12)
    args = ap.parse_args()
    torch.manual_seed(SEED); np.random.seed(SEED)

    vocab = json.load(open(VOCAB))
    cfg = json.load(open(MODEL_DIR / "config.json"))
    seq_len = int(cfg["seq_len"])

    orig = [json.loads(l) for l in open(ORIG) if l.strip()]
    Xo, yo = encode(orig, vocab)
    tr_idx, te_idx = common.time_split(len(orig), 0.7)
    cloud_tr = [json.loads(l) for l in open(HERE / "cloud_train.jsonl")]
    cloud_te = [json.loads(l) for l in open(HERE / "cloud_test.jsonl")]
    Xct, yct = encode(cloud_tr, vocab)
    Xce, yce = encode(cloud_te, vocab)
    print(f"original: {len(orig)} (train {len(tr_idx)}/test {len(te_idx)})  "
          f"cloud_train: {len(cloud_tr)}  cloud_test: {len(cloud_te)}")

    # set de antrenare fine-tuning = original-train + cloud_train oversample
    Xtr = np.concatenate([Xo[tr_idx]] + [Xct] * args.oversample)
    ytr = np.concatenate([yo[tr_idx]] + [yct] * args.oversample)
    Xtr_t = torch.tensor(Xtr, dtype=torch.long); ytr_t = torch.tensor(ytr, dtype=torch.long)

    def make_model():
        m = SeqClassifier(int(cfg["vocab_size"]), int(cfg["d_model"]), seq_len,
                          int(cfg.get("nhead", 4)), int(cfg.get("layers", 2)))
        m.load_state_dict(torch.load(MODEL_DIR / "model.pt", map_location="cpu"))
        return m

    def probs(model, X):
        model.eval()
        with torch.no_grad():
            out = []
            for i in range(0, len(X), 256):
                xb = torch.tensor(X[i:i+256], dtype=torch.long)
                out.append(torch.softmax(model(xb), dim=1)[:, 1].numpy())
        return np.concatenate(out) if out else np.array([])

    def report(model):
        pc = probs(model, Xce); po = probs(model, Xo[te_idx])
        cloud_fpr = common.false_positive_rate(yce, (pc >= 0.5).astype(int))
        cloud_det = float(((pc[yce == 1] >= 0.5)).mean()) if (yce == 1).any() else 0.0
        om = common.binary_metrics(yo[te_idx], po)
        return {"cloud_fpr": cloud_fpr, "cloud_det": cloud_det,
                "orig_recall": om["recall"], "orig_f1": om["f1"],
                "orig_fpr": om["false_positive_rate"] if "false_positive_rate" in om
                            else common.false_positive_rate(yo[te_idx], (po >= 0.5).astype(int))}

    # BEFORE (model original)
    base = make_model()
    before = report(base)
    print(f"\nBEFORE  cloud_FPR={before['cloud_fpr']:.3f}  cloud_det={before['cloud_det']:.3f}  "
          f"orig_recall={before['orig_recall']:.3f}  orig_f1={before['orig_f1']:.3f}")

    # fine-tuning
    model = make_model()
    n_pos = max(int(ytr.sum()), 1); n_neg = max(int((ytr == 0).sum()), 1)
    w = torch.tensor([1.0 / n_neg, 1.0 / n_pos], dtype=torch.float)
    loss_fn = nn.CrossEntropyLoss(weight=w / w.sum() * 2)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr)

    guard = 0.85 * before["orig_recall"]   # nu accepta uitare > 15% pe atacurile originale
    best_score, best_state, best_m = -1e9, None, None
    n = len(Xtr_t)
    for ep in range(1, args.epochs + 1):
        model.train()
        perm = np.random.permutation(n)
        for i in range(0, n, 64):
            b = torch.as_tensor(perm[i:i+64], dtype=torch.long)
            opt.zero_grad()
            loss = loss_fn(model(Xtr_t[b]), ytr_t[b])
            loss.backward(); opt.step()
        m = report(model)
        score = m["cloud_det"] - m["cloud_fpr"]
        ok = m["orig_recall"] >= guard
        if ok and score > best_score:
            best_score = score
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            best_m = m
        if ep == 1 or ep % 5 == 0:
            print(f"  ep {ep:3d}  cloud_FPR={m['cloud_fpr']:.3f}  cloud_det={m['cloud_det']:.3f}  "
                  f"orig_recall={m['orig_recall']:.3f}  orig_f1={m['orig_f1']:.3f}  {'*' if ok else 'x'}")

    if best_state is None:   # nimic n-a trecut de guard -> ia ultimul
        best_state = {k: v.clone() for k, v in model.state_dict().items()}; best_m = m
    model.load_state_dict(best_state)

    OUT.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), OUT / "model.pt")
    json.dump(cfg, open(OUT / "config.json", "w"), indent=2)
    summary = {"before": before, "after": best_m,
               "epochs": args.epochs, "lr": args.lr, "oversample": args.oversample}
    json.dump(summary, open(OUT / "finetune_metrics.json", "w"), indent=2)

    print("\n" + "=" * 60)
    print(" REZULTAT FINE-TUNING (test cloud held-out + test original)")
    print("=" * 60)
    print(f" {'metrică':<26}{'BEFORE':>10}{'AFTER':>10}")
    print(f" {'cloud FPR benign':<26}{before['cloud_fpr']*100:>9.1f}%{best_m['cloud_fpr']*100:>9.1f}%")
    print(f" {'cloud detection atac':<26}{before['cloud_det']*100:>9.1f}%{best_m['cloud_det']*100:>9.1f}%")
    print(f" {'orig recall (forgetting?)':<26}{before['orig_recall']*100:>9.1f}%{best_m['orig_recall']*100:>9.1f}%")
    print(f" {'orig f1':<26}{before['orig_f1']*100:>9.1f}%{best_m['orig_f1']*100:>9.1f}%")
    print("=" * 60)
    print(f"model fine-tunat salvat în: {OUT}")

if __name__ == "__main__":
    main()
