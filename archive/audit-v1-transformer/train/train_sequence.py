#!/usr/bin/env python3
"""Train the deep sequence model for the runtime IDS.

A small Transformer encoder over audit-event token sequences - the LogBERT-style
headline AI model. Each event is a "verb:resource:subresource" token; the model
classifies an event from the window of recent events by the same user.

Input : data/sequences.jsonl, data/vocab.json   (from features/featurize.py)
Outputs (models/sequence_audit/):
  metrics.json     test metrics + per-attack-type recall
  predictions.csv  timestamp,user,attack_type,label,prob,pred
  model.pt         trained weights
  config.json      hyper-parameters (needed by the IDS service)
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

SEED = 42

def load_data(seq_path, vocab_path):
    vocab = json.load(open(vocab_path))
    records = [json.loads(line) for line in open(seq_path) if line.strip()]
    unk = vocab.get("<UNK>", 1)
    X = np.array([[vocab.get(tok, unk) for tok in r["tokens"]] for r in records])
    y = np.array([int(r["label"]) for r in records])
    meta = [(r.get("timestamp", ""), r.get("user", ""), r.get("attack_type", ""))
            for r in records]
    return X, y, meta, vocab

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequences", default=str(REPO / "archive/audit-v1-kind-transformer/data/sequences.jsonl"))
    parser.add_argument("--vocab", default=str(REPO / "archive/audit-v1-kind-transformer/data/vocab.json"))
    parser.add_argument("--outdir", default=str(REPO / "data/models/sequence_audit"))
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--d-model", type=int, default=64)
    args = parser.parse_args()

    import torch
    import torch.nn as nn
    torch.manual_seed(SEED)
    np.random.seed(SEED)

    X, y, meta, vocab = load_data(args.sequences, args.vocab)
    n, seq_len = X.shape
    train_idx, test_idx = common.time_split(n, 0.7)
    val_cut = int(len(train_idx) * 0.85)          # validation = tail of train
    val_idx = train_idx[val_cut:]
    train_idx = train_idx[:val_cut]
    print(f"sequences={n} length={seq_len} vocab={len(vocab)}  "
          f"train={len(train_idx)} val={len(val_idx)} test={len(test_idx)}")

    X_t = torch.tensor(X, dtype=torch.long)
    y_t = torch.tensor(y, dtype=torch.long)

    class SeqClassifier(nn.Module):
        """Token embedding + positional embedding + Transformer encoder."""

        def __init__(self, vocab_size, d_model, seq_len, nhead=4, layers=2):
            super().__init__()
            self.tok = nn.Embedding(vocab_size, d_model, padding_idx=0)
            self.pos = nn.Embedding(seq_len, d_model)
            layer = nn.TransformerEncoderLayer(
                d_model, nhead, dim_feedforward=128, dropout=0.1,
                batch_first=True)
            self.encoder = nn.TransformerEncoder(layer, layers)
            self.head = nn.Linear(d_model, 2)

        def forward(self, x):
            positions = torch.arange(x.size(1), device=x.device).unsqueeze(0)
            h = self.tok(x) + self.pos(positions)
            pad = (x == 0)
            h = self.encoder(h, src_key_padding_mask=pad)
            keep = (~pad).float().unsqueeze(-1)         # masked mean-pool
            return self.head((h * keep).sum(1) / keep.sum(1).clamp(min=1.0))

    model = SeqClassifier(len(vocab), args.d_model, seq_len)

    # inverse-frequency class weights from the training split
    n_pos = max(int(y[train_idx].sum()), 1)
    n_neg = max(int((y[train_idx] == 0).sum()), 1)
    weights = torch.tensor([1.0 / n_neg, 1.0 / n_pos], dtype=torch.float)
    loss_fn = nn.CrossEntropyLoss(weight=weights / weights.sum() * 2)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    def batches(idx, batch_size=64, shuffle=True):
        idx = np.array(idx)
        if shuffle:
            np.random.shuffle(idx)
        for i in range(0, len(idx), batch_size):
            yield torch.as_tensor(idx[i:i + batch_size], dtype=torch.long)

    def predict(idx):
        model.eval()
        probs = []
        with torch.no_grad():
            for batch in batches(idx, 128, shuffle=False):
                logits = model(X_t[batch])
                probs.append(torch.softmax(logits, dim=1)[:, 1].numpy())
        return np.concatenate(probs) if probs else np.array([])

    best_f1, best_state = -1.0, None
    for epoch in range(1, args.epochs + 1):
        model.train()
        for batch in batches(train_idx, 64):
            optimizer.zero_grad()
            loss = loss_fn(model(X_t[batch]), y_t[batch])
            loss.backward()
            optimizer.step()
        val_metrics = common.binary_metrics(y[val_idx], predict(val_idx))
        if val_metrics["f1"] >= best_f1:
            best_f1 = val_metrics["f1"]
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        if epoch == 1 or epoch % 5 == 0:
            print(f"  epoch {epoch:3d}  val_f1={val_metrics['f1']:.3f}  "
                  f"val_recall={val_metrics['recall']:.3f}")

    if best_state is not None:
        model.load_state_dict(best_state)

    prob = predict(test_idx)
    pred = (prob >= 0.5).astype(int)
    attack_type_test = np.array([meta[i][2] for i in test_idx], dtype=object)

    metrics = common.binary_metrics(y[test_idx], prob)
    metrics["false_positive_rate"] = common.false_positive_rate(y[test_idx], pred)
    metrics["per_attack_recall"] = common.per_attack_recall(
        y[test_idx], pred, attack_type_test)
    metrics["train_rows"] = int(len(train_idx))
    metrics["val_rows"] = int(len(val_idx))
    metrics["test_rows"] = int(len(test_idx))
    metrics["best_val_f1"] = best_f1

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    common.save_json(metrics, outdir / "metrics.json")
    pd.DataFrame({
        "timestamp": [meta[i][0] for i in test_idx],
        "user": [meta[i][1] for i in test_idx],
        "attack_type": attack_type_test,
        "label": y[test_idx], "prob": prob, "pred": pred,
    }).to_csv(outdir / "predictions.csv", index=False)
    torch.save(model.state_dict(), outdir / "model.pt")
    common.save_json({"d_model": args.d_model, "seq_len": int(seq_len),
                      "vocab_size": len(vocab), "nhead": 4, "layers": 2},
                     outdir / "config.json")

    print(f"\nsequence model  acc={metrics['accuracy']:.3f}  "
          f"prec={metrics['precision']:.3f}  recall={metrics['recall']:.3f}  "
          f"f1={metrics['f1']:.3f}  roc_auc={metrics.get('roc_auc', 0):.3f}  "
          f"pr_auc={metrics.get('pr_auc', 0):.3f}  "
          f"fpr={metrics['false_positive_rate']:.3f}")
    print("per-attack-type recall:")
    for attack_type, v in metrics["per_attack_recall"].items():
        print(f"  {attack_type:22s} {v['recall']:.3f}  (n={v['support']})")

if __name__ == "__main__":
    main()
