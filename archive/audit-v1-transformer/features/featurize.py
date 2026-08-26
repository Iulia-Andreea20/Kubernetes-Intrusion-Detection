#!/usr/bin/env python3
"""Turn the labelled audit-event table into model-ready features.

Input
  data/audit_events.csv      from collect_audit.py

Outputs
  data/features_tabular.csv  one numeric row per event + label  (XGBoost / LightGBM)
  data/sequences.jsonl       per-event token sequence + label   (deep sequence model)
  data/vocab.json            token -> id map for the sequences

Two views of the same events:
  * tabular  - per-event categorical one-hots, identity flags, response-code
               flags, and BEHAVIOURAL rate features (how busy / how varied /
               how many errors this user has been in the last 5 s and 60 s).
  * sequence - each event becomes a "<verb>:<resource>:<subresource>" token;
               the feature is the window of recent tokens by the same user,
               ending at this event (the DeepLog / LogBERT style).

Row i of features_tabular.csv and line i of sequences.jsonl describe the SAME
event, so the two model families are directly comparable.

In features_tabular.csv the columns `timestamp`, `user`, `attack_type` and
`label` are metadata/target; every other column is a model feature.
"""
import argparse
import json
from bisect import bisect_left
from datetime import timedelta
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[3]

# categorical column -> how many of its most frequent values to one-hot encode
CAT_COLS = {"verb": 12, "resource": 25, "subresource": 8,
            "api_group": 8, "namespace": 8}
META_COLS = ["timestamp", "user", "attack_type", "label"]
BODY_COLS = ["pod_privileged", "pod_host_path", "pod_host_pid",
             "pod_host_network", "pod_host_ipc", "rbac_wildcard"]
SEQ_LEN = 20

def load_events(path):
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df["ts"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("ts").reset_index(drop=True)
    df["label"] = df["label"].astype(int)
    return df

def one_hot_top(df, col, k):
    """One-hot the k most frequent values of `col`; everything else -> =other."""
    top = df[col].value_counts().head(k).index.tolist()
    out = pd.DataFrame(index=df.index)
    for value in top:
        out[f"{col}={value or 'none'}"] = (df[col] == value).astype(int)
    out[f"{col}=other"] = (~df[col].isin(top)).astype(int)
    return out

def behavioural_features(df):
    """Per-user look-back rate features - the behavioural IDS signal."""
    n = len(df)
    names = ("user_events_5s", "user_events_60s", "user_distinct_resources_60s",
             "user_distinct_verbs_60s", "user_errors_60s",
             "user_readonly_ratio_60s", "secs_since_user_prev")
    cols = {name: [0.0] * n for name in names}

    for _, g in df.groupby("user", sort=False):
        rows = g.index.tolist()
        times = g["ts"].tolist()
        verbs = g["verb"].tolist()
        resources = g["resource"].tolist()
        is_err = [c[:1] in ("4", "5") for c in g["response_code"].tolist()]
        is_ro = [v in ("get", "list", "watch") for v in verbs]

        for i, row in enumerate(rows):
            t = times[i]
            lo5 = bisect_left(times, t - timedelta(seconds=5))
            lo60 = bisect_left(times, t - timedelta(seconds=60))
            win = slice(lo60, i + 1)
            ro = is_ro[win]
            cols["user_events_5s"][row] = i - lo5 + 1
            cols["user_events_60s"][row] = i - lo60 + 1
            cols["user_distinct_resources_60s"][row] = len(set(resources[win]))
            cols["user_distinct_verbs_60s"][row] = len(set(verbs[win]))
            cols["user_errors_60s"][row] = sum(is_err[win])
            cols["user_readonly_ratio_60s"][row] = sum(ro) / len(ro) if ro else 0.0
            cols["secs_since_user_prev"][row] = (
                (t - times[i - 1]).total_seconds() if i > 0 else -1.0)

    return pd.DataFrame(cols, index=df.index)

def build_tabular(df):
    parts = [df[META_COLS].copy()]
    for col, k in CAT_COLS.items():
        parts.append(one_hot_top(df, col, k))

    ident = pd.DataFrame(index=df.index)
    ident["is_system_user"] = df["user"].str.startswith("system:").astype(int)
    ident["is_service_account"] = df["user"].str.startswith(
        "system:serviceaccount:").astype(int)
    code = pd.to_numeric(df["response_code"], errors="coerce").fillna(0).astype(int)
    ident["resp_2xx"] = ((code >= 200) & (code < 300)).astype(int)
    ident["resp_4xx"] = ((code >= 400) & (code < 500)).astype(int)
    ident["resp_403"] = (code == 403).astype(int)
    ident["resp_5xx"] = (code >= 500).astype(int)
    parts.append(ident)

    body_cols = [c for c in BODY_COLS if c in df.columns]
    if body_cols:
        parts.append(df[body_cols].apply(pd.to_numeric, errors="coerce")
                     .fillna(0).astype(int))

    parts.append(behavioural_features(df))
    return pd.concat(parts, axis=1)

def build_sequences(df, seq_len):
    """Each event -> the window of the last `seq_len` tokens by the same user."""
    df = df.copy()
    df["token"] = df["verb"] + ":" + df["resource"] + ":" + df["subresource"]

    vocab = {"<PAD>": 0, "<UNK>": 1}
    for token in sorted(df["token"].unique()):
        vocab[token] = len(vocab)

    records, history = [], {}
    for row in df.itertuples(index=False):
        hist = history.setdefault(row.user, [])
        hist.append(row.token)
        window = hist[-seq_len:]
        padded = ["<PAD>"] * (seq_len - len(window)) + window
        records.append({"timestamp": row.timestamp, "user": row.user,
                         "tokens": padded, "label": int(row.label),
                         "attack_type": row.attack_type})
    return records, vocab

def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", default=str(REPO / "archive/audit-v1-kind-transformer/data/audit_events.csv"))
    parser.add_argument("--seq-len", type=int, default=SEQ_LEN)
    parser.add_argument("--outdir", default=str(REPO / "archive/audit-v1-kind-transformer/data"))
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = load_events(Path(args.events))
    tabular = build_tabular(df)
    sequences, vocab = build_sequences(df, args.seq_len)

    tabular.to_csv(outdir / "features_tabular.csv", index=False)
    with open(outdir / "sequences.jsonl", "w") as fh:
        for record in sequences:
            fh.write(json.dumps(record) + "\n")
    with open(outdir / "vocab.json", "w") as fh:
        json.dump(vocab, fh, indent=1)

    n_features = tabular.shape[1] - len(META_COLS)
    n_attack = int(tabular["label"].sum())
    print(f"Events                : {len(df)}")
    print(f"Tabular features      : {n_features} columns")
    print(f"  label balance       : {n_attack} attack / {len(df) - n_attack} benign")
    print(f"Sequences             : {len(sequences)} (length {args.seq_len})")
    print(f"  token vocabulary    : {len(vocab)} tokens")
    print(f"Outputs -> {outdir}/features_tabular.csv, sequences.jsonl, vocab.json")

if __name__ == "__main__":
    main()
