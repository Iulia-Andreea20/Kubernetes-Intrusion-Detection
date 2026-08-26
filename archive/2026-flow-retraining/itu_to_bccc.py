#!/usr/bin/env python3
"""Convert an ITU / Sever Kaggle dataset CSV to the BCCC column schema.

The BCCC Cloud DDoS 2024 dataset uses ~317 numeric features with snake_case
names. The ITU / Sever (AINA 2024) Kubernetes dataset uses ~86 CIC-IDS-2017
style columns with capitalized names and spaces. This script:

1. Streams the (large) ITU CSV in chunks.
2. Renames overlapping columns to their BCCC equivalents (see ITU_TO_BCCC).
3. Normalizes the Label column to binary (Benign=0, anything else=1).
4. Optionally filters rows by attack class (e.g. only DDoS-style attacks).
5. Writes a single output CSV that can be fed directly to
   `cross_dataset_eval.py` or the training scripts.

The result is a "best effort" mapping: the BCCC features that have no ITU
counterpart will be absent from the output, so `tabular_data.load_tabular`
or `cross_dataset_eval.align_features` will zero-fill them. The adapter
prints how many BCCC features were actually populated, which is what you
should quote in the cross-dataset section of the report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ITU_TO_BCCC: dict[str, str] = {
    "Flow ID": "flow_id",
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dst_ip",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "duration",
    "Total Fwd Packet": "fwd_packets_count",
    "Total Bwd packets": "bwd_packets_count",
    "Total Length of Fwd Packet": "fwd_total_payload_bytes",
    "Total Length of Bwd Packet": "bwd_total_payload_bytes",
    "Fwd Packet Length Max": "fwd_payload_bytes_max",
    "Fwd Packet Length Min": "fwd_payload_bytes_min",
    "Fwd Packet Length Mean": "fwd_payload_bytes_mean",
    "Fwd Packet Length Std": "fwd_payload_bytes_std",
    "Bwd Packet Length Max": "bwd_payload_bytes_max",
    "Bwd Packet Length Min": "bwd_payload_bytes_min",
    "Bwd Packet Length Mean": "bwd_payload_bytes_mean",
    "Bwd Packet Length Std": "bwd_payload_bytes_std",
    "Flow Bytes/s": "bytes_rate",
    "Flow Packets/s": "packets_rate",
    "Flow IAT Mean": "packets_IAT_mean",
    "Flow IAT Std": "packet_IAT_std",
    "Flow IAT Max": "packet_IAT_max",
    "Flow IAT Min": "packet_IAT_min",
    "Fwd IAT Total": "fwd_packets_IAT_total",
    "Fwd IAT Mean": "fwd_packets_IAT_mean",
    "Fwd IAT Std": "fwd_packets_IAT_std",
    "Fwd IAT Max": "fwd_packets_IAT_max",
    "Fwd IAT Min": "fwd_packets_IAT_min",
    "Bwd IAT Total": "bwd_packets_IAT_total",
    "Bwd IAT Mean": "bwd_packets_IAT_mean",
    "Bwd IAT Std": "bwd_packets_IAT_std",
    "Bwd IAT Max": "bwd_packets_IAT_max",
    "Bwd IAT Min": "bwd_packets_IAT_min",
    "Fwd PSH Flags": "fwd_psh_flag_counts",
    "Bwd PSH Flags": "bwd_psh_flag_counts",
    "Fwd URG Flags": "fwd_urg_flag_counts",
    "Bwd URG Flags": "bwd_urg_flag_counts",
    "Fwd RST Flags": "fwd_rst_flag_counts",
    "Bwd RST Flags": "bwd_rst_flag_counts",
    "Fwd Header Length": "fwd_total_header_bytes",
    "Bwd Header Length": "bwd_total_header_bytes",
    "Fwd Packets/s": "fwd_packets_rate",
    "Bwd Packets/s": "bwd_packets_rate",
    "Packet Length Min": "payload_bytes_min",
    "Packet Length Max": "payload_bytes_max",
    "Packet Length Mean": "payload_bytes_mean",
    "Packet Length Std": "payload_bytes_std",
    "Packet Length Variance": "payload_bytes_variance",
    "FIN Flag Count": "fin_flag_counts",
    "SYN Flag Count": "syn_flag_counts",
    "RST Flag Count": "rst_flag_counts",
    "PSH Flag Count": "psh_flag_counts",
    "ACK Flag Count": "ack_flag_counts",
    "URG Flag Count": "urg_flag_counts",
    "CWR Flag Count": "cwr_flag_counts",
    "ECE Flag Count": "ece_flag_counts",
    "Down/Up Ratio": "down_up_rate",
    "Average Packet Size": "avg_segment_size",
    "Fwd Segment Size Avg": "fwd_avg_segment_size",
    "Bwd Segment Size Avg": "bwd_avg_segment_size",
    "Fwd Bytes/Bulk Avg": "avg_fwd_bytes_per_bulk",
    "Fwd Packet/Bulk Avg": "avg_fwd_packets_per_bulk",
    "Fwd Bulk Rate Avg": "avg_fwd_bulk_rate",
    "Bwd Bytes/Bulk Avg": "avg_bwd_bytes_per_bulk",
    "Bwd Packet/Bulk Avg": "avg_bwd_packets_bulk_rate",
    "Bwd Bulk Rate Avg": "avg_bwd_bulk_rate",
    "Subflow Fwd Packets": "subflow_fwd_packets",
    "Subflow Fwd Bytes": "subflow_fwd_bytes",
    "Subflow Bwd Packets": "subflow_bwd_packets",
    "Subflow Bwd Bytes": "subflow_bwd_bytes",
    "FWD Init Win Bytes": "fwd_init_win_bytes",
    "Bwd Init Win Bytes": "bwd_init_win_bytes",
    "Fwd Seg Size Min": "fwd_min_header_bytes",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
    "Label": "label",
}

BENIGN_TOKENS = {"benign", "normal", "legitimate", "0", "false", "no", "none"}

DDOS_TOKENS = {
    "ddos", "dos", "doshulk", "dos hulk", "dos-hulk",
    "dosgoldeneye", "dos goldeneye", "dos-goldeneye",
    "dosslowloris", "dos slowloris", "dos-slowloris",
    "dosslowhttptest", "dos slowhttptest", "dos-slowhttptest",
    "syn flood", "synflood", "syn-flood",
    "http flood", "httpflood", "http-flood",
    "udp flood", "udpflood", "udp-flood",
    "icmp flood", "icmpflood", "icmp-flood",
    "ddos-http-flood", "ddos-syn-flood", "ddos-udp-flood",
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ITU/Sever -> BCCC schema adapter.")
    parser.add_argument("--input", required=True, help="Input ITU CSV (can be large).")
    parser.add_argument("--output", required=True, help="Output CSV in BCCC schema.")
    parser.add_argument("--chunk-size", type=int, default=200_000,
                        help="Rows per streamed chunk (default: 200000).")
    parser.add_argument("--filter", choices=["none", "ddos", "attack"], default="none",
                        help="Row filter: keep all (default), keep only benign+DDoS rows, "
                             "or keep all attacks (drop benign).")
    parser.add_argument("--summary-out", default=None,
                        help="Optional path to write a JSON summary (label counts, mapping coverage).")
    return parser.parse_args()

def normalize_label_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = text.replace("_", " ").replace("/", " ")
    while "  " in text:
        text = text.replace("  ", " ")
    return text

def is_benign(label_text: str) -> bool:
    return label_text in BENIGN_TOKENS

def is_ddos(label_text: str) -> bool:
    if label_text in DDOS_TOKENS:
        return True
    return "ddos" in label_text or "dos" in label_text or "flood" in label_text

def label_to_binary(label_text: str) -> int:
    if is_benign(label_text):
        return 0
    return 1

def keep_row(label_text: str, mode: str) -> bool:
    if mode == "none":
        return True
    if mode == "attack":
        return not is_benign(label_text)
    if mode == "ddos":
        return is_benign(label_text) or is_ddos(label_text)
    raise ValueError(f"Unknown filter mode: {mode}")

def process_chunk(chunk: pd.DataFrame, mode: str, label_counter: dict[str, int]) -> pd.DataFrame:
    rename_map = {k: v for k, v in ITU_TO_BCCC.items() if k in chunk.columns}
    chunk = chunk.rename(columns=rename_map)

    if "label" not in chunk.columns:
        raise KeyError(
            "No 'Label' column found in the ITU CSV; cannot binarize. "
            f"Available columns: {list(chunk.columns)[:10]} ..."
        )

    label_text = chunk["label"].map(normalize_label_text)
    for value in label_text:
        label_counter[value] = label_counter.get(value, 0) + 1

    if mode != "none":
        mask = label_text.map(lambda t: keep_row(t, mode))
        chunk = chunk[mask].copy()
        label_text = label_text[mask]

    chunk["label"] = label_text.map(label_to_binary).astype("int8")
    return chunk

def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    label_counter: dict[str, int] = {}
    total_in = 0
    total_out = 0
    header_written = False
    mapped_cols: set[str] = set()

    print(f"Reading: {input_path}")
    print(f"Writing: {output_path}")
    print(f"Filter:  {args.filter}")
    print(f"Chunk:   {args.chunk_size:,} rows")

    for chunk_idx, raw in enumerate(pd.read_csv(input_path, chunksize=args.chunk_size, low_memory=False)):
        total_in += len(raw)

        for column in raw.columns:
            if column in ITU_TO_BCCC:
                mapped_cols.add(ITU_TO_BCCC[column])

        processed = process_chunk(raw, args.filter, label_counter)
        total_out += len(processed)

        if not header_written:
            processed.to_csv(output_path, index=False, mode="w")
            header_written = True
        else:
            processed.to_csv(output_path, index=False, mode="a", header=False)

        if (chunk_idx + 1) % 5 == 0:
            print(f"  chunk {chunk_idx + 1}: in={total_in:,} kept={total_out:,}")

    bccc_features_total = len([v for v in ITU_TO_BCCC.values() if v != "label"])

    summary = {
        "input": str(input_path),
        "output": str(output_path),
        "filter": args.filter,
        "rows_in": total_in,
        "rows_out": total_out,
        "mapped_bccc_columns": sorted(mapped_cols),
        "mapped_bccc_count": len(mapped_cols),
        "max_mappable": bccc_features_total + 1,
        "raw_label_counts": dict(sorted(label_counter.items(), key=lambda kv: -kv[1])),
    }

    print(f"\nDone.")
    print(f"  Rows read:  {total_in:,}")
    print(f"  Rows kept:  {total_out:,}")
    print(f"  Columns mapped to BCCC schema: {len(mapped_cols)} (out of ITU's {len(ITU_TO_BCCC)} known cols)")
    print(f"  Raw label distribution (top 10):")
    for name, count in list(summary["raw_label_counts"].items())[:10]:
        print(f"    {name!r}: {count:,}")

    if args.summary_out:
        Path(args.summary_out).write_text(json.dumps(summary, indent=2))
        print(f"\nSummary written to: {args.summary_out}")

if __name__ == "__main__":
    sys.exit(main())
