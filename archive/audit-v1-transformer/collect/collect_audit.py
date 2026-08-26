#!/usr/bin/env python3
"""Parse the Kubernetes API-server audit log into a labelled event table.

Reads
  audit-logs/audit.log   one JSON audit Event per line
  data/labels.jsonl      attack windows written by the attack scenarios
  data/run_start         timestamp marking the start of the current dataset run

Writes
  data/audit_events.csv  one flat row per audit event, with a binary label

Labelling
  Only events at/after data/run_start are kept (older lines belong to previous
  runs). An event is label=1 if its timestamp falls inside an attack window AND
  it was issued by a non-system user; system controllers (system:*) are always
  label=0. Benign and attack phases never overlap, so time-window labelling is
  unambiguous.
"""
import argparse
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

WORKDIR = Path(__file__).resolve().parents[1]

def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None

def load_windows(path):
    windows = []
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            w = json.loads(line)
            windows.append((parse_ts(w["start"]), parse_ts(w["end"]),
                            w.get("attack_type", "attack")))
    return windows

POD_FLAG_KEYS = ["pod_privileged", "pod_host_path", "pod_host_pid",
                 "pod_host_network", "pod_host_ipc"]

def pod_security_flags(event):
    """Extract security-relevant fields from a Pod create request body.

    Pods are audited at RequestResponse level, so the submitted spec is
    available. These flags are what separates a benign pod from a
    container-escape pod (privileged / host namespaces / host-path mounts) -
    in plain audit metadata the two creates look identical.
    """
    flags = {key: 0 for key in POD_FLAG_KEYS}
    obj = event.get("requestObject")
    if not isinstance(obj, dict):
        return flags
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        return flags
    flags["pod_host_pid"] = int(bool(spec.get("hostPID")))
    flags["pod_host_network"] = int(bool(spec.get("hostNetwork")))
    flags["pod_host_ipc"] = int(bool(spec.get("hostIPC")))
    flags["pod_host_path"] = int(any(
        isinstance(v, dict) and v.get("hostPath")
        for v in (spec.get("volumes") or [])))
    for container in (spec.get("containers") or []):
        sc = container.get("securityContext") if isinstance(container, dict) else None
        if isinstance(sc, dict) and sc.get("privileged"):
            flags["pod_privileged"] = 1
    return flags

def rbac_wildcard_flag(event):
    """Flag a Role/ClusterRole create whose rules grant wildcard ('*') access.

    A wildcard role is the privilege-escalation signal; a scoped least-
    privilege role is benign. Without this the two creates look identical.
    """
    obj = event.get("requestObject")
    if not isinstance(obj, dict) or obj.get("kind") not in ("Role", "ClusterRole"):
        return {"rbac_wildcard": 0}
    for rule in (obj.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        if "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []):
            return {"rbac_wildcard": 1}
    return {"rbac_wildcard": 0}

def flatten(event):
    user = event.get("user", {}) or {}
    obj = event.get("objectRef", {}) or {}
    status = event.get("responseStatus", {}) or {}
    src = event.get("sourceIPs") or []
    row = {
        "timestamp": event.get("requestReceivedTimestamp") or event.get("stageTimestamp"),
        "verb": event.get("verb", ""),
        "user": user.get("username", ""),
        "user_groups": "|".join(user.get("groups", []) or []),
        "stage": event.get("stage", ""),
        "resource": obj.get("resource", ""),
        "subresource": obj.get("subresource", ""),
        "namespace": obj.get("namespace", ""),
        "name": obj.get("name", ""),
        "api_group": obj.get("apiGroup", ""),
        "response_code": status.get("code", ""),
        "source_ip": src[0] if src else "",
        "user_agent": event.get("userAgent", ""),
        "request_uri": event.get("requestURI", ""),
    }
    row.update(pod_security_flags(event))
    row.update(rbac_wildcard_flag(event))
    return row

def label_for(ts, user, windows):
    """Return (label, attack_type) for one event."""
    if ts is None or user.startswith("system:"):
        return 0, ""
    for start, end, attack_type in windows:
        if start and end and start <= ts <= end:
            return 1, attack_type
    return 0, ""

def collect(audit_path, labels_path, run_start_path, out_path):
    windows = load_windows(labels_path)
    run_start = parse_ts(run_start_path.read_text()) if run_start_path.exists() else None

    rows, bad_lines, skipped_old = [], 0, 0
    with open(audit_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
                continue
            row = flatten(event)
            ts = parse_ts(row["timestamp"])
            if run_start and ts and ts < run_start:
                skipped_old += 1
                continue
            row["label"], row["attack_type"] = label_for(ts, row["user"], windows)
            rows.append(row)

    if not rows:
        print("No audit events in range. Did run_dataset.sh run on this cluster?")
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    n_attack = sum(r["label"] for r in rows)
    by_type = Counter(r["attack_type"] for r in rows if r["label"] == 1)
    print(f"Parsed {len(rows)} audit events "
          f"({bad_lines} unparseable, {skipped_old} older than run_start).")
    print(f"  benign events : {len(rows) - n_attack}")
    print(f"  attack events : {n_attack}")
    for attack_type, count in sorted(by_type.items()):
        print(f"      {attack_type:24s} {count}")
    print(f"  attack windows: {len(windows)}")
    print(f"  -> {out_path}")

def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--audit", default=str(WORKDIR / "audit-logs/audit.log"))
    parser.add_argument("--labels", default=str(WORKDIR / "data/labels.jsonl"))
    parser.add_argument("--run-start", default=str(WORKDIR / "data/run_start"))
    parser.add_argument("--out", default=str(WORKDIR / "data/audit_events.csv"))
    args = parser.parse_args()
    collect(Path(args.audit), Path(args.labels),
            Path(args.run_start), Path(args.out))

if __name__ == "__main__":
    main()
