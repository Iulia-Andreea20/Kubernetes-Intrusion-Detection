"""Turn Falco alerts into correlator input.

Falco watches syscalls, the audit component watches the API. Mapping Falco alerts onto the same
actor and time window lets the correlator join the two planes into one attack chain:

  Falco priority  -> a raw score on the same scale as the other detectors
  Falco rule      -> an attack hint from the MITRE chain vocabulary in chains.py
  pod             -> the Kubernetes actor, resolved through the audit log
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipeline import Alert  # noqa: E402

# Falco priority -> a raw score comparable with the other detectors
PRIORITY_SCORE = {
    "Emergency": 1.0, "Alert": 0.97, "Critical": 0.95, "Error": 0.90,
    "Warning": 0.85, "Notice": 0.70, "Informational": 0.50, "Debug": 0.30,
}

# Falco rule -> tactic token from the chains.py vocabulary
RULE_TO_TACTIC = [
    (("read sensitive file", "sensitive file opened", "service account token",
      "read environment variable", "ssh", "/etc/shadow"), "credential_theft"),
    (("terminal shell", "shell was spawned", "spawned in a container",
      "drop and execute", "execute new binary", "run shell"), "container_exec"),
    (("escape", "privileged container", "mount", "change thread namespace",
      "container drift", "sensitive mount"), "container_escape"),
    (("contact k8s api server", "k8s api server from container",
      "service discovery"), "discovery"),
]

def rule_to_tactic(rule: str, output: str = "") -> str:
    s = f"{rule} {output}".lower()
    for keys, tactic in RULE_TO_TACTIC:
        if any(k in s for k in keys):
            return tactic
    return ""

def _parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

def falco_json_to_alert(obj: dict, pod_to_actor: dict | None = None,
                        component: str = "falco_runtime") -> Alert | None:
    """One Falco alert -> a correlator Alert, or None if it carries no useful signal."""
    of = obj.get("output_fields", {}) or {}
    pod = of.get("k8s.pod.name") or of.get("k8s_pod_name") or ""
    ts = _parse_time(obj.get("time"))
    if ts is None:
        return None
    priority = obj.get("priority", "Notice")
    rule = obj.get("rule", "")
    hint = rule_to_tactic(rule, obj.get("output", ""))
    # Resolve pod -> Kubernetes actor from the audit log; fall back to the pod itself
    actor = (pod_to_actor or {}).get(pod, f"pod:{pod}" if pod else "unknown")
    return Alert(
        timestamp=ts,
        actor=actor,
        component=component,
        raw_score=PRIORITY_SCORE.get(priority, 0.70),
        attack_hint=hint,
    )
