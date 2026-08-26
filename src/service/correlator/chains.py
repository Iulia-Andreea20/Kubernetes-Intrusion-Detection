"""MITRE attack chain definitions for sequence-based severity boost.

A chain is an ordered sequence of attack_type tokens. If the sequence is
observed (as a *subsequence*) within one actor's alert window, the incident
severity is multiplied by the chain's `boost` factor. Longer / more dangerous
chains get larger boosts.

Tokens correspond to the `attack_type` field emitted by the audit-component
attack scenarios (see ``archive/audit-v1-kind-transformer/attacks/attack_scenarios.sh``).
"""
from __future__ import annotations

ATTACK_CHAINS = [
    {
        "name": "full_kill_chain",
        "sequence": ["discovery", "credential_theft",
                     "privilege_escalation", "container_escape"],
        "description": "Full MITRE kill chain: recon -> creds -> priv-esc -> escape",
        "boost": 3.0,
    },
    {
        "name": "recon_to_escape",
        "sequence": ["discovery", "container_exec", "container_escape"],
        "description": "Recon -> in-container execution -> escape attempt",
        "boost": 2.0,
    },
    {
        "name": "credential_to_escalation",
        "sequence": ["credential_theft", "privilege_escalation"],
        "description": "Steal credentials -> use them for RBAC escalation",
        "boost": 1.8,
    },
    {
        "name": "token_to_escalation",
        "sequence": ["token_theft", "privilege_escalation"],
        "description": "Service-account token theft -> privilege escalation",
        "boost": 1.8,
    },
    {
        "name": "discovery_to_credential",
        "sequence": ["discovery", "credential_theft"],
        "description": "Recon -> credential harvesting",
        "boost": 1.5,
    },
    {
        "name": "discovery_to_exec",
        "sequence": ["discovery", "container_exec"],
        "description": "Recon -> in-container execution",
        "boost": 1.3,
    },
]

def _subsequence_match(observed: list[str], pattern: list[str]) -> bool:
    """Each element of `pattern` appears in `observed`, in order, with gaps OK."""
    p = 0
    for obs in observed:
        if p < len(pattern) and obs == pattern[p]:
            p += 1
    return p == len(pattern)

def match_chain(attack_sequence: list[str], chains: list[dict] | None = None):
    """Return the strongest-boost chain that matches, or None."""
    if chains is None:
        chains = ATTACK_CHAINS
    best = None
    for chain in chains:
        if _subsequence_match(attack_sequence, chain["sequence"]):
            if best is None or chain["boost"] > best["boost"]:
                best = chain
    return best
