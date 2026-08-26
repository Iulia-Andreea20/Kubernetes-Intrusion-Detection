"""Multi-component alert correlator — the 5-level decision pipeline.

Implements the architecture from the thesis outline (Report 3, Section 3.5):

    threshold  ->  calibration  ->  correlation  ->  chain matching  ->  analyst

The correlator is *data-source agnostic*: it accepts ``Alert`` records from any
number of detection components (Flow, Audit, future Falco/syscall), brings their
raw scores onto a comparable scale via Platt scaling, groups alerts into
*incidents* by actor + time window, optionally boosts the severity if the
observed attack sequence matches a known MITRE chain, and emits one structured
incident per coordinated event.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent))
from chains import match_chain  # noqa: E402

SEVERITY_THRESHOLDS = [
    ("CRITICAL", 0.95),
    ("HIGH", 0.85),
    ("MEDIUM", 0.70),
    ("LOW", 0.50),
]

# --------------------------------------------------------------------------- #
# Per-component score calibration (Platt scaling)
# --------------------------------------------------------------------------- #

class PlattCalibrator:
    """Map raw model scores to calibrated probabilities via logistic regression.

    Equivalent to Platt's method: fit ``sigma(a*score + b)`` to ``(score, label)``
    on a held-out calibration split.
    """

    def __init__(self) -> None:
        self.model = LogisticRegression()
        self.fitted = False

    def fit(self, scores, labels) -> "PlattCalibrator":
        scores = np.asarray(scores, dtype=float).reshape(-1, 1)
        labels = np.asarray(labels, dtype=int)
        self.model.fit(scores, labels)
        self.fitted = True
        return self

    def calibrate(self, scores) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("Calibrator not fitted")
        scores = np.asarray(scores, dtype=float).reshape(-1, 1)
        return self.model.predict_proba(scores)[:, 1]

# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

@dataclass
class Alert:
    timestamp: datetime
    actor: str
    component: str
    raw_score: float
    calibrated_score: float = 0.0
    attack_hint: str = ""

@dataclass
class Incident:
    actor: str
    start: datetime
    end: datetime
    alerts: list = field(default_factory=list)
    components: list = field(default_factory=list)
    attack_sequence: list = field(default_factory=list)
    base_score: float = 0.0
    boosted_score: float = 0.0
    chain_matched: Optional[str] = None
    severity: str = "LOW"

    def to_dict(self) -> dict:
        def ts(t):
            return t.isoformat() if isinstance(t, datetime) else t
        return {
            "actor": self.actor,
            "start": ts(self.start),
            "end": ts(self.end),
            "n_alerts": len(self.alerts),
            "components": sorted(set(self.components)),
            "attack_sequence": self.attack_sequence,
            "base_score": round(self.base_score, 4),
            "boosted_score": round(self.boosted_score, 4),
            "chain_matched": self.chain_matched,
            "severity": self.severity,
        }

# --------------------------------------------------------------------------- #
# The correlator
# --------------------------------------------------------------------------- #

class AlertCorrelator:
    """5-level alert correlator: threshold -> calibrate -> correlate -> chain -> sev."""

    def __init__(self, thresholds: dict, window_seconds: float = 60.0) -> None:
        self.thresholds = thresholds        # {component_name: raw-score threshold}
        self.window_seconds = window_seconds
        self.calibrators: dict[str, PlattCalibrator] = {}

    # L2: calibration ------------------------------------------------------- #
    def fit_calibrators(self, calibration_data: dict) -> None:
        """``calibration_data``: ``{component_name: (scores, labels)}``."""
        for component, (scores, labels) in calibration_data.items():
            self.calibrators[component] = PlattCalibrator().fit(scores, labels)

    # L1 + L2 --------------------------------------------------------------- #
    def threshold_and_calibrate(self, alerts: list[Alert]) -> list[Alert]:
        kept: list[Alert] = []
        for a in alerts:
            thr = self.thresholds.get(a.component, 0.5)
            if a.raw_score < thr:
                continue
            cal = self.calibrators.get(a.component)
            a.calibrated_score = (
                float(cal.calibrate([a.raw_score])[0])
                if cal is not None
                else a.raw_score
            )
            kept.append(a)
        return kept

    # L3: time-window + actor correlation ----------------------------------- #
    def correlate(self, alerts: list[Alert]) -> list[Incident]:
        by_actor: dict[str, list[Alert]] = defaultdict(list)
        for a in alerts:
            by_actor[a.actor].append(a)

        incidents: list[Incident] = []
        for actor, actor_alerts in by_actor.items():
            actor_alerts.sort(key=lambda x: x.timestamp)
            i = 0
            while i < len(actor_alerts):
                window = [actor_alerts[i]]
                cutoff = actor_alerts[i].timestamp + timedelta(
                    seconds=self.window_seconds)
                j = i + 1
                while j < len(actor_alerts) and actor_alerts[j].timestamp <= cutoff:
                    window.append(actor_alerts[j])
                    cutoff = max(cutoff,
                                  actor_alerts[j].timestamp
                                  + timedelta(seconds=self.window_seconds))
                    j += 1

                incidents.append(Incident(
                    actor=actor,
                    start=window[0].timestamp,
                    end=window[-1].timestamp,
                    alerts=window,
                    components=[a.component for a in window],
                    attack_sequence=[a.attack_hint for a in window if a.attack_hint],
                    base_score=max(a.calibrated_score for a in window),
                ))
                i = j
        return incidents

    # L4: MITRE chain matching --------------------------------------------- #
    @staticmethod
    def match_chains_and_score(incidents: list[Incident]) -> list[Incident]:
        for inc in incidents:
            chain = match_chain(inc.attack_sequence)
            if chain is not None:
                inc.chain_matched = chain["name"]
                inc.boosted_score = min(inc.base_score * chain["boost"], 1.0)
            else:
                inc.boosted_score = inc.base_score
        return incidents

    # L5: severity --------------------------------------------------------- #
    @staticmethod
    def assign_severity(incidents: list[Incident]) -> list[Incident]:
        for inc in incidents:
            inc.severity = "LOW"
            for label, thr in SEVERITY_THRESHOLDS:
                if inc.boosted_score >= thr:
                    inc.severity = label
                    break
        return incidents

    # Full pipeline -------------------------------------------------------- #
    def run(self, alerts: list[Alert]) -> list[Incident]:
        alerts = self.threshold_and_calibrate(alerts)
        incidents = self.correlate(alerts)
        incidents = self.match_chains_and_score(incidents)
        incidents = self.assign_severity(incidents)
        return incidents
