"""Configurable, explainable risk scoring engine (Phase 2 D2).

The MVP hardcoded scoring weights in models.py. This engine externalizes them
into a versioned model that can be loaded from JSON (no code edit needed to
retune), adds an exposure/internet-facing factor, and returns a per-factor
breakdown so every score is explainable (PRD pillar: Explainability).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .models import Asset, AssetCriticality, Finding, Severity

_SEVERITY_CVSS_FLOOR = {
    Severity.INFORMATIONAL: 0.0,
    Severity.LOW: 3.9,
    Severity.MEDIUM: 6.0,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
}


@dataclass
class ScoreFactor:
    name: str
    raw: float          # the input value (e.g. cvss=9.8, epss=0.94)
    weight: float       # weight applied
    contribution: float # points this factor added to the 0..100 score


@dataclass
class ScoreBreakdown:
    score: float
    model_version: str
    factors: list[ScoreFactor] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "model_version": self.model_version,
            "factors": [asdict(f) for f in self.factors],
        }


@dataclass
class ScoringModel:
    """Versioned weights. Load from JSON to retune without touching code."""

    version: str = "1.0.0"
    cvss_weight: float = 0.50
    epss_weight: float = 0.30
    kev_boost: float = 0.20
    exposure_boost: float = 0.10
    criticality_weights: dict[str, float] = field(default_factory=lambda: {
        AssetCriticality.LOW.value: 0.80,
        AssetCriticality.MEDIUM.value: 1.00,
        AssetCriticality.HIGH.value: 1.20,
        AssetCriticality.MISSION_CRITICAL.value: 1.40,
    })

    @classmethod
    def from_file(cls, path: str) -> "ScoringModel":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**d)

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def score(self, finding: Finding, asset: Optional[Asset] = None) -> ScoreBreakdown:
        criticality = asset.criticality if asset else AssetCriticality.MEDIUM
        internet_facing = bool(asset and asset.internet_facing)

        cvss = finding.cvss_score
        if cvss is None:
            cvss = _SEVERITY_CVSS_FLOOR.get(finding.severity, 5.0)
        epss = finding.epss_score or 0.0
        crit_w = self.criticality_weights.get(criticality.value, 1.0)

        # Base (pre-criticality) contributions: (raw_value, weight, base_points).
        raw_contribs = {
            "cvss": (cvss, self.cvss_weight, (cvss / 10.0) * self.cvss_weight),
            "epss": (epss, self.epss_weight, epss * self.epss_weight),
            "kev": (1.0 if finding.in_kev else 0.0,
                    self.kev_boost, self.kev_boost if finding.in_kev else 0.0),
            "exposure": (1.0 if internet_facing else 0.0,
                         self.exposure_boost, self.exposure_boost if internet_facing else 0.0),
        }
        base_total = sum(v[2] for v in raw_contribs.values())
        # Cap the base at 1.0, then apply criticality weighting and the 0..100 scale.
        scale = (min(base_total, 1.0) / base_total) if base_total > 0 else 0.0
        final_score = min(round(min(base_total, 1.0) * crit_w * 100.0, 1), 100.0)

        factors: list[ScoreFactor] = []
        for name, (raw, weight, base_points) in raw_contribs.items():
            contribution = round(base_points * scale * crit_w * 100.0, 2)
            factors.append(ScoreFactor(name, round(raw, 4), weight, contribution))
        # Criticality is a multiplier, not an additive term — reported for clarity.
        factors.append(ScoreFactor("criticality", crit_w, crit_w, 0.0))

        return ScoreBreakdown(score=final_score, model_version=self.version, factors=factors)


# Module-level default so callers can score without wiring a model.
DEFAULT_MODEL = ScoringModel()


def score_finding(finding: Finding, asset: Optional[Asset] = None,
                  model: Optional[ScoringModel] = None) -> ScoreBreakdown:
    return (model or DEFAULT_MODEL).score(finding, asset)
