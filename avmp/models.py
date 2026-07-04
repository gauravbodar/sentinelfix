"""Canonical domain models (PRD §4 State Store).

Real dataclasses with risk scoring and (de)serialization. These are the shared
vocabulary used by the scanner, console, and remediation engine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MISSION_CRITICAL = "mission_critical"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationMode(str, Enum):
    INFORMATIONAL = "informational"
    ADVISORY = "advisory"
    SAFE_AUTO = "safe_auto"
    STAGED_PATCH = "staged_patch"
    MANUAL_ONLY = "manual_only"


# Weights used by risk scoring (PRD §2 "Risk realism").
_CRITICALITY_WEIGHT = {
    AssetCriticality.LOW: 0.80,
    AssetCriticality.MEDIUM: 1.00,
    AssetCriticality.HIGH: 1.20,
    AssetCriticality.MISSION_CRITICAL: 1.40,
}

_SEVERITY_CVSS_FLOOR = {
    Severity.INFORMATIONAL: 0.0,
    Severity.LOW: 3.9,
    Severity.MEDIUM: 6.0,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
}


@dataclass
class Asset:
    asset_id: str
    hostname: Optional[str] = None
    ip_addresses: list[str] = field(default_factory=list)
    owner: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: dict[str, str] = field(default_factory=dict)
    discovered_at: Optional[datetime] = None
    internet_facing: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["criticality"] = self.criticality.value
        d["discovered_at"] = self.discovered_at.isoformat() if self.discovered_at else None
        return d


@dataclass
class Finding:
    finding_id: str
    asset_id: str
    plugin_id: str
    title: str
    severity: Severity = Severity.MEDIUM
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None      # 0..1 exploit prediction (EPSS)
    in_kev: bool = False                    # CISA Known Exploited Vulnerabilities
    evidence: dict[str, str] = field(default_factory=dict)
    remediation_hint: Optional[str] = None
    detected_at: Optional[datetime] = None

    def exploit_likely(self) -> bool:
        """Heuristic used by the policy matrix: KEV membership or high EPSS."""
        return self.in_kev or (self.epss_score is not None and self.epss_score >= 0.30)

    def risk_score(self, criticality: AssetCriticality = AssetCriticality.MEDIUM) -> float:
        """Blend CVSS, EPSS, KEV and asset criticality into a 0..100 score.

        Not raw CVSS — exploitability (EPSS/KEV) and mission impact matter too.
        """
        cvss = self.cvss_score
        if cvss is None:
            cvss = _SEVERITY_CVSS_FLOOR.get(self.severity, 5.0)
        epss = self.epss_score or 0.0
        base = (cvss / 10.0) * 0.5 + epss * 0.3
        if self.in_kev:
            base += 0.2
        weighted = base * _CRITICALITY_WEIGHT.get(criticality, 1.0)
        return round(min(weighted, 1.0) * 100.0, 1)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["detected_at"] = self.detected_at.isoformat() if self.detected_at else None
        return d


@dataclass
class Policy:
    asset_criticality: AssetCriticality
    severity: Severity
    exploit_likely: bool
    allowed_mode: RemediationMode
    requires_approval: bool = True


@dataclass
class AuditRecord:
    record_id: str
    actor: str
    action: str
    subject_id: str            # asset_id / finding_id / action_id
    timestamp: datetime
    details: dict[str, str] = field(default_factory=dict)
    prev_signature: Optional[str] = None
    signature: Optional[str] = None  # signed receipt (HMAC), set at write time

    def signing_payload(self) -> dict:
        """Deterministic subset signed by the WORM store (excludes signature)."""
        return {
            "record_id": self.record_id,
            "actor": self.actor,
            "action": self.action,
            "subject_id": self.subject_id,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "prev_signature": self.prev_signature,
        }
