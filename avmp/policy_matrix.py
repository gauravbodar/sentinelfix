"""Policy matrix (PRD §6 Governance controls).

Maps (asset criticality x severity x exploit likelihood) -> allowed remediation
mode. This is the core governance gate. It FAILS CLOSED: any combination not
explicitly cleared for automation resolves to MANUAL_ONLY with approval
required.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import AssetCriticality, RemediationMode, Severity


@dataclass(frozen=True)
class MatrixKey:
    criticality: AssetCriticality
    severity: Severity
    exploit_likely: bool


@dataclass
class MatrixDecision:
    allowed_mode: RemediationMode
    requires_approval: bool
    rationale: str = ""


# Explicit overrides take precedence over the rule engine below.
DEFAULT_OVERRIDES: dict[MatrixKey, MatrixDecision] = {
    MatrixKey(AssetCriticality.LOW, Severity.LOW, False): MatrixDecision(
        RemediationMode.SAFE_AUTO, requires_approval=False,
        rationale="Low criticality + low severity + no active exploit."
    ),
    MatrixKey(AssetCriticality.MEDIUM, Severity.LOW, False): MatrixDecision(
        RemediationMode.SAFE_AUTO, requires_approval=False,
        rationale="Low severity, no active exploit — reversible safe action."
    ),
}

_HIGH_CRIT = {AssetCriticality.HIGH, AssetCriticality.MISSION_CRITICAL}


def resolve(
    key: MatrixKey,
    overrides: dict[MatrixKey, MatrixDecision] | None = None,
) -> MatrixDecision:
    """Return the governed remediation decision. Fails closed."""
    table = DEFAULT_OVERRIDES if overrides is None else overrides
    if key in table:
        return table[key]

    sev = key.severity
    crit = key.criticality

    # High / mission-critical assets never get unattended automation.
    if crit in _HIGH_CRIT:
        if sev in (Severity.HIGH, Severity.CRITICAL) or key.exploit_likely:
            return MatrixDecision(
                RemediationMode.MANUAL_ONLY, requires_approval=True,
                rationale="High-value asset with serious/exploitable finding — human-led."
            )
        if sev is Severity.INFORMATIONAL:
            return MatrixDecision(
                RemediationMode.INFORMATIONAL, requires_approval=False,
                rationale="Informational on high-value asset — no action."
            )
        return MatrixDecision(
            RemediationMode.ADVISORY, requires_approval=True,
            rationale="High-value asset — recommend manual fix with approval."
        )

    # Low / medium criticality assets.
    if sev is Severity.INFORMATIONAL:
        return MatrixDecision(
            RemediationMode.INFORMATIONAL, requires_approval=False,
            rationale="Informational — no action required."
        )
    if sev is Severity.LOW:
        return MatrixDecision(
            RemediationMode.SAFE_AUTO, requires_approval=key.exploit_likely,
            rationale="Low severity — reversible safe action."
        )
    if sev is Severity.MEDIUM:
        return MatrixDecision(
            RemediationMode.SAFE_AUTO, requires_approval=True,
            rationale="Medium severity — safe action gated by approval."
        )
    if sev is Severity.HIGH:
        return MatrixDecision(
            RemediationMode.STAGED_PATCH, requires_approval=True,
            rationale="High severity — stage via canary with approval."
        )

    # Severity.CRITICAL on low/med assets, or anything unhandled: fail closed.
    return MatrixDecision(
        RemediationMode.MANUAL_ONLY, requires_approval=True,
        rationale="Critical/unclassified — fail closed to human-led remediation."
    )
