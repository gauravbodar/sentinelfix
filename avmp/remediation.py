"""Remediation engine (PRD §6).

Governed path for a single finding:

    plan -> (approval if required) -> change-window check -> canary staged apply
    -> post-fix validation -> rollback on failure -> signed audit receipt

Every gate fails closed. Applying a fix is SIMULATED in this MVP: no real host
is modified. The point is to prove the control flow and the audit trail.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from typing import Callable, Optional

from .canary import CanaryRing, RolloutResult, staged_rollout
from .models import (
    Asset,
    AuditRecord,
    Finding,
    RemediationMode,
    utcnow,
)
from .plugin_sdk import Plugin, PluginTarget, RemediationProposal
from .policy_matrix import MatrixKey, MatrixDecision, resolve
from .rbac import enforce_separation_of_duties
from .store import Store


@dataclass
class ChangeWindow:
    """Allowed maintenance window (UTC), inclusive start, exclusive end."""

    start: dtime
    end: dtime

    def contains(self, when: datetime) -> bool:
        t = when.timetz().replace(tzinfo=None)
        if self.start <= self.end:
            return self.start <= t < self.end
        # Window wraps midnight.
        return t >= self.start or t < self.end


@dataclass
class RemediationPlan:
    finding: Finding
    asset: Asset
    decision: MatrixDecision
    proposal: RemediationProposal
    approved_by: Optional[str] = None

    @property
    def requires_approval(self) -> bool:
        return self.decision.requires_approval

    @property
    def auto_applicable(self) -> bool:
        return self.decision.allowed_mode in (
            RemediationMode.SAFE_AUTO,
            RemediationMode.STAGED_PATCH,
        )


@dataclass
class RemediationOutcome:
    action_id: str
    applied: bool
    denied_reason: Optional[str] = None
    rollout: Optional[RolloutResult] = None
    receipt_signature: Optional[str] = None
    audit_records: list[str] = field(default_factory=list)


class RemediationEngine:
    def __init__(
        self,
        store: Store,
        change_windows: Optional[list[ChangeWindow]] = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.store = store
        self.change_windows = change_windows or []
        self.clock = clock

    # --- planning -------------------------------------------------------
    def plan(self, finding: Finding, asset: Asset, plugin: Plugin) -> RemediationPlan:
        key = MatrixKey(asset.criticality, finding.severity, finding.exploit_likely())
        decision = resolve(key)
        target = PluginTarget(asset_id=asset.asset_id,
                              address=(asset.ip_addresses or [asset.hostname or ""])[0])
        try:
            proposal = plugin.remediate(target, dry_run=True)
        except NotImplementedError:
            proposal = RemediationProposal(
                action_id=f"manual-{finding.finding_id}",
                description="No automated remediation available; manual playbook required.",
                dry_run_output="[MANUAL] Follow the generated playbook.",
                rollback_steps=[],
            )
        return RemediationPlan(finding, asset, decision, proposal)

    # --- gates ----------------------------------------------------------
    def approve(self, plan: RemediationPlan, approver: str, scanner_principal: str) -> None:
        enforce_separation_of_duties(scanner_principal, approver)
        plan.approved_by = approver
        self._audit(approver, "remediation.approved", plan.finding.finding_id,
                    {"action_id": plan.proposal.action_id, "mode": plan.decision.allowed_mode.value})

    def within_change_window(self, when: Optional[datetime] = None) -> bool:
        if not self.change_windows:
            return True   # no windows configured => unrestricted (dev default)
        when = when or self.clock()
        return any(w.contains(when) for w in self.change_windows)

    # --- apply ----------------------------------------------------------
    def apply(
        self,
        plan: RemediationPlan,
        actor: str,
        emergency_override: bool = False,
        health_fn: Optional[Callable[[CanaryRing], bool]] = None,
    ) -> RemediationOutcome:
        action_id = plan.proposal.action_id
        outcome = RemediationOutcome(action_id=action_id, applied=False)

        # Gate 1: mode must permit automation.
        if not plan.auto_applicable:
            outcome.denied_reason = (
                f"Policy requires {plan.decision.allowed_mode.value} — not auto-applicable."
            )
            self._audit(actor, "remediation.denied", plan.finding.finding_id,
                        {"reason": outcome.denied_reason}, outcome)
            return outcome

        # Gate 2: approval.
        if plan.requires_approval and not plan.approved_by:
            outcome.denied_reason = "Approval required but not granted."
            self._audit(actor, "remediation.denied", plan.finding.finding_id,
                        {"reason": outcome.denied_reason}, outcome)
            return outcome

        # Gate 3: change window (emergency override is audited).
        if not self.within_change_window() and not emergency_override:
            outcome.denied_reason = "Outside maintenance window."
            self._audit(actor, "remediation.denied", plan.finding.finding_id,
                        {"reason": outcome.denied_reason}, outcome)
            return outcome
        if emergency_override and not self.within_change_window():
            self._audit(actor, "remediation.emergency_override", plan.finding.finding_id,
                        {"action_id": action_id}, outcome)

        # Canary staged rollout (SIMULATED apply/health/rollback).
        rings = [
            CanaryRing("canary", [plan.asset.asset_id]),
            CanaryRing("fleet", [plan.asset.asset_id]),
        ]
        applied_log: list[str] = []
        health = health_fn or (lambda ring: True)  # default: healthy

        def apply_fn(ring: CanaryRing) -> None:
            applied_log.append(ring.name)  # SIMULATION: no host mutation

        def rollback_fn(ring: CanaryRing) -> None:
            self._audit(actor, "remediation.rolled_back", plan.finding.finding_id,
                        {"ring": ring.name, "action_id": action_id})

        rollout = staged_rollout(rings, apply_fn, health, rollback_fn)
        outcome.rollout = rollout
        outcome.applied = rollout.success

        event = "remediation.applied" if rollout.success else "remediation.rollback_completed"
        rec = self._audit(actor, event, plan.finding.finding_id, {
            "action_id": action_id,
            "mode": plan.decision.allowed_mode.value,
            "approved_by": plan.approved_by or "",
            "dry_run_output": plan.proposal.dry_run_output,
            "simulated": "true",
        }, outcome)
        outcome.receipt_signature = rec.signature
        return outcome

    # --- audit helper ---------------------------------------------------
    def _audit(self, actor: str, action: str, subject_id: str,
               details: dict, outcome: Optional[RemediationOutcome] = None) -> AuditRecord:
        rec = AuditRecord(
            record_id=str(uuid.uuid4()),
            actor=actor,
            action=action,
            subject_id=subject_id,
            timestamp=self.clock(),
            details={k: str(v) for k, v in details.items()},
        )
        self.store.append_audit(rec)
        if outcome is not None:
            outcome.audit_records.append(rec.record_id)
        return rec
