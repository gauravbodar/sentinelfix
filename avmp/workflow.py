"""Manual remediation workflow (Phase 2 D4).

A guarded finding-lifecycle state machine with risk-driven SLAs, a verification
loop (a re-scan must PASS before `verified`), and a false-positive feedback path.
Every transition is written to the tamper-evident WORM audit log (reusing
avmp.store), so no new audit primitive is introduced.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Callable, Optional

from .models import Asset, AuditRecord, Finding, utcnow
from .store import Store


class FindingState(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


_TERMINAL = {FindingState.CLOSED, FindingState.RISK_ACCEPTED, FindingState.FALSE_POSITIVE}

# Allowed transitions (guards). Anything not listed is rejected.
_ALLOWED: dict[FindingState, set[FindingState]] = {
    FindingState.OPEN: {FindingState.TRIAGED, FindingState.FALSE_POSITIVE, FindingState.RISK_ACCEPTED},
    FindingState.TRIAGED: {FindingState.ASSIGNED, FindingState.FALSE_POSITIVE, FindingState.RISK_ACCEPTED},
    FindingState.ASSIGNED: {FindingState.IN_PROGRESS, FindingState.TRIAGED},
    FindingState.IN_PROGRESS: {FindingState.REMEDIATED, FindingState.ASSIGNED},
    FindingState.REMEDIATED: {FindingState.VERIFIED, FindingState.IN_PROGRESS},
    FindingState.VERIFIED: {FindingState.CLOSED},
    FindingState.CLOSED: set(),
    FindingState.RISK_ACCEPTED: {FindingState.OPEN},
    FindingState.FALSE_POSITIVE: {FindingState.OPEN},
}

# Risk-score -> SLA hours (PRD §6 SLA timers, driven by prioritization).
def sla_hours_for_risk(risk: float) -> int:
    if risk >= 90:
        return 24
    if risk >= 70:
        return 72
    if risk >= 40:
        return 168
    return 720


class IllegalTransition(Exception):
    pass


class VerificationFailed(Exception):
    pass


@dataclass
class FindingTicket:
    finding_id: str
    asset_id: str
    state: FindingState
    risk_score: float
    created_at: str
    sla_due: str
    assignee: Optional[str] = None
    updated_at: str = ""
    history: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FindingTicket":
        d = dict(d)
        d["state"] = FindingState(d["state"])
        return cls(**d)


class WorkflowEngine:
    def __init__(self, store: Store, clock: Callable[[], datetime] = utcnow) -> None:
        self.store = store
        self.clock = clock

    # --- lifecycle ------------------------------------------------------
    def open_ticket(self, finding: Finding, risk_score: float, asset: Asset,
                    actor: str = "system") -> FindingTicket:
        now = self.clock()
        due = now + timedelta(hours=sla_hours_for_risk(risk_score))
        ticket = FindingTicket(
            finding_id=finding.finding_id, asset_id=finding.asset_id,
            state=FindingState.OPEN, risk_score=risk_score,
            created_at=now.isoformat(), sla_due=due.isoformat(),
            updated_at=now.isoformat(),
            history=[{"at": now.isoformat(), "actor": actor, "to": FindingState.OPEN.value}],
        )
        self.store.upsert_ticket(finding.finding_id, ticket.to_dict())
        self._audit(actor, "workflow.opened", finding.finding_id,
                    {"risk": str(risk_score), "sla_due": ticket.sla_due})
        return ticket

    def get(self, finding_id: str) -> FindingTicket:
        d = self.store.get_ticket(finding_id)
        if d is None:
            raise KeyError(f"No ticket for finding {finding_id}")
        return FindingTicket.from_dict(d)

    def assign(self, finding_id: str, assignee: str, actor: str) -> FindingTicket:
        ticket = self.transition(finding_id, FindingState.ASSIGNED, actor,
                                 note=f"assigned to {assignee}")
        ticket.assignee = assignee
        self.store.upsert_ticket(finding_id, ticket.to_dict())
        return ticket

    def transition(self, finding_id: str, to_state: FindingState, actor: str,
                   note: str = "", verify_fn: Optional[Callable[[], bool]] = None) -> FindingTicket:
        ticket = self.get(finding_id)
        if to_state not in _ALLOWED.get(ticket.state, set()):
            raise IllegalTransition(f"{ticket.state.value} -> {to_state.value} not allowed")

        # Verification gate: cannot reach VERIFIED without a passing re-scan.
        if to_state is FindingState.VERIFIED:
            if verify_fn is None or not verify_fn():
                raise VerificationFailed(
                    "Re-scan did not confirm remediation; cannot mark verified.")

        now = self.clock()
        ticket.state = to_state
        ticket.updated_at = now.isoformat()
        ticket.history.append({"at": now.isoformat(), "actor": actor,
                               "to": to_state.value, "note": note})
        self.store.upsert_ticket(finding_id, ticket.to_dict())
        self._audit(actor, f"workflow.{to_state.value}", finding_id, {"note": note})
        return ticket

    def mark_false_positive(self, finding_id: str, actor: str, reason: str) -> FindingTicket:
        ticket = self.transition(finding_id, FindingState.FALSE_POSITIVE, actor, note=reason)
        # Feedback loop to plugin authors (PRD §11).
        self._audit(actor, "workflow.false_positive_feedback", finding_id,
                    {"reason": reason})
        return ticket

    # --- SLA ------------------------------------------------------------
    def sla_breached(self, finding_id: str, now: Optional[datetime] = None) -> bool:
        ticket = self.get(finding_id)
        if ticket.state in _TERMINAL:
            return False
        now = now or self.clock()
        return now > datetime.fromisoformat(ticket.sla_due)

    # --- audit helper ---------------------------------------------------
    def _audit(self, actor: str, action: str, subject_id: str, details: dict) -> None:
        self.store.append_audit(AuditRecord(
            record_id=str(uuid.uuid4()), actor=actor, action=action,
            subject_id=subject_id, timestamp=self.clock(),
            details={k: str(v) for k, v in details.items()},
        ))
