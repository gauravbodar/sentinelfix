"""Change-control integration (Phase 4 D6 / P4-AC-7).

A remediation must ride on an approved change request. The engine (when wired to
an ITSM connector) auto-creates an RFC and BLOCKS auto-apply until the RFC is
approved; the RFC id is written into the WORM audit.

`MockServiceNow` is an in-process stand-in for a real ServiceNow/Jira instance.
A production connector implements the same `ITSMConnector` interface over the
vendor REST API.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RFCState(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"
    CLOSED = "closed"


@dataclass
class ChangeRequest:
    rfc_id: str
    short_description: str
    asset_id: str
    action_id: str
    created_by: str
    state: RFCState = RFCState.PENDING_APPROVAL
    approver: Optional[str] = None
    history: list[str] = field(default_factory=list)


class ITSMConnector(ABC):
    @abstractmethod
    def create_rfc(self, short_description: str, asset_id: str, action_id: str,
                   created_by: str) -> ChangeRequest: ...

    @abstractmethod
    def get(self, rfc_id: str) -> Optional[ChangeRequest]: ...

    @abstractmethod
    def approve(self, rfc_id: str, approver: str) -> ChangeRequest: ...

    @abstractmethod
    def reject(self, rfc_id: str, approver: str) -> ChangeRequest: ...

    @abstractmethod
    def set_state(self, rfc_id: str, state: RFCState) -> ChangeRequest: ...


class MockServiceNow(ITSMConnector):
    def __init__(self) -> None:
        self._rfcs: dict[str, ChangeRequest] = {}
        self._seq = 0

    def create_rfc(self, short_description, asset_id, action_id, created_by):
        self._seq += 1
        rfc_id = f"CHG{self._seq:07d}"
        rfc = ChangeRequest(rfc_id, short_description, asset_id, action_id, created_by)
        rfc.history.append("created (pending_approval)")
        self._rfcs[rfc_id] = rfc
        return rfc

    def get(self, rfc_id):
        return self._rfcs.get(rfc_id)

    def approve(self, rfc_id, approver):
        rfc = self._require(rfc_id)
        rfc.state = RFCState.APPROVED
        rfc.approver = approver
        rfc.history.append(f"approved by {approver}")
        return rfc

    def reject(self, rfc_id, approver):
        rfc = self._require(rfc_id)
        rfc.state = RFCState.REJECTED
        rfc.approver = approver
        rfc.history.append(f"rejected by {approver}")
        return rfc

    def set_state(self, rfc_id, state):
        rfc = self._require(rfc_id)
        rfc.state = state
        rfc.history.append(f"state -> {state.value}")
        return rfc

    def _require(self, rfc_id) -> ChangeRequest:
        rfc = self._rfcs.get(rfc_id)
        if rfc is None:
            raise KeyError(f"No such RFC {rfc_id}")
        return rfc
