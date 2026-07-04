"""Remediation backends + safe auto-fix actions (Phase 3).

A backend turns a governed `RemediationAction` into a real, reversible change on
a target, and can validate that the change took (post-fix validation). The MVP
ships `HostModelBackend`, which operates on the controllable `SimulatedHost`
model and implements the three PRD §6 "Safe Auto" actions:

  * close_port      — add a firewall deny for an exposed port
  * disable_service — disable a noncritical service
  * rotate_secret   — rotate a non-production secret

Every action records an undo so rollback is exact. A production backend
(SSH/WinRM/Azure NSG) implements the same interface — the engine, policy gates,
canary, and audit trail are unchanged.
"""

from __future__ import annotations

import secrets as _secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from .targets import TargetRegistry

SAFE_ACTION_TYPES = {"close_port", "disable_service", "rotate_secret"}


class RemediationBackendError(Exception):
    pass


@dataclass
class RemediationAction:
    action_id: str
    action_type: str
    asset_id: str
    params: dict[str, str] = field(default_factory=dict)
    description: str = ""


class RemediationBackend(ABC):
    @abstractmethod
    def apply(self, action: RemediationAction) -> None: ...

    @abstractmethod
    def rollback(self, action: RemediationAction) -> None: ...

    @abstractmethod
    def validate(self, action: RemediationAction) -> bool:
        """Post-fix validation: return True iff the change is in effect."""
        ...


class HostModelBackend(RemediationBackend):
    def __init__(self, registry: TargetRegistry) -> None:
        self.registry = registry
        self._undo: dict[str, tuple] = {}

    def _host(self, action: RemediationAction):
        host = self.registry.get(action.asset_id)
        if host is None:
            raise RemediationBackendError(f"No target registered for {action.asset_id}")
        return host

    # --- apply (idempotent; records exact undo) -------------------------
    def apply(self, action: RemediationAction) -> None:
        if action.action_type not in SAFE_ACTION_TYPES:
            raise RemediationBackendError(
                f"'{action.action_type}' is not a safe auto-fix action; "
                f"must be one of {sorted(SAFE_ACTION_TYPES)}")
        if action.action_id in self._undo:
            return  # already applied — idempotent
        host = self._host(action)

        if action.action_type == "close_port":
            port = int(action.params["port"])
            was_blocked = port in host.firewall_blocked
            host.block_port(port)
            self._undo[action.action_id] = ("close_port", port, was_blocked)

        elif action.action_type == "disable_service":
            name = action.params["service"]
            prev = host.service_enabled(name)
            host.set_service(name, False)
            self._undo[action.action_id] = ("disable_service", name, prev)

        elif action.action_type == "rotate_secret":
            name = action.params["secret"]
            prev = host.get_secret(name)
            new_value = action.params.get("new_value") or _secrets.token_hex(16)
            host.set_secret(name, new_value)
            self._undo[action.action_id] = ("rotate_secret", name, prev)

    # --- validate (post-fix) --------------------------------------------
    def validate(self, action: RemediationAction) -> bool:
        host = self._host(action)
        if action.action_type == "close_port":
            return not host.is_port_exposed(int(action.params["port"]))
        if action.action_type == "disable_service":
            return host.service_enabled(action.params["service"]) is False
        if action.action_type == "rotate_secret":
            name = action.params["secret"]
            old = action.params.get("old_value")
            cur = host.get_secret(name)
            return cur is not None and cur != old
        return False

    # --- rollback (exact reversal) --------------------------------------
    def rollback(self, action: RemediationAction) -> None:
        undo = self._undo.pop(action.action_id, None)
        if undo is None:
            return  # nothing applied
        host = self._host(action)
        kind = undo[0]
        if kind == "close_port":
            _, port, was_blocked = undo
            if not was_blocked:
                host.unblock_port(port)
        elif kind == "disable_service":
            _, name, prev = undo
            host.set_service(name, prev)
        elif kind == "rotate_secret":
            _, name, prev = undo
            if prev is None:
                host.secrets.pop(name, None)
            else:
                host.set_secret(name, prev)


def action_from_finding(finding, proposal) -> Optional[RemediationAction]:
    """Derive a safe auto-fix action from a finding + its plugin proposal.

    Network-exposure findings carry the port in evidence -> close_port. Returns
    None when no safe automated action maps to the finding (engine falls back to
    the simulated/manual path)."""
    port = finding.evidence.get("port") if finding.evidence else None
    if port:
        return RemediationAction(
            action_id=proposal.action_id,
            action_type="close_port",
            asset_id=finding.asset_id,
            params={"port": str(port)},
            description=proposal.description,
        )
    return None
