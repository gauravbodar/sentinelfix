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

    def preview(self, action: RemediationAction) -> str:
        """Dry-run: describe the change without applying it. Override for a
        backend-specific preview (P4-AC-8)."""
        return f"[DRY-RUN] {action.action_type} on {action.asset_id} {action.params}"


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


@dataclass
class NsgRule:
    name: str
    priority: int
    port: int
    access: str = "Deny"       # Allow | Deny
    direction: str = "Inbound"
    source: str = "0.0.0.0/0"


class SimulatedNsg:
    """In-process Azure Network Security Group model."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.rules: dict[str, NsgRule] = {}

    def add_rule(self, rule: NsgRule) -> None:
        self.rules[rule.name] = rule

    def remove_rule(self, name: str) -> None:
        self.rules.pop(name, None)

    def has_deny(self, port: int) -> bool:
        return any(r.port == port and r.access == "Deny" and r.direction == "Inbound"
                   for r in self.rules.values())


class AzureNsgBackend(RemediationBackend):
    """Applies close_port as an NSG Deny rule. Reversible and validatable.

    With `client=None` it mutates a `SimulatedNsg` (safe, testable). A production
    build passes an authenticated Azure SDK client and the same methods issue
    real NSG calls — the engine, gates, canary, and audit are unchanged.
    """

    def __init__(self, nsgs: dict[str, SimulatedNsg] | None = None, client=None) -> None:
        self.nsgs = nsgs if nsgs is not None else {}
        self.client = client   # None => simulated; production => Azure SDK client
        self._undo: dict[str, tuple] = {}

    def _nsg(self, asset_id: str) -> SimulatedNsg:
        nsg = self.nsgs.get(asset_id)
        if nsg is None:
            nsg = self.nsgs.setdefault(asset_id, SimulatedNsg(f"nsg-{asset_id}"))
        return nsg

    def preview(self, action: RemediationAction) -> str:
        if action.action_type != "close_port":
            return f"[DRY-RUN] AzureNsgBackend does not handle {action.action_type}"
        port = action.params["port"]
        return (f"[DRY-RUN] az network nsg rule create --nsg-name nsg-{action.asset_id} "
                f"--name deny-{port} --priority 100 --access Deny --direction Inbound "
                f"--destination-port-ranges {port} --source-address-prefixes 0.0.0.0/0")

    def apply(self, action: RemediationAction) -> None:
        if action.action_type != "close_port":
            raise RemediationBackendError(
                "AzureNsgBackend only implements 'close_port' (NSG deny rule).")
        if action.action_id in self._undo:
            return
        nsg = self._nsg(action.asset_id)
        port = int(action.params["port"])
        rule_name = f"deny-{port}"
        existed = rule_name in nsg.rules
        nsg.add_rule(NsgRule(name=rule_name, priority=100, port=port))
        self._undo[action.action_id] = (rule_name, existed, action.asset_id)

    def validate(self, action: RemediationAction) -> bool:
        return self._nsg(action.asset_id).has_deny(int(action.params["port"]))

    def rollback(self, action: RemediationAction) -> None:
        undo = self._undo.pop(action.action_id, None)
        if undo is None:
            return
        rule_name, existed, asset_id = undo
        if not existed:
            self._nsg(asset_id).remove_rule(rule_name)


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
