"""Controllable host model for remediation (Phase 3).

Remediation backends need something real to mutate and roll back. A production
adapter would reconfigure a live firewall/host over SSH/WinRM or an Azure NSG
API (Phase 4). Until that adapter exists, `SimulatedHost` is a real, in-process
representation of an asset's remediable state so that apply / post-fix
validation / rollback exercise genuine, reversible logic — not a no-op.

The state here (firewall denies, service enablement, secret values) is the same
surface the three MVP safe auto-fix actions operate on (PRD §6 Safe Auto:
"close unused port, disable noncritical service, rotate non-production secret").
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SimulatedHost:
    asset_id: str
    open_ports: set[int] = field(default_factory=set)
    firewall_blocked: set[int] = field(default_factory=set)
    services: dict[str, bool] = field(default_factory=dict)   # name -> enabled
    secrets: dict[str, str] = field(default_factory=dict)     # name -> value

    # --- firewall -------------------------------------------------------
    def is_port_exposed(self, port: int) -> bool:
        return port in self.open_ports and port not in self.firewall_blocked

    def block_port(self, port: int) -> None:
        self.firewall_blocked.add(port)

    def unblock_port(self, port: int) -> None:
        self.firewall_blocked.discard(port)

    # --- services -------------------------------------------------------
    def service_enabled(self, name: str) -> bool:
        return self.services.get(name, True)

    def set_service(self, name: str, enabled: bool) -> None:
        self.services[name] = enabled

    # --- secrets --------------------------------------------------------
    def get_secret(self, name: str) -> str | None:
        return self.secrets.get(name)

    def set_secret(self, name: str, value: str) -> None:
        self.secrets[name] = value


class TargetRegistry:
    """Maps asset_id -> SimulatedHost. A production build swaps this for real
    host/cloud connections behind the same lookup."""

    def __init__(self) -> None:
        self._hosts: dict[str, SimulatedHost] = {}

    def register(self, host: SimulatedHost) -> SimulatedHost:
        self._hosts[host.asset_id] = host
        return host

    def get(self, asset_id: str) -> SimulatedHost | None:
        return self._hosts.get(asset_id)
