"""Network-exposure plugins (PRD §12.B reference playbook).

A configurable base check that flags a service reachable on a target port, plus
three concrete instances (RDP/SMB/Telnet). The remediation proposal is a
reversible firewall/NSG rule and DEFAULTS TO DRY-RUN — the engine decides
whether to apply.
"""

from __future__ import annotations

from ..plugin_sdk import (
    CheckResult,
    CheckStatus,
    Plugin,
    PluginConstraints,
    PluginMetadata,
    PluginTarget,
    RemediationProposal,
)
from ..probes import is_tcp_open


class PortExposurePlugin(Plugin):
    """Flags a TCP service reachable on `port`.

    `port` may be overridden per-target via target.params['port'] so the same
    check logic is testable against an ephemeral bound port.
    """

    def __init__(
        self,
        plugin_id: str,
        service_name: str,
        port: int,
        severity: str = "high",
        cve: list[str] | None = None,
        timeout_ms: int = 1_000,
    ) -> None:
        self.service_name = service_name
        self.port = port
        self.metadata = PluginMetadata(
            id=plugin_id,
            name=f"Internet-exposed {service_name} (TCP/{port})",
            cve=cve or [],
            severity=severity,
            requires_credentials=False,
        )
        self.constraints = PluginConstraints(
            max_runtime_ms=max(timeout_ms + 500, 1_000), network_access=True
        )

    def _resolve_port(self, target: PluginTarget) -> int:
        raw = target.params.get("port")
        return int(raw) if raw is not None else self.port

    def check(self, target: PluginTarget) -> CheckResult:
        port = self._resolve_port(target)
        timeout_ms = self.constraints.max_runtime_ms - 500
        if is_tcp_open(target.address, port, timeout_ms):
            return CheckResult(
                status=CheckStatus.FAIL,
                evidence={
                    "observation": f"{self.service_name} reachable on "
                                   f"{target.address}:{port}",
                    "protocol": "tcp",
                    "port": str(port),
                },
                remediation_hint=f"Restrict inbound access to {self.service_name} "
                                 f"(port {port}) to authorized source ranges only.",
            )
        return CheckResult(
            status=CheckStatus.PASS,
            evidence={"observation": f"{self.service_name} not reachable on port {port}"},
        )

    def remediate(self, target: PluginTarget, dry_run: bool = True) -> RemediationProposal:
        port = self._resolve_port(target)
        action_id = f"block-{self.service_name.lower()}-{target.asset_id}-{port}"
        rule = f"DENY inbound tcp/{port} from 0.0.0.0/0 (allow only approved CIDRs)"
        rollback = [
            f"Re-add prior inbound rule for tcp/{port}",
            "Validate authorized users can reconnect",
        ]
        dry_run_output = (
            f"[DRY-RUN] Would apply firewall/NSG rule: {rule}\n"
            f"[DRY-RUN] Target asset={target.asset_id} address={target.address}\n"
            f"[DRY-RUN] Rollback available: {'; '.join(rollback)}"
        )
        # SIMULATION: this MVP never mutates a real firewall. `applied` stays
        # False regardless of dry_run; a real backend would flip it under the
        # engine's governed apply path only.
        return RemediationProposal(
            action_id=action_id,
            description=f"Block public access to {self.service_name} on tcp/{port}",
            dry_run_output=dry_run_output,
            rollback_steps=rollback,
            applied=False,
        )


class OpenRdp(PortExposurePlugin):
    def __init__(self) -> None:
        super().__init__("net.exposed_rdp.3389", "RDP", 3389, severity="high")


class OpenSmb(PortExposurePlugin):
    def __init__(self) -> None:
        super().__init__("net.exposed_smb.445", "SMB", 445, severity="high")


class OpenTelnet(PortExposurePlugin):
    def __init__(self) -> None:
        super().__init__("net.exposed_telnet.23", "Telnet", 23, severity="critical")
