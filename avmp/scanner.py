"""Scanner node (PRD §4 Scanner Nodes).

Discovers reachable hosts over a CIDR and runs the sandboxed plugin set against
each target, turning FAIL results into Findings. In a distributed deployment
this runs as a containerized appliance and pushes findings to the Console over
TLS; here it returns them in-process.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Iterable, Optional

from .models import Finding, Severity, utcnow
from .plugin_sdk import CheckStatus, Plugin, PluginTarget, run_check
from .probes import tcp_connect_scan

# Common ports used purely for liveness discovery (non-credentialed).
_DISCOVERY_PORTS = [22, 23, 80, 135, 139, 443, 445, 3389]


class ScannerNode:
    def __init__(self, node_id: str = "scanner-0") -> None:
        self.node_id = node_id

    def discover(self, cidr: str, timeout_ms: int = 500, max_hosts: int = 256) -> list[str]:
        """Return hosts in `cidr` that answer on any common discovery port."""
        net = ipaddress.ip_network(cidr, strict=False)
        live: list[str] = []
        for i, host in enumerate(net.hosts()):
            if i >= max_hosts:
                break
            addr = str(host)
            if any(r.open for r in tcp_connect_scan(addr, _DISCOVERY_PORTS, timeout_ms)):
                live.append(addr)
        # A /32 has no .hosts(); handle single-address scans explicitly.
        if net.num_addresses == 1:
            addr = str(net.network_address)
            if any(r.open for r in tcp_connect_scan(addr, _DISCOVERY_PORTS, timeout_ms)):
                live.append(addr)
        return live

    def run_plugins(
        self,
        target: PluginTarget,
        plugins: Iterable[Plugin],
    ) -> list[Finding]:
        """Run each plugin under its sandbox budget; emit Findings for FAILs."""
        findings: list[Finding] = []
        for plugin in plugins:
            result = run_check(plugin, target)
            if result.status is CheckStatus.FAIL:
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        asset_id=target.asset_id,
                        plugin_id=plugin.metadata.id,
                        title=plugin.metadata.name,
                        severity=Severity(plugin.metadata.severity),
                        cve_ids=list(plugin.metadata.cve),
                        evidence=result.evidence,
                        remediation_hint=result.remediation_hint,
                        detected_at=utcnow(),
                    )
                )
            # PASS / NOT_APPLICABLE produce no finding; ERROR is intentionally
            # dropped here (a real node would emit a low-severity scan-quality
            # event so operators can spot flaky checks — PRD §11 false-positive
            # feedback loop).
        return findings
