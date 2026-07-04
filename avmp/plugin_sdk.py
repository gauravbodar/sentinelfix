"""Plugin SDK: contract + sandboxed runner (PRD §5, §12.A).

A plugin's check() is read-only. remediate() is optional and dry-run by default.
The runner enforces the per-plugin runtime budget in a worker thread and
converts any crash/timeout into a structured ERROR result rather than letting a
misbehaving plugin take down the scanner (PRD §5 resource/time limits).
"""

from __future__ import annotations

import queue
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class PluginMetadata:
    id: str
    name: str
    cve: list[str] = field(default_factory=list)
    severity: str = "medium"
    requires_credentials: bool = False


@dataclass
class PluginConstraints:
    max_runtime_ms: int = 5_000
    network_access: bool = False


@dataclass
class CheckResult:
    status: CheckStatus
    evidence: dict[str, str] = field(default_factory=dict)
    remediation_hint: Optional[str] = None


@dataclass
class RemediationProposal:
    action_id: str
    description: str
    dry_run_output: str
    rollback_steps: list[str] = field(default_factory=list)
    applied: bool = False


@dataclass
class PluginTarget:
    asset_id: str
    address: str
    credentials_ref: Optional[str] = None
    # Optional per-scan overrides (e.g. a port to probe) — never raw secrets.
    params: dict[str, str] = field(default_factory=dict)


class Plugin(ABC):
    metadata: PluginMetadata
    constraints: PluginConstraints = PluginConstraints()

    @abstractmethod
    def check(self, target: PluginTarget) -> CheckResult:
        """Read-only probe of the target."""
        raise NotImplementedError

    def remediate(self, target: PluginTarget, dry_run: bool = True) -> RemediationProposal:
        """Optional. Propose a reversible fix; dry-run by default.

        A plugin never decides to apply — the remediation engine's policy matrix
        and approval workflow gate any non-dry-run apply.
        """
        raise NotImplementedError("This plugin does not implement remediation.")


def run_check(plugin: Plugin, target: PluginTarget) -> CheckResult:
    """Run plugin.check() under its runtime budget in a worker thread."""
    result_q: "queue.Queue" = queue.Queue(maxsize=1)

    def _worker() -> None:
        try:
            result_q.put(plugin.check(target))
        except Exception as exc:  # noqa: BLE001 - contain arbitrary plugin faults
            result_q.put(CheckResult(CheckStatus.ERROR, evidence={"error": repr(exc)}))

    t = threading.Thread(target=_worker, daemon=True)
    started = time.monotonic()
    t.start()
    t.join(timeout=plugin.constraints.max_runtime_ms / 1000.0)
    if t.is_alive():
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return CheckResult(
            CheckStatus.ERROR,
            evidence={"error": f"timeout after {elapsed_ms}ms "
                               f"(budget {plugin.constraints.max_runtime_ms}ms)"},
        )
    return result_q.get()
