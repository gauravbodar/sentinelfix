"""Playbook authoring backend + linkage engine (Phase 2 D3).

The MVP only *rendered* a fixed playbook layout. This adds a versioned template
model with a draft->review->published lifecycle, persistence, and an engine that
links the right published playbook to each finding (by plugin id, then CVE, then
severity). The web authoring UI (D3.2) sits on top of this and is deferred until
the UI-stack decision; everything here is headless and fully testable.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

from .models import Finding, Severity, utcnow


class PlaybookState(str, Enum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    PUBLISHED = "published"
    ARCHIVED = "archived"


@dataclass
class PlaybookTemplate:
    """Covers the 10 PRD §6 playbook fields, plus binding + lifecycle metadata."""

    playbook_id: str
    title: str
    version: int = 1
    state: PlaybookState = PlaybookState.DRAFT
    # Binding — how this playbook attaches to findings (most specific wins).
    binds_plugin_ids: list[str] = field(default_factory=list)
    binds_cve_ids: list[str] = field(default_factory=list)
    binds_severities: list[str] = field(default_factory=list)
    # Content (PRD §6 template).
    root_cause: str = ""
    impact: str = ""
    fix_steps: list[str] = field(default_factory=list)
    pre_checks: list[str] = field(default_factory=list)
    post_validation: list[str] = field(default_factory=list)
    rollback_steps: list[str] = field(default_factory=list)
    est_downtime: str = "unknown"
    risk_notes: str = ""
    updated_by: str = "system"
    updated_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "PlaybookTemplate":
        d = dict(d)
        d["state"] = PlaybookState(d.get("state", "draft"))
        return cls(**d)


class PlaybookRepository:
    def __init__(self, store=None) -> None:
        self.store = store
        self._mem: dict[tuple[str, int], PlaybookTemplate] = {}

    # --- persistence ----------------------------------------------------
    def save(self, template: PlaybookTemplate) -> PlaybookTemplate:
        template.updated_at = template.updated_at or utcnow().isoformat()
        self._mem[(template.playbook_id, template.version)] = template
        if self.store is not None:
            self.store.upsert_playbook(template.playbook_id, template.version, template.to_dict())
        return template

    def _all(self) -> list[PlaybookTemplate]:
        if self.store is not None:
            return [PlaybookTemplate.from_dict(d) for d in self.store.list_playbooks()]
        return list(self._mem.values())

    def list(self) -> list[PlaybookTemplate]:
        return self._all()

    def published(self) -> list[PlaybookTemplate]:
        return [t for t in self._all() if t.state is PlaybookState.PUBLISHED]

    # --- lifecycle ------------------------------------------------------
    def submit_for_review(self, playbook_id: str, version: int, actor: str) -> PlaybookTemplate:
        t = self._get(playbook_id, version)
        if t.state is not PlaybookState.DRAFT:
            raise ValueError(f"Only DRAFT can be submitted for review (was {t.state.value}).")
        t.state = PlaybookState.IN_REVIEW
        t.updated_by = actor
        return self.save(t)

    def publish(self, playbook_id: str, version: int, actor: str) -> PlaybookTemplate:
        t = self._get(playbook_id, version)
        if t.state not in (PlaybookState.DRAFT, PlaybookState.IN_REVIEW):
            raise ValueError(f"Cannot publish from state {t.state.value}.")
        # Separation of duties: the author/last editor cannot publish their own
        # playbook (governance parity with the remediation approval flow).
        if t.updated_by == actor:
            raise PermissionError(
                "Separation of duties: the author cannot publish their own playbook.")
        # Only one published version per playbook id — archive the rest.
        for other in self._all():
            if other.playbook_id == playbook_id and other.version != version \
                    and other.state is PlaybookState.PUBLISHED:
                other.state = PlaybookState.ARCHIVED
                self.save(other)
        t.state = PlaybookState.PUBLISHED
        t.updated_by = actor
        return self.save(t)

    def _get(self, playbook_id: str, version: int) -> PlaybookTemplate:
        for t in self._all():
            if t.playbook_id == playbook_id and t.version == version:
                return t
        raise KeyError(f"Playbook {playbook_id} v{version} not found.")

    def get(self, playbook_id: str, version: int) -> PlaybookTemplate:
        return self._get(playbook_id, version)

    def versions(self, playbook_id: str) -> list[int]:
        return sorted(t.version for t in self._all() if t.playbook_id == playbook_id)

    def next_version(self, playbook_id: str) -> int:
        vs = self.versions(playbook_id)
        return (max(vs) + 1) if vs else 1

    def new_version(self, playbook_id: str, actor: str) -> PlaybookTemplate:
        """Clone the latest version into a fresh DRAFT for re-authoring."""
        latest = max((t for t in self._all() if t.playbook_id == playbook_id),
                     key=lambda t: t.version, default=None)
        if latest is None:
            raise KeyError(f"Playbook {playbook_id} not found.")
        clone = PlaybookTemplate.from_dict(latest.to_dict())
        clone.version = self.next_version(playbook_id)
        clone.state = PlaybookState.DRAFT
        clone.updated_by = actor
        clone.updated_at = ""
        return self.save(clone)

    # --- linkage engine (D3.3) -----------------------------------------
    def match(self, finding: Finding) -> Optional[PlaybookTemplate]:
        """Return the best published playbook for a finding.

        Priority: plugin-id bind > CVE bind > severity bind. Higher version
        wins ties.
        """
        candidates = self.published()

        def best(pred) -> Optional[PlaybookTemplate]:
            hits = [t for t in candidates if pred(t)]
            return max(hits, key=lambda t: t.version) if hits else None

        return (
            best(lambda t: finding.plugin_id in t.binds_plugin_ids)
            or best(lambda t: any(c in t.binds_cve_ids for c in finding.cve_ids))
            or best(lambda t: finding.severity.value in t.binds_severities)
        )

    def attach(self, finding: Finding) -> str:
        """Return the linked playbook id, or a fallback marker (100% coverage)."""
        t = self.match(finding)
        return t.playbook_id if t else "generated-fallback"


# --------------------------------------------------------------------------- #
# Starter library (D3.4) — >=10 authored, published playbooks                  #
# --------------------------------------------------------------------------- #
def _pb(pid, title, plugins=(), cves=(), sevs=(), root="", impact="", fix=(),
        pre=(), post=(), rollback=(), downtime="< 5 min", notes="") -> PlaybookTemplate:
    return PlaybookTemplate(
        playbook_id=pid, title=title, state=PlaybookState.PUBLISHED,
        binds_plugin_ids=list(plugins), binds_cve_ids=list(cves),
        binds_severities=list(sevs), root_cause=root, impact=impact,
        fix_steps=list(fix), pre_checks=list(pre), post_validation=list(post),
        rollback_steps=list(rollback), est_downtime=downtime, risk_notes=notes,
        updated_at=utcnow().isoformat(),
    )


def builtin_playbooks() -> list[PlaybookTemplate]:
    common_pre = ["Confirm asset owner", "Snapshot/backup as required", "Health probe passes"]
    common_post = ["Re-run detecting check; expect PASS", "Confirm authorized connectivity"]
    return [
        _pb("pb.exposed_rdp", "Restrict exposed RDP", plugins=["net.exposed_rdp.3389", "demo.exposed_rdp"],
            cves=["CVE-2019-0708"], root="RDP (3389) reachable from untrusted ranges",
            impact="Remote code execution / lateral movement",
            fix=["Deny inbound tcp/3389 from 0.0.0.0/0", "Allow only approved CIDRs / VPN"],
            pre=common_pre, post=common_post,
            rollback=["Re-add prior inbound rule for tcp/3389", "Validate reconnect"]),
        _pb("pb.exposed_smb", "Restrict exposed SMB", plugins=["net.exposed_smb.445"],
            cves=["CVE-2017-0144"], root="SMB (445) reachable from untrusted ranges",
            impact="Worming RCE (EternalBlue class)",
            fix=["Deny inbound tcp/445 from untrusted ranges", "Disable SMBv1"],
            pre=common_pre, post=common_post, rollback=["Restore prior firewall rule"]),
        _pb("pb.exposed_telnet", "Disable Telnet", plugins=["net.exposed_telnet.23"],
            sevs=["critical"], root="Cleartext Telnet (23) exposed",
            impact="Credential interception",
            fix=["Disable telnet service", "Replace with SSH"],
            pre=common_pre, post=common_post, rollback=["Re-enable service if business-critical (not recommended)"]),
        _pb("pb.printnightmare", "Mitigate PrintNightmare", cves=["CVE-2021-34527"],
            root="Print Spooler RCE", impact="SYSTEM-level RCE",
            fix=["Apply vendor patch", "Disable Print Spooler where not needed"],
            pre=common_pre, post=common_post, rollback=["Re-enable spooler post-validation"],
            downtime="reboot window"),
        _pb("pb.log4shell", "Remediate Log4Shell", cves=["CVE-2021-44228"],
            root="Log4j JNDI lookup RCE", impact="Unauthenticated RCE",
            fix=["Upgrade log4j to fixed version", "Set log4j2.formatMsgNoLookups=true as interim"],
            pre=common_pre, post=common_post, rollback=["Redeploy prior artifact"]),
        _pb("pb.critical_generic", "Critical finding — manual remediation", sevs=["critical"],
            root="Critical severity finding", impact="High business/mission impact",
            fix=["Engage system owner", "Apply vendor guidance in change window"],
            pre=common_pre, post=common_post, rollback=["Per vendor guidance"], downtime="scheduled"),
        _pb("pb.high_generic", "High finding — staged remediation", sevs=["high"],
            root="High severity finding", impact="Significant exposure",
            fix=["Stage fix to canary", "Validate then roll out"],
            pre=common_pre, post=common_post, rollback=["Roll back canary on health failure"]),
        _pb("pb.medium_generic", "Medium finding — safe remediation", sevs=["medium"],
            root="Medium severity finding", impact="Moderate exposure",
            fix=["Apply reversible mitigation"], pre=common_pre, post=common_post,
            rollback=["Revert mitigation"]),
        _pb("pb.low_generic", "Low finding — routine remediation", sevs=["low"],
            root="Low severity finding", impact="Minor exposure",
            fix=["Apply during routine maintenance"], pre=common_pre, post=common_post,
            rollback=["Revert change"]),
        _pb("pb.info_generic", "Informational — no action", sevs=["informational"],
            root="Informational", impact="None", fix=["Document; no action required"],
            post=["N/A"], rollback=["N/A"], downtime="none"),
    ]


def load_builtin_library(repo: PlaybookRepository) -> int:
    for t in builtin_playbooks():
        repo.save(t)
    return len(repo.published())
