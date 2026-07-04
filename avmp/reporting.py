"""Reporting & evidence (PRD §8).

Generates the technical report (Markdown), a findings CSV, a per-finding
remediation playbook (PRD §6 template), and a remediation ledger from the WORM
audit log.
"""

from __future__ import annotations

import csv
import io
from typing import Iterable

from .models import Asset, Finding
from .store import Store


def _sorted_by_risk(findings: list[Finding], assets: dict[str, Asset]) -> list[Finding]:
    def score(f: Finding) -> float:
        asset = assets.get(f.asset_id)
        crit = asset.criticality if asset else None
        return f.risk_score(crit) if crit else f.risk_score()
    return sorted(findings, key=score, reverse=True)


def technical_report(findings: list[Finding], assets: list[Asset]) -> str:
    amap = {a.asset_id: a for a in assets}
    ordered = _sorted_by_risk(findings, amap)
    lines = ["# SentinelFix — Technical Report", ""]
    lines.append(f"Assets: {len(assets)} | Findings: {len(findings)}")
    lines.append("")
    lines.append("## Prioritized findings (by risk score)")
    lines.append("")
    lines.append("| Risk | Severity | Asset | Finding | CVEs | EPSS | KEV |")
    lines.append("| ---: | -------- | ----- | ------- | ---- | ---: | :-: |")
    for f in ordered:
        asset = amap.get(f.asset_id)
        crit = asset.criticality if asset else None
        risk = f.risk_score(crit) if crit else f.risk_score()
        cves = ", ".join(f.cve_ids) or "—"
        epss = f"{f.epss_score:.2f}" if f.epss_score is not None else "—"
        kev = "yes" if f.in_kev else "no"
        aname = (asset.hostname or asset.asset_id) if asset else f.asset_id
        lines.append(
            f"| {risk} | {f.severity.value} | {aname} | {f.title} | {cves} | {epss} | {kev} |"
        )
    return "\n".join(lines) + "\n"


def findings_csv(findings: list[Finding], assets: list[Asset]) -> str:
    amap = {a.asset_id: a for a in assets}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["finding_id", "asset", "plugin_id", "title", "severity",
                "risk_score", "cves", "cvss", "epss", "in_kev"])
    for f in _sorted_by_risk(findings, amap):
        asset = amap.get(f.asset_id)
        crit = asset.criticality if asset else None
        risk = f.risk_score(crit) if crit else f.risk_score()
        w.writerow([
            f.finding_id, f.asset_id, f.plugin_id, f.title, f.severity.value,
            risk, "|".join(f.cve_ids), f.cvss_score or "", f.epss_score or "",
            "true" if f.in_kev else "false",
        ])
    return buf.getvalue()


def playbook(finding: Finding, asset: Asset, decision_mode: str,
             rollback_steps: Iterable[str], est_downtime: str = "< 1 min (simulated)") -> str:
    """Per-finding remediation playbook (PRD §6 template)."""
    steps = list(rollback_steps) or ["N/A — manual remediation, define rollback per SOP"]
    return "\n".join([
        f"# Remediation Playbook — {finding.title}",
        "",
        f"- **Finding ID:** {finding.finding_id}",
        f"- **Affected asset:** {asset.hostname or asset.asset_id} "
        f"({', '.join(asset.ip_addresses) or 'n/a'}) — criticality {asset.criticality.value}",
        f"- **Root cause:** {finding.remediation_hint or finding.title}",
        f"- **Impact if exploited:** severity {finding.severity.value}; "
        f"EPSS {finding.epss_score if finding.epss_score is not None else 'n/a'}; "
        f"KEV: {'yes' if finding.in_kev else 'no'}",
        f"- **Allowed remediation mode (policy):** {decision_mode}",
        "",
        "## Recommended fix (step-by-step)",
        f"1. {finding.remediation_hint or 'Apply vendor-recommended mitigation.'}",
        "",
        "## Pre-fix checks",
        "- Confirm asset owner and active sessions",
        "- Snapshot / backup as required",
        "- Health probe passes before change",
        "",
        "## Post-fix validation",
        "- Re-run the detecting check; expect PASS",
        "- Confirm authorized connectivity preserved",
        "",
        "## Rollback steps",
        *[f"- {s}" for s in steps],
        "",
        f"## Estimated downtime\n- {est_downtime}",
        "",
        "## Risk notes",
        "- Applied via canary ring with automated rollback on health failure.",
    ]) + "\n"


def remediation_ledger(store: Store) -> str:
    """Chronological record of remediation actions from the WORM audit log."""
    lines = ["# Remediation Ledger (from WORM audit log)", ""]
    verified = store.verify_audit_chain()
    lines.append(f"Audit chain integrity: {'VERIFIED ✅' if verified else 'TAMPERED ❌'}")
    lines.append("")
    lines.append("| Time (UTC) | Actor | Action | Subject | Signature (short) |")
    lines.append("| ---------- | ----- | ------ | ------- | ----------------- |")
    for rec in store.iter_audit():
        sig = (rec.get("signature") or "")[:12]
        lines.append(
            f"| {rec['timestamp']} | {rec['actor']} | {rec['action']} "
            f"| {rec['subject_id']} | {sig} |"
        )
    return "\n".join(lines) + "\n"
