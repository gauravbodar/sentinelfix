"""Reporting & evidence (PRD §8).

Generates the technical report (Markdown), a findings CSV, a per-finding
remediation playbook (PRD §6 template), and a remediation ledger from the WORM
audit log.
"""

from __future__ import annotations

import csv
import io
from typing import Iterable, Optional

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


def executive_summary(findings: list[Finding], assets: list[Asset], store: Store,
                      top_n: int = 5) -> str:
    """Executive summary: top risks, severity mix, trend line, MTTR (PRD §8, D5)."""
    amap = {a.asset_id: a for a in assets}
    ordered = _sorted_by_risk(findings, amap)

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    lines = ["# SentinelFix — Executive Summary", ""]
    lines.append(f"Assets: {len(assets)} | Findings: {len(findings)} | "
                 f"VDB entries: {store.vdb_count()} (updated {store.vdb_latest_update() or 'n/a'})")
    lines.append("")
    lines.append("## Severity mix")
    for sev in ("critical", "high", "medium", "low", "informational"):
        if sev in sev_counts:
            lines.append(f"- {sev}: {sev_counts[sev]}")
    lines.append("")
    lines.append(f"## Top {top_n} risks")
    for f in ordered[:top_n]:
        asset = amap.get(f.asset_id)
        crit = asset.criticality if asset else None
        risk = f.risk_score(crit) if crit else f.risk_score()
        aname = (asset.hostname or asset.asset_id) if asset else f.asset_id
        lines.append(f"- **{risk}** — {f.title} on {aname} "
                     f"({'KEV' if f.in_kev else 'no-KEV'})")
    lines.append("")

    # Trend line from persisted risk snapshots.
    snaps = store.list_risk_snapshots()
    lines.append("## Risk trend (recent scans)")
    if snaps:
        for s in snaps[-6:]:
            lines.append(f"- {s.get('taken_at', '?')}: total_risk={s.get('total_risk', 0)} "
                         f"findings={s.get('finding_count', 0)}")
        if len(snaps) >= 2:
            delta = snaps[-1].get("total_risk", 0) - snaps[-2].get("total_risk", 0)
            lines.append(f"- change vs previous: {'+' if delta >= 0 else ''}{round(delta, 1)}")
    else:
        lines.append("- no historical snapshots yet")
    lines.append("")

    # MTTR from remediation workflow tickets.
    lines.append("## Mean time to remediate (MTTR)")
    mttr = _compute_mttr_hours(store)
    lines.append(f"- {mttr:.1f} hours (over {_remediated_count(store)} remediated finding(s))"
                 if mttr is not None else "- not enough remediated findings yet")
    return "\n".join(lines) + "\n"


def _compute_mttr_hours(store: Store) -> Optional[float]:
    from datetime import datetime
    durations = []
    for t in store.list_tickets():
        created = t.get("created_at")
        remediated_at = None
        for h in t.get("history", []):
            if h.get("to") in ("remediated", "verified", "closed"):
                remediated_at = h.get("at")
                break
        if created and remediated_at:
            d = (datetime.fromisoformat(remediated_at) - datetime.fromisoformat(created))
            durations.append(d.total_seconds() / 3600.0)
    return sum(durations) / len(durations) if durations else None


def _remediated_count(store: Store) -> int:
    n = 0
    for t in store.list_tickets():
        if any(h.get("to") in ("remediated", "verified", "closed") for h in t.get("history", [])):
            n += 1
    return n


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
