"""Enrichment: local VDB + EPSS/KEV (PRD §4 step 3, §5 VDB).

A minimal local vulnerability database keyed by CVE, plus a KEV set and EPSS
scores. In production these arrive as signed, air-gap-importable bundles
(see vdb.py); here a small built-in dataset makes the pipeline demonstrable.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Severity


@dataclass
class VdbEntry:
    cve_id: str
    cvss: float
    epss: float
    in_kev: bool
    title: str = ""
    percentile: float = 0.0     # EPSS percentile
    source: str = "builtin"     # provenance (Phase 2 D1.3)
    last_updated: str = ""      # ISO date of the ingested record


# Small built-in VDB slice. Real deployments import the full signed bundle.
_BUILTIN_VDB: dict[str, VdbEntry] = {
    "CVE-2019-0708": VdbEntry("CVE-2019-0708", 9.8, 0.94, True, "BlueKeep RDP RCE"),
    "CVE-2017-0144": VdbEntry("CVE-2017-0144", 8.1, 0.97, True, "EternalBlue SMB RCE"),
    "CVE-2021-34527": VdbEntry("CVE-2021-34527", 8.8, 0.90, True, "PrintNightmare"),
}

# Severity fallback when a finding has no CVE (config/exposure findings).
_SEVERITY_DEFAULT_EPSS = {
    Severity.INFORMATIONAL: 0.01,
    Severity.LOW: 0.05,
    Severity.MEDIUM: 0.15,
    Severity.HIGH: 0.40,
    Severity.CRITICAL: 0.70,
}


class Enricher:
    def __init__(self, vdb: dict[str, VdbEntry] | None = None, store=None) -> None:
        self.vdb = dict(_BUILTIN_VDB)
        if vdb:
            self.vdb.update(vdb)
        # When a Store is provided, ingested VDB entries (Phase 2 D1) take
        # precedence over the built-in slice.
        self.store = store

    def _lookup(self, cve: str) -> VdbEntry | None:
        if self.store is not None:
            d = self.store.get_vdb_entry(cve)
            if d is not None:
                return VdbEntry(
                    cve_id=d.get("cve_id", cve),
                    cvss=d.get("cvss", 0.0),
                    epss=d.get("epss", 0.0),
                    in_kev=d.get("in_kev", False),
                    title=d.get("title", ""),
                    percentile=d.get("percentile", 0.0),
                    source=d.get("source", "ingested"),
                    last_updated=d.get("last_updated", ""),
                )
        return self.vdb.get(cve)

    def enrich(self, finding: Finding) -> Finding:
        """Populate cvss/epss/kev from the VDB, or fall back to severity."""
        best: VdbEntry | None = None
        for cve in finding.cve_ids:
            entry = self._lookup(cve)
            if entry and (best is None or entry.cvss > best.cvss):
                best = entry
        if best is not None:
            finding.cvss_score = best.cvss
            finding.epss_score = best.epss
            finding.in_kev = best.in_kev
        else:
            # No CVE mapping — derive a conservative EPSS from severity so the
            # risk score and policy matrix still have a signal to work with.
            if finding.epss_score is None:
                finding.epss_score = _SEVERITY_DEFAULT_EPSS.get(finding.severity, 0.1)
        return finding
