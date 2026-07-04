"""KEV / EPSS ingestion pipeline (Phase 2 D1).

Turns the CISA KEV catalog and FIRST.org EPSS dataset into VDB entries, packages
them as a signed offline bundle (reusing avmp.vdb), and loads them into the
persisted VDB with provenance. Everything reads from local files, so this is the
air-gapped path — no outbound network calls.

Input formats (as published):
  * KEV:  JSON  { "catalogVersion": "...", "vulnerabilities": [ {"cveID": ...,
                  "vendorProject": ..., "shortDescription": ...}, ... ] }
  * EPSS: CSV (optionally .gz) with a '#model_version...' comment line, a
          'cve,epss,percentile' header, then rows.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
from pathlib import Path
from typing import Optional

from .enrichment import Enricher, VdbEntry
from .store import Store
from .vdb import export_bundle, import_offline, verify_bundle


def parse_kev(path: str) -> dict[str, dict]:
    """Return {cve_id: {title, in_kev, date_added}} from a KEV JSON file."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "in_kev": True,
            "title": v.get("shortDescription") or v.get("vulnerabilityName") or "",
            "date_added": v.get("dateAdded", ""),
        }
    return out


def _open_maybe_gzip(path: str) -> io.TextIOBase:
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8")
    return open(path, "r", encoding="utf-8")


def parse_epss(path: str) -> dict[str, dict]:
    """Return {cve_id: {epss, percentile}} from an EPSS CSV(.gz) file."""
    out: dict[str, dict] = {}
    with _open_maybe_gzip(path) as fh:
        rows = [ln for ln in fh if not ln.startswith("#")]
    reader = csv.DictReader(rows)
    for r in reader:
        cve = (r.get("cve") or "").strip()
        if not cve:
            continue
        try:
            out[cve] = {
                "epss": float(r.get("epss", 0.0)),
                "percentile": float(r.get("percentile", 0.0)),
            }
        except ValueError:
            continue
    return out


def parse_cvss(path: Optional[str]) -> dict[str, float]:
    """Optional CVSS source: CSV with 'cve,cvss' (e.g. an NVD extract)."""
    if not path:
        return {}
    out: dict[str, float] = {}
    with _open_maybe_gzip(path) as fh:
        for r in csv.DictReader(fh):
            cve = (r.get("cve") or "").strip()
            if cve:
                try:
                    out[cve] = float(r.get("cvss", 0.0))
                except ValueError:
                    pass
    return out


def build_entries(
    kev: dict[str, dict],
    epss: dict[str, dict],
    cvss: Optional[dict[str, float]] = None,
    last_updated: str = "",
    source: str = "kev+epss",
) -> list[VdbEntry]:
    """Merge the parsed feeds into a de-duplicated list of VDB entries."""
    cvss = cvss or {}
    cve_ids = set(kev) | set(epss) | set(cvss)
    entries: list[VdbEntry] = []
    for cve in sorted(cve_ids):
        k = kev.get(cve, {})
        e = epss.get(cve, {})
        entries.append(VdbEntry(
            cve_id=cve,
            cvss=cvss.get(cve, 0.0),
            epss=e.get("epss", 0.0),
            in_kev=k.get("in_kev", False),
            title=k.get("title", ""),
            percentile=e.get("percentile", 0.0),
            source=source,
            last_updated=last_updated,
        ))
    return entries


def build_signed_bundle(path: str, entries: list[VdbEntry], key: bytes,
                        bundle_id: str, created_at: str) -> None:
    export_bundle(path, entries, key, bundle_id=bundle_id, created_at=created_at)


def ingest_offline(bundle_path: str, key: bytes, store: Store) -> int:
    """Air-gap ingest: verify the signed bundle, then load entries into the
    persisted VDB with provenance. Fails closed on bad signature/hash."""
    verify_bundle(bundle_path, key)  # raises on tamper
    doc = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    count = 0
    for item in doc["payload"]:
        entry = VdbEntry(**item)
        store.upsert_vdb_entry(
            entry.cve_id,
            {
                "cve_id": entry.cve_id, "cvss": entry.cvss, "epss": entry.epss,
                "in_kev": entry.in_kev, "title": entry.title,
                "percentile": entry.percentile,
            },
            source=entry.source or "ingested",
            last_updated=entry.last_updated or doc["manifest"].get("created_at", ""),
        )
        count += 1
    return count


def ingest_feeds(kev_path: str, epss_path: str, store: Store, key: bytes,
                 cvss_path: Optional[str] = None, bundle_out: Optional[str] = None,
                 last_updated: str = "", bundle_id: str = "kev-epss",
                 created_at: str = "1970-01-01T00:00:00Z") -> int:
    """Convenience: parse feeds -> sign a bundle -> verify -> ingest. Returns
    the number of VDB entries loaded."""
    entries = build_entries(
        parse_kev(kev_path), parse_epss(epss_path),
        parse_cvss(cvss_path), last_updated=last_updated,
    )
    out = bundle_out or str(Path(store.db_path).with_suffix(".vdbundle")) \
        if store.db_path != ":memory:" else (bundle_out or "vdb_feed.vdbundle")
    build_signed_bundle(out, entries, key, bundle_id=bundle_id, created_at=created_at)
    return ingest_offline(out, key, store)
