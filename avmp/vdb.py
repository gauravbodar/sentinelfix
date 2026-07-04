"""Signed VDB / plugin bundle export & import (PRD §5 VDB, §7 Air-gapped).

Supply-chain integrity: a bundle is a JSON document with a payload and a
manifest carrying the payload's SHA-256 and an HMAC signature. import_offline()
FAILS CLOSED on any hash or signature mismatch. No network I/O — this is the
air-gap path (offline signed-bundle import). sync_online() is a thin wrapper
that would fetch a bundle before calling the same verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .enrichment import Enricher, VdbEntry


@dataclass
class BundleManifest:
    bundle_id: str
    created_at: str
    content_sha256: str
    signature: str


class BundleVerificationError(Exception):
    pass


def _payload_bytes(entries: list[dict]) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()


def export_bundle(path: str, entries: list[VdbEntry], key: bytes, bundle_id: str,
                  created_at: str = "1970-01-01T00:00:00Z") -> BundleManifest:
    payload = [e.__dict__ for e in entries]
    raw = _payload_bytes(payload)
    digest = hashlib.sha256(raw).hexdigest()
    signature = hmac.new(key, raw, hashlib.sha256).hexdigest()
    manifest = BundleManifest(bundle_id, created_at, digest, signature)
    Path(path).write_text(json.dumps({
        "manifest": manifest.__dict__,
        "payload": payload,
    }, indent=2), encoding="utf-8")
    return manifest


def verify_bundle(path: str, key: bytes) -> BundleManifest:
    """Verify content hash + HMAC signature. Raise on any mismatch."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest = BundleManifest(**doc["manifest"])
    raw = _payload_bytes(doc["payload"])
    if hashlib.sha256(raw).hexdigest() != manifest.content_sha256:
        raise BundleVerificationError("Content hash mismatch — bundle corrupted or altered.")
    expected = hmac.new(key, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, manifest.signature):
        raise BundleVerificationError("Signature mismatch — untrusted bundle, refusing import.")
    return manifest


def import_offline(path: str, key: bytes, enricher: Enricher) -> int:
    """Air-gapped import: verify then merge entries into the enricher's VDB."""
    verify_bundle(path, key)
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    count = 0
    for item in doc["payload"]:
        entry = VdbEntry(**item)
        enricher.vdb[entry.cve_id] = entry
        count += 1
    return count


def sync_online(feed_url: str, key: bytes, enricher: Enricher) -> int:  # pragma: no cover
    """Connected sites only. Opt-in. Not used on air-gapped appliances."""
    raise NotImplementedError(
        "Online sync is disabled in the air-gapped MVP; use import_offline()."
    )
