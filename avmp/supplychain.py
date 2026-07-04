"""Signed supply-chain bundles (Phase 4 D2 / P4-AC-1, AC-6).

Upgrades the HMAC demo bundles (avmp/vdb.py) to **asymmetric** signatures: the
build host signs with a private key; the air-gapped appliance verifies with the
PUBLIC KEY ONLY. Bundles carry an embedded SBOM and a content hash, and the
build is reproducible (identical inputs -> identical digest). Verification fails
closed on any hash or signature mismatch.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import crypto


class BundleVerificationError(Exception):
    pass


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def reproducible_digest(payload, sbom: dict, bundle_id: str, created_at: str) -> str:
    body = {"bundle_id": bundle_id, "created_at": created_at, "payload": payload, "sbom": sbom}
    return hashlib.sha256(_canonical(body)).hexdigest()


def build_signed_bundle(path: str, payload, priv: crypto.PrivateKey, sbom: dict,
                        bundle_id: str, created_at: str) -> str:
    body = {"bundle_id": bundle_id, "created_at": created_at, "payload": payload, "sbom": sbom}
    raw = _canonical(body)
    digest = hashlib.sha256(raw).hexdigest()
    doc = {
        "body": body,
        "content_sha256": digest,
        "signature": crypto.sign(raw, priv),
        "alg": "RSA-SHA256",
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return digest


def verify_signed_bundle(path: str, pub: crypto.PublicKey) -> dict:
    """Verify content hash + asymmetric signature. Raise on any mismatch."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = _canonical(doc["body"])
    if hashlib.sha256(raw).hexdigest() != doc["content_sha256"]:
        raise BundleVerificationError("Content hash mismatch — bundle altered.")
    if not crypto.verify(raw, doc["signature"], pub):
        raise BundleVerificationError("Signature invalid — untrusted bundle, refusing import.")
    return doc["body"]
