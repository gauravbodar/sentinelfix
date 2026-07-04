"""Hardened WORM audit checkpoints (Phase 4 D3 / P4-AC-4).

The base audit log is already append-only + HMAC hash-chained (avmp/store.py).
Phase 4 adds periodic **signed checkpoints**: each checkpoint records the audit
count and the last chain signature, signed with the asymmetric private key.
Verification detects not just row edits (via the chain) but also **truncation**
(rows deleted after a checkpoint) — a gap the chain alone cannot catch.

In production the checkpoint is also anchored externally (append to a separate
WORM/immutable store or a timestamping authority); here it lives in the DB and
is signed with the same asymmetric key used for supply-chain bundles.
"""

from __future__ import annotations

from . import crypto
from .store import Store


def _checkpoint_body(count: int, last_signature: str, taken_at: str) -> bytes:
    return f"{count}|{last_signature}|{taken_at}".encode()


def create_checkpoint(store: Store, priv: crypto.PrivateKey, taken_at: str) -> dict:
    records = list(store.iter_audit())
    count = len(records)
    last_sig = records[-1]["signature"] if records else "GENESIS"
    signature = crypto.sign(_checkpoint_body(count, last_sig, taken_at), priv)
    cp = {"count": count, "last_signature": last_sig, "taken_at": taken_at, "signature": signature}
    store.append_checkpoint(cp)
    return cp


def verify_checkpoint(store: Store, pub: crypto.PublicKey, checkpoint: dict) -> bool:
    """True iff the checkpoint signature is valid AND no rows were altered or
    truncated below the checkpointed count."""
    body = _checkpoint_body(checkpoint["count"], checkpoint["last_signature"],
                            checkpoint["taken_at"])
    if not crypto.verify(body, checkpoint["signature"], pub):
        return False
    records = list(store.iter_audit())
    if len(records) < checkpoint["count"]:
        return False  # truncation detected
    if checkpoint["count"] > 0:
        if records[checkpoint["count"] - 1]["signature"] != checkpoint["last_signature"]:
            return False
    return store.verify_audit_chain()


def verify_all(store: Store, pub: crypto.PublicKey) -> bool:
    return all(verify_checkpoint(store, pub, cp) for cp in store.list_checkpoints())
