"""State store + tamper-evident WORM audit log (PRD §4 State Store, §7 WORM).

SQLite-backed store for assets/findings/policies plus an append-only audit log.
The audit log emulates WORM semantics:
  * there is no update or delete API for audit rows;
  * each record is HMAC-signed and hash-chained to the previous record, so any
    insertion, reordering, or edit is detectable via verify_audit_chain().

The HMAC key is the WORM signing key; in a real appliance it lives in an HSM /
FIPS keystore. Here it is generated once and stored in a gitignored key file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Iterator, Optional

from .models import (
    Asset,
    AssetCriticality,
    AuditRecord,
    Finding,
    Severity,
    utcnow,
)

GENESIS = "GENESIS"


class AuditSigner:
    """HMAC-SHA256 signer for WORM audit receipts."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def from_keyfile(cls, path: Path) -> "AuditSigner":
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            key = path.read_bytes()
        else:
            key = os.urandom(32)
            path.write_bytes(key)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # best-effort on platforms without POSIX perms
        return cls(key)

    def sign(self, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, canonical, hashlib.sha256).hexdigest()


class Store:
    """SQLite persistence for assets, findings, policies, and WORM audit."""

    def __init__(self, db_path: str = ":memory:", signer: Optional[AuditSigner] = None) -> None:
        self.db_path = db_path
        # check_same_thread=False + a lock: the read-only API server dispatches
        # requests on worker threads, so the connection is shared under a guard.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        if signer is None:
            key_path = Path(db_path).with_suffix(".audit.key") if db_path != ":memory:" \
                else Path(".avmp_audit_mem.key")
            signer = AuditSigner.from_keyfile(key_path)
        self._signer = signer
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                data     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                asset_id   TEXT NOT NULL,
                data       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id  TEXT NOT NULL,
                data       TEXT NOT NULL,
                signature  TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    # --- Assets ---------------------------------------------------------
    def upsert_asset(self, asset: Asset) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO assets(asset_id, data) VALUES(?, ?) "
                "ON CONFLICT(asset_id) DO UPDATE SET data=excluded.data",
                (asset.asset_id, json.dumps(asset.to_dict())),
            )
            self._conn.commit()

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM assets WHERE asset_id=?", (asset_id,)
            ).fetchone()
        return _asset_from_json(row["data"]) if row else None

    def list_assets(self) -> list[Asset]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM assets ORDER BY asset_id").fetchall()
        return [_asset_from_json(r["data"]) for r in rows]

    # --- Findings -------------------------------------------------------
    def upsert_finding(self, finding: Finding) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO findings(finding_id, asset_id, data) VALUES(?, ?, ?) "
                "ON CONFLICT(finding_id) DO UPDATE SET data=excluded.data, asset_id=excluded.asset_id",
                (finding.finding_id, finding.asset_id, json.dumps(finding.to_dict())),
            )
            self._conn.commit()

    def list_findings(self, asset_id: Optional[str] = None) -> list[Finding]:
        with self._lock:
            if asset_id:
                rows = self._conn.execute(
                    "SELECT data FROM findings WHERE asset_id=? ORDER BY finding_id", (asset_id,)
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT data FROM findings ORDER BY finding_id"
                ).fetchall()
        return [_finding_from_json(r["data"]) for r in rows]

    # --- WORM audit -----------------------------------------------------
    def append_audit(self, record: AuditRecord) -> AuditRecord:
        """Append-only, hash-chained, HMAC-signed. No update/delete exists."""
        with self._lock:
            last = self._conn.execute(
                "SELECT signature FROM audit ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            record.prev_signature = last["signature"] if last else GENESIS
            record.signature = self._signer.sign(record.signing_payload())
            self._conn.execute(
                "INSERT INTO audit(record_id, data, signature) VALUES(?, ?, ?)",
                (record.record_id, json.dumps(record.signing_payload()), record.signature),
            )
            self._conn.commit()
        return record

    def iter_audit(self) -> Iterator[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data, signature FROM audit ORDER BY seq"
            ).fetchall()
        for row in rows:
            payload = json.loads(row["data"])
            payload["signature"] = row["signature"]
            yield payload

    def verify_audit_chain(self) -> bool:
        """Recompute every signature + chain link; return False on any tamper."""
        prev = GENESIS
        for payload in self.iter_audit():
            stored_sig = payload.pop("signature")
            if payload.get("prev_signature") != prev:
                return False
            if self._signer.sign(payload) != stored_sig:
                return False
            prev = stored_sig
        return True

    def close(self) -> None:
        self._conn.close()


def _asset_from_json(data: str) -> Asset:
    d = json.loads(data)
    return Asset(
        asset_id=d["asset_id"],
        hostname=d.get("hostname"),
        ip_addresses=d.get("ip_addresses", []),
        owner=d.get("owner"),
        criticality=AssetCriticality(d.get("criticality", "medium")),
        tags=d.get("tags", {}),
        internet_facing=d.get("internet_facing", False),
    )


def _finding_from_json(data: str) -> Finding:
    d = json.loads(data)
    return Finding(
        finding_id=d["finding_id"],
        asset_id=d["asset_id"],
        plugin_id=d["plugin_id"],
        title=d["title"],
        severity=Severity(d.get("severity", "medium")),
        cve_ids=d.get("cve_ids", []),
        cvss_score=d.get("cvss_score"),
        epss_score=d.get("epss_score"),
        in_kev=d.get("in_kev", False),
        evidence=d.get("evidence", {}),
        remediation_hint=d.get("remediation_hint"),
    )
