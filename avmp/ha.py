"""High availability (Phase 4 D8 / P4-AC-10).

Active/passive Console clustering and scanner-node failover, demonstrated
in-process. The primary Console's audit writes are synchronously replicated to a
standby store (byte-identical rows, so the standby's hash chain matches). On
failover the standby is promoted with zero audit loss. A scanner pool reroutes
scans away from a downed node.

Production replaces the in-process replication with real log shipping / a shared
HA datastore; the failover semantics and the zero-loss guarantee are the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import AuditRecord
from .store import Store


class HACluster:
    def __init__(self, primary: Store, standby: Store) -> None:
        self.primary = primary
        self.standby = standby
        self._primary_up = True

    def append_audit(self, record: AuditRecord) -> AuditRecord:
        """Write to the primary, then synchronously replicate to the standby."""
        rec = self.primary.append_audit(record)
        # Replicate the exact signed row so chains stay byte-identical.
        self.standby.import_audit_row(rec.signing_payload(), rec.signature)
        return rec

    def fail_primary(self) -> None:
        self._primary_up = False

    @property
    def active(self) -> Store:
        return self.primary if self._primary_up else self.standby

    def failover(self) -> Store:
        """Promote the standby. Returns the now-active store."""
        self._primary_up = False
        return self.standby

    def audit_loss(self) -> int:
        """Records on primary not yet on standby (0 == zero-loss)."""
        return self.primary.audit_count() - self.standby.audit_count()

    def standby_chain_ok(self) -> bool:
        return self.standby.verify_audit_chain()


@dataclass
class ScannerNodeRef:
    node_id: str
    up: bool = True


class ScannerPool:
    def __init__(self, node_ids: list[str]) -> None:
        self.nodes: list[ScannerNodeRef] = [ScannerNodeRef(n) for n in node_ids]

    def mark_down(self, node_id: str) -> None:
        for n in self.nodes:
            if n.node_id == node_id:
                n.up = False

    def route(self) -> str:
        """Return the id of an available scanner node, or raise if none."""
        for n in self.nodes:
            if n.up:
                return n.node_id
        raise RuntimeError("No scanner nodes available.")
