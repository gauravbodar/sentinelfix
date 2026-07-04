import unittest

from avmp.models import AuditRecord, utcnow
from avmp.store import AuditSigner, Store


class TestWormAudit(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:", signer=AuditSigner(b"k" * 32))

    def _append(self, action):
        self.store.append_audit(AuditRecord(
            record_id=action, actor="a", action=action, subject_id="s",
            timestamp=utcnow(),
        ))

    def test_chain_verifies(self):
        for i in range(5):
            self._append(f"act-{i}")
        self.assertTrue(self.store.verify_audit_chain())

    def test_tamper_is_detected(self):
        self._append("act-0")
        self._append("act-1")
        # Directly mutate a stored row to simulate tampering.
        self.store._conn.execute(
            "UPDATE audit SET data = REPLACE(data, 'act-1', 'act-X') WHERE record_id='act-1'"
        )
        self.store._conn.commit()
        self.assertFalse(self.store.verify_audit_chain())

    def test_records_are_chained(self):
        self._append("act-0")
        self._append("act-1")
        rows = list(self.store.iter_audit())
        self.assertEqual(rows[0]["prev_signature"], "GENESIS")
        self.assertEqual(rows[1]["prev_signature"], rows[0]["signature"])


if __name__ == "__main__":
    unittest.main()
