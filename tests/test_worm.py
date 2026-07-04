import unittest

from avmp import crypto, worm
from avmp.models import AuditRecord, utcnow
from avmp.store import AuditSigner, Store


class TestWormCheckpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = crypto.generate_keypair(1024)
        cls.pub = cls.priv.public()

    def setUp(self):
        self.store = Store(":memory:", signer=AuditSigner(b"k" * 32))
        for i in range(5):
            self.store.append_audit(AuditRecord(str(i), "a", "act", "s", utcnow()))

    def test_checkpoint_verifies(self):
        cp = worm.create_checkpoint(self.store, self.priv, "2024-01-01")
        self.assertTrue(worm.verify_checkpoint(self.store, self.pub, cp))

    def test_truncation_detected(self):
        cp = worm.create_checkpoint(self.store, self.priv, "2024-01-01")
        self.store._conn.execute("DELETE FROM audit WHERE record_id='4'")
        self.store._conn.commit()
        self.assertFalse(worm.verify_checkpoint(self.store, self.pub, cp))

    def test_forged_checkpoint_rejected(self):
        cp = worm.create_checkpoint(self.store, self.priv, "2024-01-01")
        cp["count"] = 99          # attacker inflates without a valid signature
        self.assertFalse(worm.verify_checkpoint(self.store, self.pub, cp))

    def test_verify_all(self):
        worm.create_checkpoint(self.store, self.priv, "2024-01-01")
        self.store.append_audit(AuditRecord("x", "a", "act", "s", utcnow()))
        worm.create_checkpoint(self.store, self.priv, "2024-01-02")
        self.assertTrue(worm.verify_all(self.store, self.pub))


if __name__ == "__main__":
    unittest.main()
