import unittest

from avmp.ha import HACluster, ScannerPool
from avmp.models import AuditRecord, utcnow
from avmp.store import AuditSigner, Store


class TestHACluster(unittest.TestCase):
    def setUp(self):
        key = b"k" * 32
        self.primary = Store(":memory:", signer=AuditSigner(key))
        self.standby = Store(":memory:", signer=AuditSigner(key))
        self.cluster = HACluster(self.primary, self.standby)

    def test_failover_zero_audit_loss(self):
        for i in range(6):
            self.cluster.append_audit(AuditRecord(str(i), "a", "act", "s", utcnow()))
        self.assertEqual(self.cluster.audit_loss(), 0)
        active = self.cluster.failover()
        self.assertIs(active, self.standby)
        self.assertEqual(active.audit_count(), 6)
        self.assertTrue(self.cluster.standby_chain_ok())   # replicated chain valid

    def test_active_switches_after_failure(self):
        self.assertIs(self.cluster.active, self.primary)
        self.cluster.fail_primary()
        self.assertIs(self.cluster.active, self.standby)


class TestScannerPool(unittest.TestCase):
    def test_reroute_on_node_down(self):
        pool = ScannerPool(["scanner-a", "scanner-b"])
        self.assertEqual(pool.route(), "scanner-a")
        pool.mark_down("scanner-a")
        self.assertEqual(pool.route(), "scanner-b")

    def test_no_nodes_raises(self):
        pool = ScannerPool(["only"])
        pool.mark_down("only")
        with self.assertRaises(RuntimeError):
            pool.route()


if __name__ == "__main__":
    unittest.main()
