import unittest

from avmp.backends import AzureNsgBackend, RemediationAction, RemediationBackendError


class TestAzureNsgBackend(unittest.TestCase):
    def setUp(self):
        self.be = AzureNsgBackend()

    def test_close_port_apply_validate_rollback(self):
        a = RemediationAction("nsg1", "close_port", "web-dmz-01", {"port": "3389"})
        self.assertFalse(self.be.validate(a))
        self.be.apply(a)
        self.assertTrue(self.be.validate(a))          # deny rule present
        self.be.rollback(a)
        self.assertFalse(self.be.validate(a))         # rule removed

    def test_preview_is_dry_run_only(self):
        a = RemediationAction("nsg2", "close_port", "web-dmz-01", {"port": "22"})
        preview = self.be.preview(a)
        self.assertIn("DRY-RUN", preview)
        self.assertIn("az network nsg rule create", preview)
        self.assertFalse(self.be.validate(a))         # preview did not apply

    def test_non_close_port_rejected(self):
        a = RemediationAction("nsg3", "rotate_secret", "web-dmz-01", {"secret": "x"})
        with self.assertRaises(RemediationBackendError):
            self.be.apply(a)


if __name__ == "__main__":
    unittest.main()
