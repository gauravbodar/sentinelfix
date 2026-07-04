import tempfile
import unittest
from pathlib import Path

from avmp.enrichment import Enricher, VdbEntry
from avmp.vdb import BundleVerificationError, export_bundle, import_offline, verify_bundle


class TestVdbBundle(unittest.TestCase):
    def setUp(self):
        self.key = b"k" * 32
        self.dir = tempfile.mkdtemp()
        self.path = str(Path(self.dir) / "bundle.json")
        export_bundle(self.path, [VdbEntry("CVE-2021-44228", 10.0, 0.98, True, "Log4Shell")],
                      self.key, bundle_id="b1")

    def test_valid_bundle_verifies_and_imports(self):
        verify_bundle(self.path, self.key)
        enricher = Enricher()
        n = import_offline(self.path, self.key, enricher)
        self.assertEqual(n, 1)
        self.assertIn("CVE-2021-44228", enricher.vdb)

    def test_wrong_key_rejected(self):
        with self.assertRaises(BundleVerificationError):
            verify_bundle(self.path, b"x" * 32)

    def test_tampered_payload_rejected(self):
        p = Path(self.path)
        p.write_text(p.read_text().replace("10.0", "1.0"))
        with self.assertRaises(BundleVerificationError):
            verify_bundle(self.path, self.key)


if __name__ == "__main__":
    unittest.main()
