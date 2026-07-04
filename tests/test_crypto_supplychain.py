import tempfile
import unittest
from pathlib import Path

from avmp import crypto, sbom, supplychain


class TestCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = crypto.generate_keypair(1024)
        cls.pub = cls.priv.public()

    def test_sign_verify_roundtrip(self):
        sig = crypto.sign(b"payload", self.priv)
        self.assertTrue(crypto.verify(b"payload", sig, self.pub))

    def test_tamper_rejected(self):
        sig = crypto.sign(b"payload", self.priv)
        self.assertFalse(crypto.verify(b"payloa2", sig, self.pub))

    def test_wrong_key_rejected(self):
        other = crypto.generate_keypair(1024).public()
        sig = crypto.sign(b"payload", self.priv)
        self.assertFalse(crypto.verify(b"payload", sig, other))

    def test_key_persistence(self):
        d = tempfile.mkdtemp()
        crypto.save_private(self.priv, str(Path(d) / "priv.json"))
        crypto.save_public(self.pub, str(Path(d) / "pub.json"))
        pub2 = crypto.load_public(str(Path(d) / "pub.json"))
        sig = crypto.sign(b"x", crypto.load_private(str(Path(d) / "priv.json")))
        self.assertTrue(crypto.verify(b"x", sig, pub2))


class TestSignedBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = crypto.generate_keypair(1024)
        cls.pub = cls.priv.public()

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = str(Path(self.dir) / "bundle.json")
        self.sbom = sbom.generate_sbom("avmp")
        supplychain.build_signed_bundle(self.path, [{"cve": "CVE-1"}], self.priv,
                                        self.sbom, "b1", "2024-01-01")

    def test_public_key_only_verify(self):
        body = supplychain.verify_signed_bundle(self.path, self.pub)
        self.assertEqual(body["payload"], [{"cve": "CVE-1"}])
        self.assertGreater(body["sbom"]["component_count"], 0)

    def test_reproducible_digest(self):
        d1 = supplychain.reproducible_digest([{"cve": "CVE-1"}], self.sbom, "b1", "2024-01-01")
        d2 = supplychain.reproducible_digest([{"cve": "CVE-1"}], self.sbom, "b1", "2024-01-01")
        self.assertEqual(d1, d2)

    def test_tampered_bundle_fails_closed(self):
        p = Path(self.path)
        p.write_text(p.read_text().replace("CVE-1", "CVE-EVIL"))
        with self.assertRaises(supplychain.BundleVerificationError):
            supplychain.verify_signed_bundle(self.path, self.pub)

    def test_wrong_key_fails_closed(self):
        other = crypto.generate_keypair(1024).public()
        with self.assertRaises(supplychain.BundleVerificationError):
            supplychain.verify_signed_bundle(self.path, other)


if __name__ == "__main__":
    unittest.main()
