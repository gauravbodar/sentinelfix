import unittest
from pathlib import Path

from avmp.enrichment import Enricher
from avmp.ingest import (
    build_entries,
    build_signed_bundle,
    ingest_offline,
    parse_epss,
    parse_kev,
)
from avmp.models import Finding, Severity
from avmp.store import AuditSigner, Store
from avmp.vdb import BundleVerificationError

DATA = Path(__file__).parent / "data"
KEY = b"k" * 32


class TestIngest(unittest.TestCase):
    def test_parse_feeds(self):
        kev = parse_kev(str(DATA / "kev_sample.json"))
        epss = parse_epss(str(DATA / "epss_sample.csv"))
        self.assertTrue(kev["CVE-2019-0708"]["in_kev"])
        self.assertAlmostEqual(epss["CVE-2019-0708"]["epss"], 0.94, places=3)
        self.assertAlmostEqual(epss["CVE-2021-44228"]["percentile"], 0.999, places=3)

    def test_ingest_offline_persists_with_provenance(self):
        entries = build_entries(
            parse_kev(str(DATA / "kev_sample.json")),
            parse_epss(str(DATA / "epss_sample.csv")),
            last_updated="2024-01-01",
        )
        import tempfile
        bundle = str(Path(tempfile.mkdtemp()) / "b.vdbundle")
        build_signed_bundle(bundle, entries, KEY, bundle_id="t", created_at="2024-01-01T00:00:00Z")

        store = Store(":memory:", signer=AuditSigner(KEY))
        n = ingest_offline(bundle, KEY, store)
        self.assertGreaterEqual(n, 3)
        entry = store.get_vdb_entry("CVE-2019-0708")
        self.assertTrue(entry["in_kev"])
        self.assertEqual(entry["last_updated"], "2024-01-01")
        self.assertEqual(store.vdb_latest_update(), "2024-01-01")

    def test_enricher_uses_ingested_vdb(self):
        store = Store(":memory:", signer=AuditSigner(KEY))
        store.upsert_vdb_entry("CVE-2021-44228",
                               {"cve_id": "CVE-2021-44228", "cvss": 10.0, "epss": 0.975,
                                "in_kev": True, "title": "Log4Shell"},
                               source="kev+epss", last_updated="2024-01-01")
        enricher = Enricher(store=store)
        f = Finding("f", "a", "p", "t", severity=Severity.HIGH, cve_ids=["CVE-2021-44228"])
        enricher.enrich(f)
        self.assertTrue(f.in_kev)
        self.assertEqual(f.cvss_score, 10.0)
        self.assertAlmostEqual(f.epss_score, 0.975, places=3)

    def test_tampered_bundle_rejected_on_ingest(self):
        entries = build_entries(parse_kev(str(DATA / "kev_sample.json")), {})
        import tempfile
        bundle = Path(tempfile.mkdtemp()) / "b.vdbundle"
        build_signed_bundle(str(bundle), entries, KEY, bundle_id="t", created_at="x")
        # Tamper with a value actually carried in the signed payload (the title).
        bundle.write_text(bundle.read_text().replace("BlueKeep", "Evilkeep"))
        store = Store(":memory:", signer=AuditSigner(KEY))
        with self.assertRaises(BundleVerificationError):
            ingest_offline(str(bundle), KEY, store)


if __name__ == "__main__":
    unittest.main()
