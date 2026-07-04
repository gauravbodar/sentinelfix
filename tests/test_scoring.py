import tempfile
import unittest
from pathlib import Path

from avmp.models import Asset, AssetCriticality, Finding, Severity
from avmp.scoring import ScoringModel, score_finding


def _finding():
    return Finding("f", "a", "p", "t", severity=Severity.MEDIUM,
                   cvss_score=6.0, epss_score=0.1, in_kev=False)


def _asset(internet=False, crit=AssetCriticality.MEDIUM):
    return Asset("a", ip_addresses=["10.0.0.1"], criticality=crit, internet_facing=internet)


class TestScoring(unittest.TestCase):
    def test_records_model_version(self):
        b = score_finding(_finding(), _asset(), ScoringModel(version="9.9.9"))
        self.assertEqual(b.model_version, "9.9.9")

    def test_internet_facing_raises_score(self):
        lower = score_finding(_finding(), _asset(internet=False)).score
        higher = score_finding(_finding(), _asset(internet=True)).score
        self.assertGreater(higher, lower)

    def test_weight_change_changes_score_without_code(self):
        base = score_finding(_finding(), _asset()).score
        tuned = score_finding(_finding(), _asset(), ScoringModel(cvss_weight=0.9)).score
        self.assertNotEqual(base, tuned)

    def test_factor_breakdown_sums_to_score(self):
        b = score_finding(_finding(), _asset())  # non-capped case
        total = round(sum(f.contribution for f in b.factors), 1)
        self.assertAlmostEqual(total, b.score, delta=0.2)

    def test_config_roundtrip(self):
        d = tempfile.mkdtemp()
        p = str(Path(d) / "scoring.json")
        ScoringModel(version="2.0.0", cvss_weight=0.7).save(p)
        loaded = ScoringModel.from_file(p)
        self.assertEqual(loaded.version, "2.0.0")
        self.assertEqual(loaded.cvss_weight, 0.7)


if __name__ == "__main__":
    unittest.main()
