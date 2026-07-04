import unittest

from avmp.models import AssetCriticality, Finding, Severity


class TestRiskScore(unittest.TestCase):
    def test_kev_and_criticality_raise_score(self):
        low = Finding("f1", "a", "p", "t", severity=Severity.HIGH,
                      cvss_score=8.0, epss_score=0.5, in_kev=False)
        kev = Finding("f2", "a", "p", "t", severity=Severity.HIGH,
                      cvss_score=8.0, epss_score=0.5, in_kev=True)
        self.assertLess(low.risk_score(AssetCriticality.MEDIUM),
                        kev.risk_score(AssetCriticality.MEDIUM))
        self.assertLess(kev.risk_score(AssetCriticality.LOW),
                        kev.risk_score(AssetCriticality.MISSION_CRITICAL))

    def test_score_capped_at_100(self):
        f = Finding("f", "a", "p", "t", severity=Severity.CRITICAL,
                    cvss_score=10.0, epss_score=1.0, in_kev=True)
        self.assertLessEqual(f.risk_score(AssetCriticality.MISSION_CRITICAL), 100.0)

    def test_exploit_likely(self):
        self.assertTrue(Finding("f", "a", "p", "t", in_kev=True).exploit_likely())
        self.assertTrue(Finding("f", "a", "p", "t", epss_score=0.4).exploit_likely())
        self.assertFalse(Finding("f", "a", "p", "t", epss_score=0.1).exploit_likely())


if __name__ == "__main__":
    unittest.main()
