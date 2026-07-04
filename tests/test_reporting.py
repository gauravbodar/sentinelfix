import unittest

from avmp.models import Asset, AssetCriticality, Finding, Severity
from avmp.reporting import executive_summary
from avmp.store import AuditSigner, Store
from avmp.workflow import FindingState, WorkflowEngine


class TestExecutiveSummary(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:", signer=AuditSigner(b"k" * 32))
        self.assets = [
            Asset("web", hostname="web", ip_addresses=["10.0.0.1"],
                  criticality=AssetCriticality.MEDIUM, internet_facing=True),
        ]
        self.store.upsert_asset(self.assets[0])
        self.findings = [
            Finding("f1", "web", "net.exposed_rdp.3389", "Exposed RDP",
                    severity=Severity.HIGH, cve_ids=["CVE-2019-0708"],
                    cvss_score=9.8, epss_score=0.94, in_kev=True),
            Finding("f2", "web", "net.exposed_smb.445", "Exposed SMB",
                    severity=Severity.MEDIUM, cvss_score=6.0, epss_score=0.2),
        ]
        for f in self.findings:
            self.store.upsert_finding(f)

    def test_summary_renders_top_risks_and_sections(self):
        text = executive_summary(self.findings, self.assets, self.store)
        self.assertIn("Executive Summary", text)
        self.assertIn("Top", text)
        self.assertIn("Exposed RDP", text)
        self.assertIn("Mean time to remediate", text)

    def test_summary_includes_trend_after_snapshots(self):
        self.store.append_risk_snapshot("2024-01-01T00:00:00", {"total_risk": 100.0, "finding_count": 2})
        self.store.append_risk_snapshot("2024-01-02T00:00:00", {"total_risk": 60.0, "finding_count": 1})
        text = executive_summary(self.findings, self.assets, self.store)
        self.assertIn("Risk trend", text)
        self.assertIn("change vs previous", text)

    def test_mttr_computed_from_tickets(self):
        wf = WorkflowEngine(self.store)
        wf.open_ticket(self.findings[0], 95.0, self.assets[0])
        wf.transition("f1", FindingState.TRIAGED, "op")
        wf.assign("f1", "eng", "lead")
        wf.transition("f1", FindingState.IN_PROGRESS, "eng")
        wf.transition("f1", FindingState.REMEDIATED, "eng")
        text = executive_summary(self.findings, self.assets, self.store)
        self.assertIn("hours", text)


if __name__ == "__main__":
    unittest.main()
