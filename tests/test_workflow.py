import unittest
from datetime import datetime, timedelta, timezone

from avmp.models import Asset, AssetCriticality, Finding, Severity
from avmp.store import AuditSigner, Store
from avmp.workflow import (
    FindingState,
    IllegalTransition,
    VerificationFailed,
    WorkflowEngine,
    sla_hours_for_risk,
)


def _finding():
    return Finding("f1", "a1", "p", "Exposed RDP", severity=Severity.HIGH)


def _asset():
    return Asset("a1", ip_addresses=["10.0.0.1"], criticality=AssetCriticality.MEDIUM)


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:", signer=AuditSigner(b"k" * 32))
        self.wf = WorkflowEngine(self.store)

    def test_sla_bands(self):
        self.assertEqual(sla_hours_for_risk(95), 24)
        self.assertEqual(sla_hours_for_risk(75), 72)
        self.assertEqual(sla_hours_for_risk(50), 168)
        self.assertEqual(sla_hours_for_risk(10), 720)

    def test_open_and_full_lifecycle(self):
        self.wf.open_ticket(_finding(), 95.0, _asset(), actor="op")
        self.wf.transition("f1", FindingState.TRIAGED, "op")
        self.wf.assign("f1", "eng", "lead")
        self.wf.transition("f1", FindingState.IN_PROGRESS, "eng")
        self.wf.transition("f1", FindingState.REMEDIATED, "eng")
        # Verification requires a passing re-scan.
        t = self.wf.transition("f1", FindingState.VERIFIED, "qa", verify_fn=lambda: True)
        self.assertEqual(t.state, FindingState.VERIFIED)
        t = self.wf.transition("f1", FindingState.CLOSED, "qa")
        self.assertEqual(t.state, FindingState.CLOSED)

    def test_illegal_transition_rejected(self):
        self.wf.open_ticket(_finding(), 50.0, _asset())
        with self.assertRaises(IllegalTransition):
            self.wf.transition("f1", FindingState.VERIFIED, "x")

    def test_verified_blocked_until_rescan_passes(self):
        self.wf.open_ticket(_finding(), 50.0, _asset())
        self.wf.transition("f1", FindingState.TRIAGED, "x")
        self.wf.assign("f1", "eng", "lead")
        self.wf.transition("f1", FindingState.IN_PROGRESS, "eng")
        self.wf.transition("f1", FindingState.REMEDIATED, "eng")
        with self.assertRaises(VerificationFailed):
            self.wf.transition("f1", FindingState.VERIFIED, "qa", verify_fn=lambda: False)

    def test_false_positive_feedback(self):
        self.wf.open_ticket(_finding(), 50.0, _asset())
        t = self.wf.mark_false_positive("f1", "analyst", "benign banner")
        self.assertEqual(t.state, FindingState.FALSE_POSITIVE)
        actions = [r["action"] for r in self.store.iter_audit()]
        self.assertIn("workflow.false_positive_feedback", actions)

    def test_sla_breach_detection(self):
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        wf = WorkflowEngine(self.store, clock=lambda: past)
        wf.open_ticket(_finding(), 95.0, _asset())  # 24h SLA from 2020-01-01
        self.assertFalse(wf.sla_breached("f1", now=past + timedelta(hours=1)))
        self.assertTrue(wf.sla_breached("f1", now=past + timedelta(hours=48)))

    def test_audit_chain_intact(self):
        self.wf.open_ticket(_finding(), 95.0, _asset())
        self.wf.transition("f1", FindingState.TRIAGED, "op")
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
