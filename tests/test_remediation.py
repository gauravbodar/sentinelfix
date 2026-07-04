import unittest
from datetime import datetime, time as dtime, timezone

from avmp.models import Asset, AssetCriticality, Finding, Severity
from avmp.plugins.network_exposure import PortExposurePlugin
from avmp.remediation import ChangeWindow, RemediationEngine
from avmp.store import AuditSigner, Store


def _engine(**kw):
    store = Store(":memory:", signer=AuditSigner(b"k" * 32))
    return RemediationEngine(store, **kw), store


def _finding(sev=Severity.HIGH, kev=True):
    return Finding("f1", "a1", "demo.exposed_rdp", "Exposed RDP",
                   severity=sev, cve_ids=["CVE-2019-0708"],
                   cvss_score=9.8, epss_score=0.94, in_kev=kev)


def _asset(crit=AssetCriticality.MEDIUM):
    return Asset("a1", hostname="a1", ip_addresses=["127.0.0.1"], criticality=crit)


class TestRemediation(unittest.TestCase):
    def setUp(self):
        self.plugin = PortExposurePlugin("demo.exposed_rdp", "RDP", 3389, severity="high")

    def test_staged_patch_requires_approval_then_applies(self):
        engine, _ = _engine()
        plan = engine.plan(_finding(), _asset(), self.plugin)
        # Without approval -> denied.
        denied = engine.apply(plan, actor="bob.approver")
        self.assertFalse(denied.applied)
        self.assertIn("Approval", denied.denied_reason)
        # Approve (distinct principal) then apply -> success with signed receipt.
        engine.approve(plan, approver="bob.approver", scanner_principal="alice.operator")
        ok = engine.apply(plan, actor="bob.approver")
        self.assertTrue(ok.applied)
        self.assertTrue(ok.receipt_signature)

    def test_mission_critical_is_denied_auto_apply(self):
        engine, _ = _engine()
        plan = engine.plan(_finding(), _asset(AssetCriticality.MISSION_CRITICAL), self.plugin)
        out = engine.apply(plan, actor="bob.approver")
        self.assertFalse(out.applied)
        self.assertIn("not auto-applicable", out.denied_reason)

    def test_separation_of_duties_blocks_self_approval(self):
        engine, _ = _engine()
        plan = engine.plan(_finding(), _asset(), self.plugin)
        with self.assertRaises(PermissionError):
            engine.approve(plan, approver="alice", scanner_principal="alice")

    def test_canary_rollback_on_unhealthy(self):
        engine, _ = _engine()
        plan = engine.plan(_finding(), _asset(), self.plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        out = engine.apply(plan, actor="bob", health_fn=lambda ring: ring.name != "fleet")
        self.assertFalse(out.applied)
        self.assertTrue(any(s.rolled_back for s in out.rollout.steps))

    def test_outside_change_window_denied_but_override_allows(self):
        # A window that never contains 'now' (1 minute at a fixed instant).
        fixed = datetime(2020, 1, 1, 3, 0, tzinfo=timezone.utc)
        window = ChangeWindow(dtime(4, 0), dtime(4, 1))
        engine, _ = _engine(change_windows=[window], clock=lambda: fixed)
        plan = engine.plan(_finding(), _asset(), self.plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        denied = engine.apply(plan, actor="bob")
        self.assertFalse(denied.applied)
        self.assertIn("maintenance window", denied.denied_reason)
        ok = engine.apply(plan, actor="bob", emergency_override=True)
        self.assertTrue(ok.applied)

    def test_audit_chain_intact_after_actions(self):
        engine, store = _engine()
        plan = engine.plan(_finding(), _asset(), self.plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        engine.apply(plan, actor="bob")
        self.assertTrue(store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
