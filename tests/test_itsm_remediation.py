import unittest

from avmp.backends import HostModelBackend
from avmp.itsm import MockServiceNow, RFCState
from avmp.models import Asset, AssetCriticality, Finding, Severity
from avmp.plugins.network_exposure import PortExposurePlugin
from avmp.remediation import RemediationEngine
from avmp.store import AuditSigner, Store
from avmp.targets import SimulatedHost, TargetRegistry


def _finding():
    return Finding("f1", "web", "demo.exposed_rdp", "Exposed RDP",
                   severity=Severity.HIGH, cve_ids=["CVE-2019-0708"],
                   cvss_score=9.8, epss_score=0.94, in_kev=True,
                   evidence={"port": "3389"})


def _asset():
    return Asset("web", ip_addresses=["127.0.0.1"], criticality=AssetCriticality.MEDIUM)


def _engine_with_itsm():
    store = Store(":memory:", signer=AuditSigner(b"k" * 32))
    itsm = MockServiceNow()
    engine = RemediationEngine(store, itsm=itsm)
    reg = TargetRegistry()
    reg.register(SimulatedHost("web", open_ports={3389}))
    backend = HostModelBackend(reg)
    plugin = PortExposurePlugin("demo.exposed_rdp", "RDP", 3389, severity="high")
    return store, itsm, engine, backend, plugin


class TestChangeControlGate(unittest.TestCase):
    def test_apply_blocked_until_rfc_approved(self):
        store, itsm, engine, backend, plugin = _engine_with_itsm()
        plan = engine.plan(_finding(), _asset(), plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        rfc_id = engine.open_change_request(plan, actor="bob")

        # RFC pending -> apply denied.
        denied = engine.apply(plan, actor="bob", backend=backend)
        self.assertFalse(denied.applied)
        self.assertIn("Change request not approved", denied.denied_reason)

        # Approve RFC -> apply proceeds, RFC marked implemented, id in audit.
        itsm.approve(rfc_id, approver="cab.manager")
        ok = engine.apply(plan, actor="bob", backend=backend)
        self.assertTrue(ok.applied)
        self.assertEqual(itsm.get(rfc_id).state, RFCState.IMPLEMENTED)
        applied = [r for r in store.iter_audit() if r["action"] == "remediation.applied"]
        self.assertEqual(applied[-1]["details"]["rfc_id"], rfc_id)

    def test_no_rfc_means_denied(self):
        store, itsm, engine, backend, plugin = _engine_with_itsm()
        plan = engine.plan(_finding(), _asset(), plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        # No RFC opened at all.
        out = engine.apply(plan, actor="bob", backend=backend)
        self.assertFalse(out.applied)


if __name__ == "__main__":
    unittest.main()
