import unittest

from avmp.backends import HostModelBackend
from avmp.models import Asset, AssetCriticality, Finding, Severity
from avmp.plugins.network_exposure import PortExposurePlugin
from avmp.remediation import RemediationEngine
from avmp.store import AuditSigner, Store
from avmp.targets import SimulatedHost, TargetRegistry


def _finding(port=3389):
    return Finding("f1", "web", "demo.exposed_rdp", "Exposed RDP",
                   severity=Severity.HIGH, cve_ids=["CVE-2019-0708"],
                   cvss_score=9.8, epss_score=0.94, in_kev=True,
                   evidence={"port": str(port), "protocol": "tcp"})


def _asset():
    return Asset("web", hostname="web", ip_addresses=["127.0.0.1"],
                 criticality=AssetCriticality.MEDIUM, internet_facing=True)


def _setup():
    store = Store(":memory:", signer=AuditSigner(b"k" * 32))
    engine = RemediationEngine(store)
    reg = TargetRegistry()
    reg.register(SimulatedHost("web", open_ports={3389}))
    backend = HostModelBackend(reg)
    plugin = PortExposurePlugin("demo.exposed_rdp", "RDP", 3389, severity="high")
    return store, engine, reg, backend, plugin


class TestRemediationWithBackend(unittest.TestCase):
    def test_real_apply_closes_port_and_validates(self):
        store, engine, reg, backend, plugin = _setup()
        plan = engine.plan(_finding(), _asset(), plugin)
        self.assertIsNotNone(plan.action)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        out = engine.apply(plan, actor="bob", backend=backend)
        self.assertTrue(out.applied)
        self.assertTrue(out.validated)         # post-fix validation passed
        self.assertFalse(out.simulated)
        self.assertFalse(reg.get("web").is_port_exposed(3389))  # really fixed

    def test_failed_validation_triggers_rollback_and_restores_host(self):
        store, engine, reg, backend, plugin = _setup()
        plan = engine.plan(_finding(), _asset(), plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        # Force the fleet ring health gate to fail -> rollback.
        out = engine.apply(plan, actor="bob", backend=backend,
                           health_fn=lambda ring: ring.name != "fleet")
        self.assertFalse(out.applied)
        self.assertTrue(reg.get("web").is_port_exposed(3389))   # restored
        self.assertTrue(store.verify_audit_chain())

    def test_audit_records_non_simulated(self):
        store, engine, reg, backend, plugin = _setup()
        plan = engine.plan(_finding(), _asset(), plugin)
        engine.approve(plan, approver="bob", scanner_principal="alice")
        engine.apply(plan, actor="bob", backend=backend)
        applied = [r for r in store.iter_audit() if r["action"] == "remediation.applied"]
        self.assertTrue(applied)
        self.assertEqual(applied[-1]["details"]["simulated"], "false")
        self.assertEqual(applied[-1]["details"]["post_fix_validated"], "True")


if __name__ == "__main__":
    unittest.main()
