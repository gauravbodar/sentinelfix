import unittest

from avmp.backends import (
    HostModelBackend,
    RemediationAction,
    RemediationBackendError,
)
from avmp.targets import SimulatedHost, TargetRegistry


def _registry():
    reg = TargetRegistry()
    reg.register(SimulatedHost(
        asset_id="h1", open_ports={3389, 445},
        services={"telnet": True}, secrets={"api": "old-value"},
    ))
    return reg


class TestHostModelBackend(unittest.TestCase):
    def setUp(self):
        self.reg = _registry()
        self.be = HostModelBackend(self.reg)

    def test_close_port_apply_validate_rollback(self):
        host = self.reg.get("h1")
        a = RemediationAction("a1", "close_port", "h1", {"port": "3389"})
        self.assertTrue(host.is_port_exposed(3389))
        self.be.apply(a)
        self.assertFalse(host.is_port_exposed(3389))   # fixed
        self.assertTrue(self.be.validate(a))            # post-fix validation
        self.be.rollback(a)
        self.assertTrue(host.is_port_exposed(3389))     # restored exactly

    def test_disable_service_apply_validate_rollback(self):
        host = self.reg.get("h1")
        a = RemediationAction("a2", "disable_service", "h1", {"service": "telnet"})
        self.be.apply(a)
        self.assertFalse(host.service_enabled("telnet"))
        self.assertTrue(self.be.validate(a))
        self.be.rollback(a)
        self.assertTrue(host.service_enabled("telnet"))

    def test_rotate_secret_apply_validate_rollback(self):
        host = self.reg.get("h1")
        a = RemediationAction("a3", "rotate_secret", "h1",
                              {"secret": "api", "old_value": "old-value"})
        self.be.apply(a)
        self.assertNotEqual(host.get_secret("api"), "old-value")
        self.assertTrue(self.be.validate(a))
        self.be.rollback(a)
        self.assertEqual(host.get_secret("api"), "old-value")

    def test_apply_is_idempotent(self):
        host = self.reg.get("h1")
        a = RemediationAction("a4", "close_port", "h1", {"port": "445"})
        self.be.apply(a)
        self.be.apply(a)   # second apply must not corrupt the undo
        self.be.rollback(a)
        self.assertTrue(host.is_port_exposed(445))

    def test_unsafe_action_rejected(self):
        a = RemediationAction("a5", "reformat_disk", "h1", {})
        with self.assertRaises(RemediationBackendError):
            self.be.apply(a)

    def test_unknown_target_raises(self):
        a = RemediationAction("a6", "close_port", "ghost", {"port": "22"})
        with self.assertRaises(RemediationBackendError):
            self.be.apply(a)


if __name__ == "__main__":
    unittest.main()
