import os
import unittest

from avmp.azure_client import AzureNsgClient, NsgScope, build_from_env
from avmp.backends import AzureNsgBackend, RemediationAction, RemediationBackendError


class FakeAzureClient(AzureNsgClient):
    """In-memory stand-in for a live Azure NSG client (no SDK required)."""

    def __init__(self):
        self.rules: dict[tuple, dict] = {}   # (rg, nsg) -> {name: port}
        self.calls: list[str] = []

    def create_deny_rule(self, scope, name, port, priority=100):
        self.calls.append(f"create {name}")
        self.rules.setdefault((scope.resource_group, scope.nsg_name), {})[name] = port

    def delete_rule(self, scope, name):
        self.calls.append(f"delete {name}")
        self.rules.get((scope.resource_group, scope.nsg_name), {}).pop(name, None)

    def deny_exists(self, scope, port):
        return port in self.rules.get((scope.resource_group, scope.nsg_name), {}).values()


class TestAzureNsgBackend(unittest.TestCase):
    def setUp(self):
        self.be = AzureNsgBackend()

    def test_close_port_apply_validate_rollback(self):
        a = RemediationAction("nsg1", "close_port", "web-dmz-01", {"port": "3389"})
        self.assertFalse(self.be.validate(a))
        self.be.apply(a)
        self.assertTrue(self.be.validate(a))          # deny rule present
        self.be.rollback(a)
        self.assertFalse(self.be.validate(a))         # rule removed

    def test_preview_is_dry_run_only(self):
        a = RemediationAction("nsg2", "close_port", "web-dmz-01", {"port": "22"})
        preview = self.be.preview(a)
        self.assertIn("DRY-RUN", preview)
        self.assertIn("az network nsg rule create", preview)
        self.assertFalse(self.be.validate(a))         # preview did not apply

    def test_non_close_port_rejected(self):
        a = RemediationAction("nsg3", "rotate_secret", "web-dmz-01", {"secret": "x"})
        with self.assertRaises(RemediationBackendError):
            self.be.apply(a)


class TestAzureLiveClientRouting(unittest.TestCase):
    """Same backend logic, routed through a (fake) live client — proves the
    credentials-only switch without any Azure SDK installed."""

    def setUp(self):
        self.client = FakeAzureClient()
        self.scope = NsgScope("sub-123", "rg-prod", "nsg-web")
        self.be = AzureNsgBackend(client=self.client, scopes={"web-dmz-01": self.scope})
        self.action = RemediationAction("live1", "close_port", "web-dmz-01", {"port": "3389"})

    def test_apply_validate_rollback_hits_client(self):
        self.assertFalse(self.be.validate(self.action))
        self.be.apply(self.action)
        self.assertTrue(self.be.validate(self.action))          # real client call
        self.be.rollback(self.action)
        self.assertFalse(self.be.validate(self.action))
        self.assertIn("create deny-3389", self.client.calls)
        self.assertIn("delete deny-3389", self.client.calls)

    def test_preview_shows_live_target(self):
        p = self.be.preview(self.action)
        self.assertIn("[LIVE]", p)
        self.assertIn("rg-prod", p)
        self.assertIn("nsg-web", p)

    def test_asset_without_scope_falls_back_to_simulated(self):
        # Client present but no scope for this asset -> must NOT touch live.
        a = RemediationAction("live2", "close_port", "unmapped-asset", {"port": "22"})
        self.be.apply(a)
        self.assertEqual(self.client.calls, [])   # no live call made
        self.assertTrue(self.be.validate(a))       # simulated NSG instead


class TestAzureEnvSwitch(unittest.TestCase):
    def test_build_from_env_is_none_without_subscription(self):
        saved = os.environ.pop("AZURE_SUBSCRIPTION_ID", None)
        try:
            self.assertIsNone(build_from_env())   # air-gap safe: no creds -> simulated
        finally:
            if saved is not None:
                os.environ["AZURE_SUBSCRIPTION_ID"] = saved


if __name__ == "__main__":
    unittest.main()
