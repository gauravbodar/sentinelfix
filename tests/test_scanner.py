import socket
import threading
import unittest

from avmp.plugins.network_exposure import PortExposurePlugin
from avmp.plugin_sdk import CheckStatus, PluginTarget, run_check
from avmp.scanner import ScannerNode


class _Listener:
    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.srv.settimeout(0.2)
        while not self.stop.is_set():
            try:
                c, _ = self.srv.accept()
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.srv.close()


class TestScanner(unittest.TestCase):
    def test_open_port_produces_finding(self):
        lis = _Listener()
        try:
            plugin = PortExposurePlugin("t.exposed", "Svc", lis.port, severity="high")
            node = ScannerNode()
            findings = node.run_plugins(
                PluginTarget(asset_id="a1", address="127.0.0.1"), [plugin]
            )
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].asset_id, "a1")
        finally:
            lis.close()

    def test_closed_port_produces_no_finding(self):
        # Bind then immediately close to obtain an almost-certainly-closed port.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()
        plugin = PortExposurePlugin("t.exposed", "Svc", closed_port)
        node = ScannerNode()
        findings = node.run_plugins(
            PluginTarget(asset_id="a1", address="127.0.0.1"), [plugin]
        )
        self.assertEqual(findings, [])

    def test_plugin_timeout_becomes_error(self):
        import time as _t

        from avmp.plugin_sdk import CheckResult, Plugin, PluginConstraints, PluginMetadata

        class SlowPlugin(Plugin):
            metadata = PluginMetadata("slow", "slow")
            constraints = PluginConstraints(max_runtime_ms=100)

            def check(self, target):
                _t.sleep(0.5)
                return CheckResult(CheckStatus.PASS)

        res = run_check(SlowPlugin(), PluginTarget("a", "127.0.0.1"))
        self.assertEqual(res.status, CheckStatus.ERROR)
        self.assertIn("timeout", res.evidence.get("error", ""))


if __name__ == "__main__":
    unittest.main()
