"""Detection benchmark — false-positive rate measurement (Phase 2 AC-10).

Stands up a seeded target lab in-process: a set of *vulnerable* hosts (a real
TCP listener bound on the checked port) and a set of *clean* hosts (the port
closed). It runs the exposure check against each and measures:

  * detection rate      = true positives / vulnerable hosts
  * false-positive rate = false positives / clean hosts   (PRD §10 target < 5%)

Because the credentialed/networked exposure check is deterministic, a correct
implementation yields a 0% false-positive rate on this lab.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass

from .plugin_sdk import CheckStatus, PluginTarget, run_check
from .plugins.network_exposure import PortExposurePlugin


@dataclass
class BenchmarkResult:
    vulnerable: int
    clean: int
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def detection_rate(self) -> float:
        return (self.true_positives / self.vulnerable) if self.vulnerable else 1.0

    @property
    def false_positive_rate(self) -> float:
        return (self.false_positives / self.clean) if self.clean else 0.0


class _Listener:
    def __init__(self) -> None:
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        self.srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self.srv.close()


def _closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_benchmark(n_vulnerable: int = 10, n_clean: int = 20) -> BenchmarkResult:
    tp = fp = fn = 0
    listeners: list[_Listener] = []
    try:
        # Vulnerable hosts: a live listener on the checked port -> expect FAIL.
        for _ in range(n_vulnerable):
            lis = _Listener()
            listeners.append(lis)
            plugin = PortExposurePlugin("bench.exposed", "Svc", lis.port, severity="high")
            res = run_check(plugin, PluginTarget("vuln", "127.0.0.1"))
            if res.status is CheckStatus.FAIL:
                tp += 1
            else:
                fn += 1
        # Clean hosts: the checked port is closed -> expect PASS (no finding).
        for _ in range(n_clean):
            plugin = PortExposurePlugin("bench.exposed", "Svc", _closed_port(), severity="high")
            res = run_check(plugin, PluginTarget("clean", "127.0.0.1"))
            if res.status is CheckStatus.FAIL:
                fp += 1
        return BenchmarkResult(n_vulnerable, n_clean, tp, fp, fn)
    finally:
        for lis in listeners:
            lis.close()
