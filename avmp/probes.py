"""Low-level network probes (PRD §3 Scanner Engine).

Real, non-credentialed TCP/UDP primitives built on the standard library.

Authorized use only: point these at hosts you are permitted to scan. The
scanner layer is responsible for rate limiting and scan-window enforcement.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional


@dataclass
class PortResult:
    host: str
    port: int
    protocol: str          # "tcp" | "udp"
    open: bool
    banner: Optional[str] = None


def is_tcp_open(host: str, port: int, timeout_ms: int = 1_000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_ms / 1000.0)
        try:
            return s.connect_ex((host, port)) == 0
        except OSError:
            return False


def tcp_connect_scan(host: str, ports: list[int], timeout_ms: int = 1_000) -> list[PortResult]:
    results: list[PortResult] = []
    for port in ports:
        is_open = is_tcp_open(host, port, timeout_ms)
        banner = _grab_banner(host, port, timeout_ms) if is_open else None
        results.append(PortResult(host, port, "tcp", is_open, banner))
    return results


def _grab_banner(host: str, port: int, timeout_ms: int) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_ms / 1000.0)
            s.connect((host, port))
            data = s.recv(128)
            text = data.decode("latin-1", errors="replace").strip()
            return text or None
    except OSError:
        return None


def udp_probe(host: str, ports: list[int], timeout_ms: int = 1_000) -> list[PortResult]:
    """Best-effort UDP probe. UDP is connectionless, so 'open' is unreliable;
    we report open=False unless an ICMP-port-unreachable is *not* observed and a
    response comes back. Kept conservative to avoid false positives (PRD §11)."""
    results: list[PortResult] = []
    for port in ports:
        open_guess = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout_ms / 1000.0)
                s.sendto(b"\x00", (host, port))
                try:
                    s.recvfrom(128)
                    open_guess = True
                except socket.timeout:
                    open_guess = False   # no reply -> unknown, report closed
                except OSError:
                    open_guess = False   # port unreachable
        except OSError:
            open_guess = False
        results.append(PortResult(host, port, "udp", open_guess))
    return results
