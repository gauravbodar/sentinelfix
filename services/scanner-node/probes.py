"""Network probes — canonical implementation in `avmp.probes`. Re-export shim."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.probes import (  # noqa: E402,F401
    PortResult,
    is_tcp_open,
    tcp_connect_scan,
    udp_probe,
)
