"""Reference plugin: internet-exposed RDP (TCP/3389) — PRD §12.B.

Now a thin subclass of the real, implemented `PortExposurePlugin` in
`avmp.plugins.network_exposure`. The check is a real TCP reachability probe; the
remediation proposal is a reversible firewall/NSG rule, dry-run by default.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.plugins.network_exposure import PortExposurePlugin  # noqa: E402


class OpenRdpPlugin(PortExposurePlugin):
    def __init__(self) -> None:
        super().__init__(
            plugin_id="net.exposed_rdp.3389",
            service_name="RDP",
            port=3389,
            severity="high",
            cve=["CVE-2019-0708"],
        )


if __name__ == "__main__":
    from avmp.plugin_sdk import PluginTarget, run_check

    plugin = OpenRdpPlugin()
    result = run_check(plugin, PluginTarget(asset_id="demo", address="127.0.0.1"))
    print(f"{plugin.metadata.name}: {result.status.value} — {result.evidence}")
