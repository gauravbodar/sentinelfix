"""Built-in plugin registry (PRD §5).

The MVP ships a small set of real, non-credentialed network-exposure checks.
The registry is how the scanner discovers available plugins; production loads
signed WASM bundles (PRD §5) through the same interface.
"""

from __future__ import annotations

from ..plugin_sdk import Plugin
from .network_exposure import OpenRdp, OpenSmb, OpenTelnet, PortExposurePlugin

__all__ = ["PortExposurePlugin", "OpenRdp", "OpenSmb", "OpenTelnet", "builtin_plugins"]


def builtin_plugins() -> list[Plugin]:
    """Instantiate the default plugin set."""
    return [OpenRdp(), OpenSmb(), OpenTelnet()]
