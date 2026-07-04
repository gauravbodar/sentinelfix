"""Scanner node entrypoint — delegates to the real `avmp.scanner.ScannerNode`.

Run a one-off scan of a target against the built-in plugin set:
    python services/scanner-node/main.py 127.0.0.1
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.plugin_sdk import PluginTarget  # noqa: E402
from avmp.plugins import builtin_plugins  # noqa: E402
from avmp.scanner import ScannerNode  # noqa: E402

# Re-exported for `from ... import ScannerNode` compatibility.
__all__ = ["ScannerNode"]


def main() -> int:
    address = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    node = ScannerNode()
    target = PluginTarget(asset_id=address, address=address)
    findings = node.run_plugins(target, builtin_plugins())
    print(f"Scanned {address}: {len(findings)} finding(s)")
    for f in findings:
        print(f"  - {f.title} [{f.severity.value}] {f.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
