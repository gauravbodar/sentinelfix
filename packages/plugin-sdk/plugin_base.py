"""Plugin SDK contract — canonical implementation lives in `avmp.plugin_sdk`.

Re-export shim so the documented `packages/plugin-sdk` path resolves to the real
runner. `RemediationResult` is kept as an alias of `RemediationProposal` for
backward compatibility with the original scaffold.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.plugin_sdk import (  # noqa: E402,F401
    CheckResult,
    CheckStatus,
    Plugin,
    PluginConstraints,
    PluginMetadata,
    PluginTarget,
    RemediationProposal,
    run_check,
)

RemediationResult = RemediationProposal  # legacy alias
