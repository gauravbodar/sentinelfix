"""VDB updater — canonical implementation in `avmp.vdb`. Re-export shim.

Air-gapped import is the supported path; online sync is intentionally disabled.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.vdb import (  # noqa: E402,F401
    BundleManifest,
    BundleVerificationError,
    export_bundle,
    import_offline,
    sync_online,
    verify_bundle,
)
