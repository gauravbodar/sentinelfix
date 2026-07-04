"""Remediation engine — canonical implementation in `avmp.remediation`. Re-export shim."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.remediation import (  # noqa: E402,F401
    ChangeWindow,
    RemediationEngine,
    RemediationOutcome,
    RemediationPlan,
)
