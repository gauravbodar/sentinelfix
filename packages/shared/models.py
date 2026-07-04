"""Shared domain models — canonical implementation lives in `avmp.models`.

This path is kept for the scaffold's documented layout; it re-exports the real
models so existing imports (`packages.shared.models`) resolve to one source of
truth. See ../../avmp/models.py.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.models import (  # noqa: E402,F401
    Asset,
    AssetCriticality,
    AuditRecord,
    Finding,
    Policy,
    RemediationMode,
    Severity,
    utcnow,
)
