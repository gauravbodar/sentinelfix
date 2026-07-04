"""RBAC — canonical implementation in `avmp.rbac`. Re-export shim."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.rbac import (  # noqa: E402,F401
    Permission,
    Role,
    enforce_separation_of_duties,
    has_permission,
)
