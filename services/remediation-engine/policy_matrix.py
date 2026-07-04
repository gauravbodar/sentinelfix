"""Policy matrix — canonical implementation in `avmp.policy_matrix`. Re-export shim."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.policy_matrix import (  # noqa: E402,F401
    DEFAULT_OVERRIDES,
    MatrixDecision,
    MatrixKey,
    resolve,
)
