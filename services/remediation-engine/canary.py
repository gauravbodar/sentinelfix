"""Canary framework — canonical implementation in `avmp.canary`. Re-export shim."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from avmp.canary import (  # noqa: E402,F401
    CanaryRing,
    RolloutResult,
    RolloutStep,
    staged_rollout,
)
