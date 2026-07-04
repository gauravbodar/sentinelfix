"""Canary & rollback framework (PRD §6, Phase 3).

Apply a change to a small canary ring first, run health checks, and only
proceed if healthy — otherwise roll back everything applied so far. All apply /
health / rollback effects are injected callables so this controller is pure and
testable, and so the MVP can run it in simulation mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CanaryRing:
    name: str
    asset_ids: list[str] = field(default_factory=list)


@dataclass
class RolloutStep:
    ring: str
    applied: bool
    healthy: bool
    rolled_back: bool = False


@dataclass
class RolloutResult:
    success: bool
    steps: list[RolloutStep] = field(default_factory=list)


# Callable signatures (all keyed by ring):
ApplyFn = Callable[[CanaryRing], None]
HealthFn = Callable[[CanaryRing], bool]
RollbackFn = Callable[[CanaryRing], None]


def staged_rollout(
    rings: list[CanaryRing],
    apply_fn: ApplyFn,
    health_fn: HealthFn,
    rollback_fn: RollbackFn,
) -> RolloutResult:
    """Apply ring-by-ring; on the first failed health gate, roll back all
    rings applied so far (in reverse) and stop."""
    result = RolloutResult(success=True)
    applied_rings: list[CanaryRing] = []

    for ring in rings:
        apply_fn(ring)
        applied_rings.append(ring)
        healthy = health_fn(ring)
        step = RolloutStep(ring=ring.name, applied=True, healthy=healthy)
        result.steps.append(step)

        if not healthy:
            result.success = False
            for done in reversed(applied_rings):
                rollback_fn(done)
                for s in result.steps:
                    if s.ring == done.name:
                        s.rolled_back = True
            return result

    return result
