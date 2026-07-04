"""SBOM generation (Phase 4 D2 / P4-AC-6).

Produces a lightweight software bill of materials — every module in the package
with its SHA-256 — that is embedded in signed bundles and lets an auditor verify
exactly what shipped. The same inputs always yield the same SBOM, which is what
makes bundle builds reproducible (identical digest).
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def generate_sbom(package_dir: str, name: str = "avmp") -> dict:
    root = Path(package_dir)
    components = []
    for f in sorted(root.rglob("*.py")):
        rel = f.relative_to(root.parent).as_posix()
        components.append({
            "name": rel,
            "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
        })
    return {
        "format": "CycloneDX-lite",
        "package": name,
        "component_count": len(components),
        "components": components,
    }
