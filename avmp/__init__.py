"""AVMP — SentinelFix Autonomous Vulnerability Management Platform.

Runnable MVP (Phase 0/1 vertical slice) implemented with the Python standard
library only, so it runs on a sealed / air-gapped appliance with no external
dependencies (PRD §7 Air-gapped operation).

Pipeline (PRD §4 data flow):
    Discovery -> Scan -> Enrichment -> Prioritization -> Action -> Verify -> Audit

Everything that would touch a real host (remediation apply/rollback) runs in
SIMULATION MODE by default (PRD §6). Scanning uses real TCP sockets and must
only ever be pointed at systems the operator is authorized to scan.
"""

__version__ = "0.1.0-mvp"
