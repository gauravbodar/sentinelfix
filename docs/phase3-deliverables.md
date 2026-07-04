# SentinelFix — Phase 3 Deliverables & Acceptance Criteria

**Phase 3 — Safe Auto-Remediation (PRD §9, Weeks 17–24)**
Scope: policy matrix, approval workflows, canary rollout engine, rollback
automation, post-fix validation. The MVP already delivered the *governed control
flow* in simulation; Phase 3 makes apply / validate / rollback **real and
reversible** through pluggable remediation backends, and closes the Phase 2
AC-10 benchmark.

Legend: `NEW` · `HARDEN` (extends MVP).

---

## Deliverables

### D1 — Remediation backend abstraction `NEW`
- `RemediationBackend` interface (`apply` / `rollback` / `validate`) in
  `avmp/backends.py`. Production adapters (SSH/WinRM/Azure NSG) implement the
  same interface; the engine, gates, canary, and audit are unchanged.

### D2 — Controllable target model `NEW`
- `avmp/targets.py` — `SimulatedHost` + `TargetRegistry`: real, in-process
  remediable state (firewall denies, service enablement, secrets) so apply and
  rollback exercise genuine reversible logic rather than a no-op.

### D3 — Three safe auto-fix actions `NEW`
- `close_port`, `disable_service`, `rotate_secret` (PRD §6 "Safe Auto").
  Each records an exact undo; every apply is idempotent; non-safe action types
  are rejected.

### D4 — Real apply / post-fix validation / rollback in the engine `HARDEN`
- `RemediationEngine.apply(..., backend=...)` runs the canary staged rollout
  with **real apply**, **post-fix validation** as the health gate, and **exact
  rollback** on failure. Outcome now reports `validated` and `simulated`. Absent
  a backend, the same flow runs in simulation (backward compatible).

### D5 — Detection benchmark (closes Phase 2 AC-10) `NEW`
- `avmp/benchmark.py` — seeds vulnerable (live listener) + clean (closed port)
  targets and measures detection and false-positive rates.

### D6 — Standard per-phase deliverables
- Working build (`avmp phase3`, `avmp benchmark`), green tests, DELTA rows,
  this doc.

---

## Acceptance Criteria

| # | Criterion | Status | Verified by |
|---|-----------|:------:|-------------|
| P3-AC-1 | ≥3 safe auto-fix actions apply, validate, and roll back exactly | ✅ | `test_backends.*` |
| P3-AC-2 | Apply is idempotent; unsafe/unknown actions rejected; unknown target fails closed | ✅ | `test_backends.test_apply_is_idempotent`, `test_unsafe_action_rejected`, `test_unknown_target_raises` |
| P3-AC-3 | Engine performs **real** apply via backend and confirms **post-fix validation** | ✅ | `test_remediation_backend.test_real_apply_closes_port_and_validates` |
| P3-AC-4 | Failed post-fix validation triggers **automatic rollback** that restores the host exactly | ✅ | `test_remediation_backend.test_failed_validation_triggers_rollback_and_restores_host` |
| P3-AC-5 | Real remediation actions produce **signed, non-simulated** WORM audit receipts | ✅ | `test_remediation_backend.test_audit_records_non_simulated` |
| P3-AC-6 | Policy/approval/change-window/SoD gates still enforced with a real backend | ✅ | `test_remediation.*` (unchanged) + backend tests |
| AC-10 (Phase 2) | False-positive rate **< 5%** on the seeded benchmark | ✅ | `test_benchmark.test_false_positive_rate_under_5_percent`; `avmp benchmark` |

MVP §Final acceptance ("≥3 safe auto-fix actions validated in canary mode with
rollback") is now met with **real** apply/rollback, not simulation.

---

## Out of scope (→ Phase 4)
Production host/cloud adapters (SSH/WinRM, Azure NSG), staged **vendor patch**
orchestration (WSUS/SCCM), real change-control (ServiceNow RFC), FIPS crypto,
SAML/AD auth + MFA, HA clustering. The backend interface is the drop-in seam.

## Safety note
`SimulatedHost` is a controllable model, not a live host — no real infrastructure
is modified by this build. A production backend must add real credentials,
dry-run parity, and blast-radius controls before touching live systems, behind
the same policy/approval/canary/audit gates already enforced here.
