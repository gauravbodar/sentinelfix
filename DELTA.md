# DELTA.md — Phase 2 Verification Checklist

Phase 2 (Prioritization & Playbooks). Run everything from `sentinelfix/`:

```bash
python run_tests.py                          # full suite (93 tests) — reliable runner
python -m unittest discover -s tests         # (also works; avoid the `-t .` form on Windows)
python -m avmp phase2                        # Phase 2 prioritization & playbooks
python -m avmp phase3                        # Phase 3 safe auto-remediation (real backend)
python -m avmp phase4                        # Phase 4 government hardening
python -m avmp benchmark                      # AC-10 detection / false-positive rate
python -m avmp authoring                      # playbook authoring UI :8600
python -m avmp demo                          # MVP pipeline (regression)
```

Status legend: ✅ done · 🟡 partial/headless · ⛔ deferred.

| AC | Criterion | Status | Proof (test / command) |
|----|-----------|:------:|------------------------|
| AC-1 | KEV+EPSS ingest via **signed offline bundle**, zero outbound calls; tampered bundle rejected | ✅ | `test_ingest.test_ingest_offline_persists_with_provenance`, `test_ingest.test_tampered_bundle_rejected_on_ingest`, `test_vdb.*` |
| AC-2 | Findings enriched from **ingested VDB** with provenance, not the stub | ✅ | `test_ingest.test_enricher_uses_ingested_vdb`; `avmp phase2` D1/D2 |
| AC-3 | Risk score driven by **externalized versioned config**; weight change → score change, no code edit | ✅ | `test_scoring.test_weight_change_changes_score_without_code`, `test_scoring.test_config_roundtrip` |
| AC-4 | Each finding exposes a **factor-level breakdown** summing to the score | ✅ | `test_scoring.test_factor_breakdown_sums_to_score`; `avmp phase2` D2 output |
| AC-5 | Playbook can be **authored, versioned, published**, bound to a finding class, via a **web UI** | ✅ | `test_playbooks.test_lifecycle_draft_review_publish_and_versioning`, `test_ui.*` (server-rendered authoring UI; RBAC + author≠publisher SoD enforced) |
| AC-6 | **100% of findings** have a linked playbook (authored or fallback) | ✅ | `test_playbooks.test_match_*`, `test_attach_returns_fallback_when_no_match`; `PlaybookRepository.attach()` never returns empty |
| AC-7 | Workflow enforces the **state machine**; illegal transitions rejected; `verified` blocked until re-scan PASS | ✅ | `test_workflow.test_illegal_transition_rejected`, `test_verified_blocked_until_rescan_passes`, `test_open_and_full_lifecycle` |
| AC-8 | SLA/escalation fire by **risk score**; every transition in the **tamper-evident** audit log | ✅ | `test_workflow.test_sla_bands`, `test_sla_breach_detection`, `test_audit_chain_intact` |
| AC-9 | **Executive summary** renders top risks + trend + MTTR | ✅ | `test_reporting.test_summary_*`, `test_mttr_computed_from_tickets`; `out/executive_summary.md` |
| AC-10 | **False-positive rate < 5%** on benchmark check set | ✅ | `test_benchmark.test_false_positive_rate_under_5_percent`; `avmp benchmark` → 0.00% FP, 100% detection |
| AC-11 | Full suite green; DELTA.md + deployment guide delivered | ✅ | `python run_tests.py` → 63 passing; this file; `docs/deployment-airgap.md` |

### Phase 3 — Safe auto-remediation (real backends)

| # | Criterion | Status | Proof |
|---|-----------|:------:|-------|
| P3-AC-1 | ≥3 safe auto-fix actions apply/validate/rollback exactly | ✅ | `test_backends.*` |
| P3-AC-2 | Idempotent apply; unsafe/unknown action + target rejected | ✅ | `test_backends.test_apply_is_idempotent`, `..._unsafe_action_rejected`, `..._unknown_target_raises` |
| P3-AC-3 | Engine real apply + post-fix validation via backend | ✅ | `test_remediation_backend.test_real_apply_closes_port_and_validates` |
| P3-AC-4 | Failed validation → automatic rollback restores host exactly | ✅ | `test_remediation_backend.test_failed_validation_triggers_rollback_and_restores_host` |
| P3-AC-5 | Real actions produce signed, non-simulated audit receipts | ✅ | `test_remediation_backend.test_audit_records_non_simulated` |
| P3-AC-6 | Policy/approval/window/SoD gates hold with a real backend | ✅ | `test_remediation.*` + backend tests |

See [docs/phase3-deliverables.md](docs/phase3-deliverables.md).

### Phase 4 — Government hardening

| # | Criterion | Status | Proof |
|---|-----------|:------:|-------|
| P4-AC-1 | Asymmetric signing; public-key verify; tamper/wrong-key rejected | ✅ | `test_crypto_supplychain.*` |
| P4-AC-4 | WORM signed checkpoints detect edit + truncation | ✅ | `test_worm.*` |
| P4-AC-5 | Privileged action requires identity + MFA | ✅ | `test_authn.*` |
| P4-AC-6 | Verifiable SBOM + reproducible build digest | ✅ | `test_crypto_supplychain.*` |
| P4-AC-7 | Auto-RFC; apply blocked until approved; RFC id in audit | ✅ | `test_itsm_remediation.*` |
| P4-AC-8 | Azure NSG adapter apply/rollback, dry-run first; **live-tenant routing tested via fake client** (credentials-only switch) | ✅ | `test_azure_backend.*` (incl. `TestAzureLiveClientRouting`); go-live: `docs/azure-live-switch.md` |
| P4-AC-10 | Console failover, zero audit loss; scanner reroute | ✅ | `test_ha.*` |
| P4-AC-2/3/9 | TLS/mTLS, at-rest encryption, CIS/STIG image | 🟡 SWAP | need certs/KMS/image (see phase4-deliverables) |

7 of 11 fully REAL in-repo; 4 need a target environment. See
[docs/phase4-deliverables.md](docs/phase4-deliverables.md),
[docs/compliance-pack.md](docs/compliance-pack.md), and
[docs/demo-script.md](docs/demo-script.md).

## Deliverable → code map

| Deliverable | Module(s) | Tests |
|-------------|-----------|-------|
| D1 KEV/EPSS ingestion | `avmp/ingest.py`, `avmp/vdb.py`, `avmp/store.py` (vdb table), `avmp/enrichment.py` | `test_ingest`, `test_vdb` |
| D2 Scoring engine | `avmp/scoring.py` | `test_scoring` |
| D3 Playbook backend + linkage | `avmp/playbooks.py`, `avmp/store.py` (playbooks table) | `test_playbooks` |
| D3.2 Playbook authoring UI | `avmp/ui.py` (stdlib http.server, HTML forms) | `test_ui` |
| D4 Manual workflow | `avmp/workflow.py`, `avmp/store.py` (tickets table) | `test_workflow` |
| D5 Reporting/trend | `avmp/reporting.py`, `avmp/store.py` (risk_snapshots table) | `test_reporting` |

## Known open items (pilot / hardening engagement)

- **Live environment swap-ins** — Azure NSG adapter is built + tested and is a
  credentials-only switch (`docs/azure-live-switch.md`); still to wire against real
  services: **SSH/WinRM** adapter, **Entra/SAML** SSO, **ServiceNow** instance,
  **FIPS** module, **TLS certs / at-rest KMS**, **CIS/STIG** image.
- Reporting "Top risks" table uses the simple `Finding.risk_score`; the configurable
  engine (`avmp/scoring.py`) is authoritative elsewhere. Unify if a single number is required.
