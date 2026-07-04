# DELTA.md — Phase 2 Verification Checklist

Phase 2 (Prioritization & Playbooks). Run everything from `sentinelfix/`:

```bash
python -m unittest discover -s tests -t .   # full suite (48 tests)
python -m avmp phase2                        # Phase 2 pipeline end-to-end
python -m avmp demo                          # MVP pipeline (regression)
```

Status legend: ✅ done · 🟡 partial/headless · ⛔ deferred.

| AC | Criterion | Status | Proof (test / command) |
|----|-----------|:------:|------------------------|
| AC-1 | KEV+EPSS ingest via **signed offline bundle**, zero outbound calls; tampered bundle rejected | ✅ | `test_ingest.test_ingest_offline_persists_with_provenance`, `test_ingest.test_tampered_bundle_rejected_on_ingest`, `test_vdb.*` |
| AC-2 | Findings enriched from **ingested VDB** with provenance, not the stub | ✅ | `test_ingest.test_enricher_uses_ingested_vdb`; `avmp phase2` D1/D2 |
| AC-3 | Risk score driven by **externalized versioned config**; weight change → score change, no code edit | ✅ | `test_scoring.test_weight_change_changes_score_without_code`, `test_scoring.test_config_roundtrip` |
| AC-4 | Each finding exposes a **factor-level breakdown** summing to the score | ✅ | `test_scoring.test_factor_breakdown_sums_to_score`; `avmp phase2` D2 output |
| AC-5 | Playbook can be **authored, versioned, published**, bound to a finding class | 🟡 | `test_playbooks.test_lifecycle_draft_review_publish_and_versioning` (headless; **web authoring UI D3.2 deferred** pending UI-stack decision) |
| AC-6 | **100% of findings** have a linked playbook (authored or fallback) | ✅ | `test_playbooks.test_match_*`, `test_attach_returns_fallback_when_no_match`; `PlaybookRepository.attach()` never returns empty |
| AC-7 | Workflow enforces the **state machine**; illegal transitions rejected; `verified` blocked until re-scan PASS | ✅ | `test_workflow.test_illegal_transition_rejected`, `test_verified_blocked_until_rescan_passes`, `test_open_and_full_lifecycle` |
| AC-8 | SLA/escalation fire by **risk score**; every transition in the **tamper-evident** audit log | ✅ | `test_workflow.test_sla_bands`, `test_sla_breach_detection`, `test_audit_chain_intact` |
| AC-9 | **Executive summary** renders top risks + trend + MTTR | ✅ | `test_reporting.test_summary_*`, `test_mttr_computed_from_tickets`; `out/executive_summary.md` |
| AC-10 | **False-positive rate < 5%** on benchmark check set | ⛔ | Deferred — needs a benchmark target-lab; the FP feedback path exists (`test_workflow.test_false_positive_feedback`). Tracked as open Phase 2 test-harness item. |
| AC-11 | Full suite green; DELTA.md + deployment guide delivered | ✅ | `python -m unittest discover -s tests -t .` → 48 passing; this file; `docs/deployment-airgap.md` |

## Deliverable → code map

| Deliverable | Module(s) | Tests |
|-------------|-----------|-------|
| D1 KEV/EPSS ingestion | `avmp/ingest.py`, `avmp/vdb.py`, `avmp/store.py` (vdb table), `avmp/enrichment.py` | `test_ingest`, `test_vdb` |
| D2 Scoring engine | `avmp/scoring.py` | `test_scoring` |
| D3 Playbook backend + linkage | `avmp/playbooks.py`, `avmp/store.py` (playbooks table) | `test_playbooks` |
| D4 Manual workflow | `avmp/workflow.py`, `avmp/store.py` (tickets table) | `test_workflow` |
| D5 Reporting/trend | `avmp/reporting.py`, `avmp/store.py` (risk_snapshots table) | `test_reporting` |

## Known open items (carry into Phase 2 close-out / Phase 3)

- **D3.2 web authoring UI** — backend + linkage complete; UI blocked on stack choice.
- **AC-10 benchmark FP measurement** — needs a seeded target lab.
- Reporting "Top risks" table currently uses the simple `Finding.risk_score`; the
  configurable engine (`avmp/scoring.py`) is authoritative and used by the Console,
  snapshots, and workflow SLAs. Unify in close-out if a single number is required.
