# SentinelFix — Phase 2 Deliverables & Acceptance Criteria

**Phase 2 — Prioritization & Playbooks (PRD §9, Weeks 11–16)**
Scope: EPSS/KEV ingestion, risk scoring engine, remediation playbook authoring,
manual remediation workflow. Standard per-phase deliverables also apply: working
build, test harness, playbook examples, this `DELTA.md` checklist, deployment guide.

Legend: `NEW` = net-new · `HARDEN` = extends the MVP slice · `UI` = needs a frontend.

---

## Deliverables

### D1 — EPSS/KEV & VDB ingestion pipeline `HARDEN`
- **D1.1** Ingestion of the **CISA KEV** catalog and **FIRST.org EPSS** dataset into
  a persisted local VDB (replaces the 3-entry built-in slice in `enrichment.py`).
- **D1.2** Air-gap path: both feeds consumed as **signed offline bundles** through
  the existing `avmp/vdb.py` verify→import flow (no outbound calls).
- **D1.3** VDB schema mapping CVE ↔ CVSS ↔ EPSS ↔ percentile ↔ KEV ↔ source, with
  per-record **provenance** (`source`, `last_updated`).
- **D1.4** VDB **staleness** indicator + emergency KEV hotfix channel.

### D2 — Configurable risk scoring engine `HARDEN`
- **D2.1** Externalized, **versioned scoring model** (weights in config, not code).
- **D2.2** Adds **exposure / internet-facing** and asset-context inputs to the score.
- **D2.3** **Explainable** per-factor breakdown ("why this number").
- **D2.4** Findings record the **scoring-model version** for comparable trends.

### D3 — Playbook authoring + template engine `NEW` / `UI`
- **D3.1** Versioned **playbook template model** covering all 10 PRD §6 fields.
- **D3.2** **Authoring UI** with draft→review→publish states — delivered as a
  **server-rendered, standard-library-only** web UI (`avmp/ui.py`); no JS
  framework / Node / npm, keeping the air-gapped supply-chain footprint minimal
  (PRD §7/§11). RBAC + author≠publisher separation of duties enforced.
- **D3.3** Playbook ↔ finding **linkage engine** (bind by plugin id / CVE / severity).
- **D3.4** Starter **library of ≥10 authored playbooks**.

### D4 — Manual remediation workflow `NEW`
- **D4.1** Finding **lifecycle state machine** with guarded transitions.
- **D4.2** **Assignment + SLA timers** driven by risk score, with escalation.
- **D4.3** **Verification loop** — re-scan must PASS before `verified`.
- **D4.4** Every transition written to the **WORM audit log**.
- **D4.5** **False-positive feedback** path to plugin authors.

### D5 — Reporting extensions `HARDEN`
- **D5.1** **Executive summary** (top risks, trend line, MTTR).
- **D5.2** Trend persistence (scan-over-scan risk snapshots).

### D6 — Standard per-phase deliverables
Working build (`avmp ingest` / workflow commands), green test harness,
`DELTA.md`, deployment guide for loading KEV/EPSS bundles on air-gapped sites.

---

## Acceptance Criteria (exit gate — all must pass)

| # | Criterion | Verified by |
|---|-----------|-------------|
| AC-1 | KEV + EPSS ingest via **signed offline bundle**, zero outbound calls; tampered bundle rejected | `test_ingest`, `test_vdb` |
| AC-2 | Every finding enriched from **ingested VDB** with provenance, not the stub | `test_ingest` |
| AC-3 | Risk score driven by **externalized versioned config**; weight change changes score, no code edit | `test_scoring` |
| AC-4 | Each finding exposes a **factor-level breakdown** summing to the score | `test_scoring` |
| AC-5 | Playbook can be **authored, versioned, published**, and bound to a finding class | `test_playbooks` |
| AC-6 | **100% of findings** have a linked playbook (authored or fallback) | `test_playbooks` |
| AC-7 | Workflow enforces the **state machine**; illegal transitions rejected; `verified` blocked until re-scan PASS | `test_workflow` |
| AC-8 | SLA/escalation fire by **risk score**; every transition in the **tamper-evident** audit log | `test_workflow` |
| AC-9 | **Executive summary** renders top risks + trend + MTTR | `test_reporting` |
| AC-10 | **False-positive rate < 5%** on the benchmark check set (PRD §10) | benchmark run (recorded in DELTA) |
| AC-11 | Full suite green; DELTA.md + deployment guide delivered | CI |

---

## Out of scope (→ Phase 3)
Policy-gated **auto**-remediation *execution*, real canary/rollback of live changes,
approval-gated auto-apply backends. Phase 2 remediation is **human-operated**.

## Dependencies / decisions
- KEV/EPSS **bundle signing keys** must exist before D1 (reuses `vdb.py` HMAC; HSM/FIPS in prod).
- **UI stack — DECIDED: server-rendered, stdlib-only** (no JS framework/Node/npm).
  Rationale: preserves the zero-external-dependency, air-gapped, reproducible-build
  posture the product depends on; real auth (SAML/AD, CSRF, mTLS) arrives in Phase 4,
  so the UI currently trusts `actor`/`role` fields and must sit behind an
  authenticated proxy.
