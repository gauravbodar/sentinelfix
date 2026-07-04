# SentinelFix — Autonomous Vulnerability Management Platform (AVMP)

> Governed, auditable vulnerability detection and remediation for government
> environments (air-gapped, compliance-first, change-controlled).

A **runnable Phase 0/1 MVP** built with the **Python standard library only** — no
pip installs, no external services — so it runs on a sealed / air-gapped
appliance. See [`../sentinelfix-prd.md`](../sentinelfix-prd.md) for the full PRD.

## Quickstart

```bash
# from this directory (sentinelfix/), Python 3.11+
python -m avmp demo            # MVP pipeline end-to-end, writes reports to ./out
python -m avmp phase2          # Phase 2: ingest -> score -> playbook -> workflow -> report
python -m avmp phase3          # Phase 3: safe auto-remediation with real reversible backend
python -m avmp benchmark       # detection + false-positive rate (Phase 2 AC-10)
python -m avmp ingest --kev KEV.json --epss EPSS.csv.gz --db avmp.db   # load real feeds
python -m avmp authoring       # playbook authoring UI on http://127.0.0.1:8600
python run_tests.py            # full suite (63 tests) — reliable runner
python -m avmp serve           # read-only Console API on http://127.0.0.1:8443
```

`demo` binds a throwaway localhost TCP listener as a stand-in "exposed service",
so detection is deterministic and **no external host is touched**. All
remediation runs in **simulation mode** (PRD §6) — no real firewall/host is
modified.

### What the demo exercises (maps to MVP acceptance criteria)

1. **Discovery & asset registry** — register assets with ownership + criticality.
2. **Scan → enrich → prioritize** — real TCP probe → finding → CVE/EPSS/KEV
   enrichment → blended risk score (not raw CVSS).
3. **Governed remediation** — the policy matrix routes a medium-criticality host
   to `staged_patch` (needs approval) and a mission-critical host to
   `manual_only` (auto-apply denied); separation of duties blocks self-approval.
4. **Canary rollback** — a failed health check on the `fleet` ring triggers
   automatic rollback.
5. **Air-gapped signed VDB import** — export → verify → import a signed bundle;
   a tampered bundle is rejected (fail-closed).
6. **Reports + WORM audit** — technical report, findings CSV, remediation ledger,
   and per-finding playbook; the audit chain is HMAC-signed and tamper-evident.

## Implementation layout (`avmp/`)

The real implementation is the importable `avmp` package (the scaffold's
hyphenated `services/*` dirs aren't valid Python module names, so they act as
documented deployment entrypoints that delegate into `avmp`).

| Module                         | Responsibility                                   | PRD |
| ------------------------------ | ------------------------------------------------ | --- |
| `avmp/models.py`               | Asset/Finding/Policy/Audit + risk scoring        | §4  |
| `avmp/store.py`                | SQLite store + tamper-evident WORM audit chain   | §4/§7 |
| `avmp/rbac.py`                 | Roles, permissions, separation of duties         | §7  |
| `avmp/plugin_sdk.py`           | Plugin contract + sandboxed (timeout) runner     | §5  |
| `avmp/plugins/`                | Built-in network-exposure checks (RDP/SMB/Telnet)| §5  |
| `avmp/probes.py`               | Real TCP/UDP probes                              | §3  |
| `avmp/scanner.py`              | Scanner node: discover + run plugins → findings  | §4  |
| `avmp/enrichment.py`           | Local VDB + EPSS/KEV enrichment                  | §4/§5 |
| `avmp/policy_matrix.py`        | Fail-closed remediation policy matrix            | §6  |
| `avmp/canary.py`               | Staged rollout + rollback controller             | §6  |
| `avmp/remediation.py`          | Governed apply: approval/window/canary/receipts  | §6  |
| `avmp/vdb.py`                  | Signed bundle export/verify/offline import       | §5/§7 |
| `avmp/reporting.py`            | Technical/exec report, CSV, playbook, ledger     | §8  |
| `avmp/console.py`, `api.py`, `cli.py` | Orchestration facade, HTTP API, CLI       | §4  |
| **Phase 2 →** `avmp/ingest.py` | KEV/EPSS feed ingestion → signed VDB bundle     | §5 D1 |
| `avmp/scoring.py`              | Configurable, explainable, versioned risk scoring | §4 D2 |
| `avmp/playbooks.py`            | Versioned playbook templates + linkage engine    | §6 D3 |
| `avmp/workflow.py`             | Manual remediation state machine + SLA + audit   | §6 D4 |
| `avmp/ui.py`                   | Server-rendered playbook authoring UI (stdlib)   | §6 D3.2 |
| **Phase 3 →** `avmp/backends.py` | Remediation backends + 3 safe auto-fix actions | §6 |
| `avmp/targets.py`              | Controllable host model (real, reversible state) | §6 |
| `avmp/benchmark.py`            | Detection / false-positive benchmark (AC-10)     | §10 |

**Docs:** [phase2-deliverables](docs/phase2-deliverables.md) ·
[phase3-deliverables](docs/phase3-deliverables.md) · [DELTA.md](DELTA.md) ·
[deployment-airgap](docs/deployment-airgap.md).

### Scaffold path → implementation

The original scaffold paths still resolve — they re-export from `avmp`:

- `packages/shared/models.py` → `avmp.models`
- `packages/plugin-sdk/plugin_base.py` → `avmp.plugin_sdk`
- `services/scanner-node/main.py` → runs `avmp.scanner.ScannerNode`
- `services/console/main.py` → starts `avmp.api`
- `services/remediation-engine/*` → `avmp.remediation` / `policy_matrix` / `canary`
- `services/vdb-updater/updater.py` → `avmp.vdb`
- `plugins/example_open_rdp/plugin.py` → subclass of the real `PortExposurePlugin`

## Safety & scope notes

- **Authorized use only.** `avmp/probes.py` opens real sockets. Point scans only
  at systems you are permitted to test.
- **Remediation is real but targets a model.** Phase 3 apply/validate/rollback
  actually mutate and restore a controllable `SimulatedHost` (`avmp/targets.py`) —
  genuine reversible logic, but **no live infrastructure is touched**. A
  production backend (SSH/WinRM/Azure NSG) drops into the `RemediationBackend`
  interface behind the same policy/approval/canary/audit gates.
- **Not yet implemented (Phase 4):** production host/cloud remediation adapters,
  credentialed SSH/WinRM checks, WASM plugin sandbox, vendor patch orchestration,
  SAML/AD auth + MFA, FIPS crypto, HA clustering, ServiceNow/Jira integration.

## Roadmap (PRD §9)

- **Phase 0/1** — foundation + core scanning/reporting.  ← *implemented*
- **Phase 2** — KEV/EPSS ingestion, configurable scoring, playbook backend +
  linkage, **server-rendered authoring UI**, manual remediation workflow, exec
  reporting, detection benchmark (AC-10).  ← *implemented*
- **Phase 3** — safe auto-remediation with **real, reversible backends** (3 safe
  actions), post-fix validation, canary rollback against a controllable host
  model.  ← *implemented* (production SSH/WinRM/Azure adapters are Phase 4).
- **Phase 4** — government hardening (FIPS/TLS, real WORM store, ServiceNow).
- **Phase 5** — agents + passive sensors.
