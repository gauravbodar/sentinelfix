# SentinelFix — Phase 4 Deliverables & Acceptance Criteria

**Phase 4 — Government Hardening (PRD §9, Weeks 25–36)**
Air-gapped update bundles, FIPS/TLS hardening, WORM audit store, ServiceNow
integration, appliance packaging.

Run the whole thing: `python -m avmp phase4`. Tests: `python run_tests.py`.

**Honesty tag on every row:** `REAL` = working implementation in this build ·
`SWAP` = production replaces a stand-in (marked) with a real service/module.
Nothing below claims FIPS *validation* or an ATO — those are procurement/lab
activities, not code.

---

## Deliverables

| # | Deliverable | State | Module |
|---|-------------|-------|--------|
| D1 | TLS 1.2/1.3 + mTLS + at-rest encryption | `SWAP` (needs certs/KMS) | `avmp/api.py` (+ TLS wrap), deployment |
| D2 | Asymmetric bundle signing (RSA) + SBOM + reproducible build | `REAL` | `avmp/crypto.py`, `avmp/supplychain.py`, `avmp/sbom.py` |
| D3 | Hardened WORM audit — signed checkpoints, truncation detection | `REAL` | `avmp/worm.py`, `avmp/store.py` |
| D4 | AuthN + MFA (TOTP real; SAML/Entra is the SWAP) | `REAL`/`SWAP` | `avmp/authn.py` |
| D5 | Azure NSG remediation adapter (reversible; live tenant = SWAP) | `REAL`/`SWAP` | `avmp/backends.py` (`AzureNsgBackend`) |
| D6 | ServiceNow/Jira change control (RFC gate; live instance = SWAP) | `REAL`/`SWAP` | `avmp/itsm.py`, `avmp/remediation.py` |
| D7 | Air-gapped operation — offline signed import, no telemetry | `REAL` | `avmp/supplychain.py`, `avmp/ingest.py` |
| D8 | High availability — failover, zero audit loss, scanner reroute | `REAL` | `avmp/ha.py` |
| D9 | Compliance pack (NIST/STIG/FedRAMP mapping) + hardening guide | `REAL` (doc) | `docs/compliance-pack.md`, `docs/deployment-airgap.md` |

FIPS crypto (D1) is the one item that genuinely cannot be `REAL` in a stdlib-only
build — it requires a FIPS-validated module. The asymmetric signing (D2) proves
the *scheme*; the FIPS provider is a drop-in.

---

## Acceptance Criteria

| # | Criterion | Status | Verified by |
|---|-----------|:------:|-------------|
| P4-AC-1 | Asymmetric signature, public-key-only verify, tamper + wrong-key rejected | ✅ REAL | `test_crypto_supplychain.*`; `avmp phase4` §A |
| P4-AC-2 | TLS 1.2+/mTLS; invalid cert refused | 🟡 SWAP | needs cert material / lab (design in `avmp/api.py`) |
| P4-AC-3 | State store encrypted at rest | 🟡 SWAP | needs KMS/OS-level encryption |
| P4-AC-4 | Audit append-only; signed checkpoints detect edit + truncation | ✅ REAL | `test_worm.*`; `avmp phase4` §B |
| P4-AC-5 | Privileged action requires authenticated identity + MFA | ✅ REAL | `test_authn.*`; `avmp phase4` §C |
| P4-AC-6 | Bundles carry verifiable SBOM; reproducible build digest | ✅ REAL | `test_crypto_supplychain.test_reproducible_digest`, `..._public_key_only_verify` |
| P4-AC-7 | Auto-created RFC; auto-apply blocked until approved; RFC id in audit | ✅ REAL | `test_itsm_remediation.*`; `avmp phase4` §D |
| P4-AC-8 | Azure NSG adapter applies + rolls back (dry-run first) behind all gates | ✅ REAL (sim) / 🟡 SWAP (live tenant) | `test_azure_backend.*`; `avmp phase4` §D |
| P4-AC-9 | CIS/STIG hardened image; no outbound telemetry by default | 🟡 REAL (no-telemetry) / SWAP (image) | `avmp phase4` §E; `docs/compliance-pack.md` |
| P4-AC-10 | Console failover, zero audit loss; scanner reroute | ✅ REAL | `test_ha.*`; `avmp phase4` §F |
| P4-AC-11 | Full suite green; DELTA + hardening + compliance pack delivered | ✅ REAL | `run_tests.py` → 89 passing; this file; `docs/compliance-pack.md` |

**7 of 11 fully REAL and tested in-repo; 4 need a target environment (TLS certs,
KMS, an Azure tenant, a CIS/STIG image) to move from SWAP to REAL.**

---

## What moves SWAP → REAL in a paid engagement
- **TLS/mTLS + at-rest**: issue certs from the agency PKI, wrap the API socket
  (stdlib `ssl`), enable OS/volume encryption. ~days.
- **FIPS**: build against the FIPS-validated OpenSSL provider; swap `avmp/crypto.py`.
- **Azure NSG live**: pass an authenticated Azure SDK client to `AzureNsgBackend`
  (the method bodies already model the exact `az network nsg rule` calls).
- **Entra SSO / ServiceNow**: implement the `IdentityProvider` / `ITSMConnector`
  interfaces against the real endpoints.
