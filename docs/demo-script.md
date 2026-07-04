# SentinelFix — ACS Demo Script & Pilot Conversion (one deliverable)

Source of truth for **talking about it → demoing it → converting to a $20k/week
pilot**. Everything here is backed by runnable commands. Read the *Honest
positioning* section before you present — it keeps the pilot alive.

---

## 0. The one-liner

> "SentinelFix is a government-grade autonomous vulnerability management platform:
> it detects, prioritizes, and **safely remediates** vulnerabilities under full
> change-control and a tamper-evident audit trail — and it runs **air-gapped**.
> It's Tenable-class detection with the safe-remediation and compliance layer
> Tenable doesn't ship."

## 1. Why we win (say these, each is demoable)

| Claim | Proof in the demo | Command |
|-------|-------------------|---------|
| Safer than Tenable | canary + post-fix validation + **automatic rollback**, blast-radius via policy matrix | `avmp phase3`, `avmp phase4` §D |
| More compliant | **WORM audit + signed checkpoints + SBOM + reproducible builds** | `avmp phase4` §A/§B |
| More deployable | **air-gapped**, offline signed bundle import, no telemetry | `avmp phase4` §E |
| More trustworthy | **asymmetric signing**, public-key-only verify, tamper fail-closed | `avmp phase4` §A |
| Change-controlled | auto-created RFC, **auto-apply blocked until approved** | `avmp phase4` §D |
| Resilient | **HA failover, zero audit loss** | `avmp phase4` §F |

## 2. 15-minute script (mapped to commands)

Pre-stage a terminal in `sentinelfix/`. Run each block live.

1. **Open (1 min)** — the one-liner. "Everything you see runs on a hardened,
   air-gapped appliance with zero external dependencies."
2. **Security hardening (3 min)** — `python -m avmp phase4`
   Narrate §A signing + SBOM + tamper-reject, §B WORM checkpoint + truncation
   detection, §C SSO + MFA blocking a privileged action until TOTP passes.
3. **Detection + prioritization (2 min)** — `python -m avmp phase2`
   Real scan → CVE/EPSS/KEV enrichment → explainable risk score → prioritized queue.
4. **Remediation + change control (4 min)** — (already on screen from §D of phase4)
   Azure NSG **dry-run** → RFC auto-created → **apply blocked** → approve RFC →
   apply + **post-fix validation** → **rollback safety** → RFC id in the audit.
5. **Air-gap + appliance (2 min)** — `avmp phase4` §E + show `docs/compliance-pack.md`
   Offline signed import, no telemetry, NIST/STIG/Essential-Eight mapping.
6. **High availability (1 min)** — `avmp phase4` §F: kill primary → failover,
   zero audit loss, scanner reroute.
7. **Close + offer (1 min)** — the pilot ask below.

Backups if a live run stalls: `out/executive_summary.md`, `out/signed_feed.bundle`,
`DELTA.md`, `docs/compliance-pack.md`.

## 3. Conversion matrix (objection → evidence → next step)

| ACS objection | Evidence to show | Convert to |
|---------------|------------------|-----------|
| "Is it just another scanner?" | phase3/phase4 remediation + rollback | Pilot on a real subnet |
| "Auto-remediation is too risky for us" | policy matrix denies mission-critical; canary + rollback; RFC gate | Pilot scoped to *safe-auto* only |
| "We're air-gapped / classified" | phase4 §E, no telemetry, offline bundles | On-prem appliance pilot |
| "Compliance/audit is everything" | WORM + signed checkpoints + compliance pack | Compliance-pack workshop (billable) |
| "Can it touch our Azure?" | Azure NSG adapter dry-run; live tenant = credential swap | Lab-tenant integration (pilot week 1) |
| "Prove it's real" | `run_tests.py` → 89 tests; `DELTA.md` AC map | Technical deep-dive |

## 4. The offer (one ask)

> "I can start remediation work **tomorrow at $500/hr**, or run a **1-week pilot
> for $20,000**. You get: a scoped scan of a target segment, prioritized
> findings with evidence, **safe auto-remediation on ≥3 action types with
> rollback**, a **compliance-mapping pack** (NIST 800-53 / STIG / Essential
> Eight), a **hardening guide**, and a **signed remediation ledger** — delivered
> on your air-gapped appliance."

Pilot deliverables (all already produced by the build):
- Prioritized findings + `out/executive_summary.md`
- Safe auto-remediation demo with rollback (`avmp phase3` / `phase4`)
- `docs/compliance-pack.md`, `docs/deployment-airgap.md`, `DELTA.md`
- Signed remediation ledger (WORM audit export)

---

## 5. Honest positioning — READ BEFORE YOU PRESENT

This protects the deal. A government buyer's technical team **will** ask, and
overclaiming ends the relationship. Say it this way:

| ✅ Say (true) | ❌ Don't say (false) |
|--------------|---------------------|
| "Asymmetric code signing is implemented; the **FIPS-validated module** is the production drop-in." | "It's FIPS 140-3 certified." |
| "MFA is real TOTP; **Entra/SAML SSO** is the integration point." | "It's already integrated with your Entra." |
| "The Azure NSG adapter is built and reversible; it runs **dry-run** until we connect your tenant." | "It's live in your Azure now." |
| "WORM audit, RBAC, SoD, change-control are working today." | "It's ATO'd / FedRAMP authorized." |
| "It maps to NIST/STIG/Essential Eight; **authorization** is the engagement." | "It's accredited." |

Framing that sells honestly: **"Tenable-class detection is table stakes. What we
add — safe governed remediation, WORM/SBOM compliance, and air-gapped
deployment — is real and running today. The pilot connects it to your live
Azure/Entra/ServiceNow and produces your accreditation evidence."**

The pilot is legitimately worth $20k: it's real engineering hooking real
infrastructure to a working platform, and it produces artifacts (compliance pack,
remediation ledger, hardening guide) the agency keeps.
