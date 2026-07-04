# SentinelFix — Compliance Mapping Pack (Phase 4 D9)

Maps product capabilities to control frameworks with the in-repo evidence
artifact for each. **This is a control *mapping*, not a certification.** It shows
how SentinelFix supports each control; formal ATO / FedRAMP authorization is a
procurement activity performed with the agency's assessor.

Evidence commands:
- `python -m avmp phase4` — exercises signing, WORM, MFA, change-control, HA.
- `python run_tests.py` — 89 automated tests.

## NIST SP 800-53 Rev. 5

| Control | Title | How SentinelFix supports it | Evidence |
|---------|-------|------------------------------|----------|
| AU-9 | Protection of Audit Information | HMAC hash-chained, append-only audit; asymmetric **signed checkpoints** detect edit + truncation | `avmp/worm.py`, `test_worm.py` |
| AU-10 | Non-repudiation | Signed remediation receipts; RFC id + approver recorded per action | `avmp/remediation.py`, `test_itsm_remediation.py` |
| CM-3 | Configuration Change Control | Auto-created RFC; auto-apply blocked until approved; maintenance windows | `avmp/itsm.py`, `avmp/remediation.py` |
| CM-5 | Access Restrictions for Change | RBAC + separation of duties (author ≠ publisher; scanner ≠ approver) | `avmp/rbac.py`, `test_ui.py` |
| IA-2 / IA-2(1) | Identification & Auth (MFA) | SSO identity + **TOTP MFA** required for privileged actions | `avmp/authn.py`, `test_authn.py` |
| RA-5 | Vulnerability Monitoring & Scanning | Credentialed/network scanning, CVE/EPSS/KEV enrichment, risk scoring | `avmp/scanner.py`, `avmp/scoring.py` |
| SI-2 | Flaw Remediation | Governed remediation: canary, post-fix validation, rollback | `avmp/remediation.py`, `avmp/backends.py` |
| SI-7 | Software/Firmware/Info Integrity | **Asymmetric-signed** plugin/VDB bundles + SBOM + reproducible builds | `avmp/supplychain.py`, `test_crypto_supplychain.py` |
| SC-8 | Transmission Confidentiality | TLS 1.2+/mTLS between components (deployment) | `docs/deployment-airgap.md` (SWAP) |
| SC-12/13 | Crypto Key Mgmt / Cryptographic Protection | Asymmetric signing keys; FIPS-validated module in production | `avmp/crypto.py` (FIPS = SWAP) |
| CP-9/10 | System Backup / Recovery | Active/passive HA, standby with zero audit loss | `avmp/ha.py`, `test_ha.py` |

## DISA STIG (representative)

| STIG requirement | Support |
|------------------|---------|
| Audit records protected from unauthorized modification/deletion | Append-only WORM + signed checkpoints |
| MFA for privileged/administrative access | TOTP MFA gate on privileged permissions |
| Application uses DoD-approved PKI / signed code | Asymmetric bundle signatures + SBOM (FIPS PKI = production swap) |
| Least privilege / separation of duties | RBAC roles + enforced SoD |
| No unnecessary outbound communication | Air-gapped default: outbound telemetry disabled |

## FedRAMP (control families touched)

Access Control (AC), Audit & Accountability (AU), Configuration Management (CM),
Identification & Authentication (IA), Risk Assessment (RA), System & Comms
Protection (SC), System & Information Integrity (SI). SentinelFix provides
supporting capability and evidence for each; the SSP/assessment is performed with
the agency 3PAO.

## Australian context (ACS / ASD Essential Eight, ISM)

| Essential Eight / ISM theme | Support |
|-----------------------------|---------|
| Patch applications / patch OS | Detection + prioritized, governed remediation with rollback |
| Restrict admin privileges | RBAC + SoD + MFA on privileged actions |
| Multi-factor authentication | TOTP MFA (Entra/SAML integration = swap) |
| Regular backups / resilience | HA failover with zero audit loss |
| Application control / integrity | Signed bundles + SBOM + reproducible builds |

## Honest boundary statement (put this in front of any assessor)

> SentinelFix **implements the controls' technical mechanisms** and produces the
> supporting evidence. It is **not yet** running on a FIPS-validated crypto
> module, a hardened/accredited image, or with production SSO/ITSM/cloud
> connectors wired to live services. Those are the deliverables of the hardening
> engagement and are required before an authorization decision.
