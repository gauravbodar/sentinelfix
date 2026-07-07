# SentinelFix — Autonomous Vulnerability Management Platform (AVMP)

**Target:** Clone core Nessus/Tenable vulnerability management capabilities (scanning, reporting, prioritized findings) and extend with a governed, auditable vulnerability-fixer suitable for government environments (air-gapped, compliance-first, change-controlled).

---

## 1. Overview and Vision

**Product name (placeholder):** SentinelFix

**One-line vision:** Detect every exploitable weakness across cloud, endpoint, network, and legacy systems; prioritize by real-world exploit risk; and remediate safely under auditable government controls so agencies fix vulnerabilities before adversaries exploit them.

**Primary users:** Government security operations centers (SOC), IT operations, system owners, compliance officers, incident response teams.

**Primary goals:**

- **Detect:** Continuous, credentialed and non-credentialed scanning across environments.
- **Prioritize:** Risk scoring that combines CVSS, EPSS/KEV signals, asset criticality, and exposure.
- **Remediate:** Provide safe manual playbooks and governed auto-remediation for low-risk fixes with canary/rollback.
- **Comply:** Produce auditable evidence for NIST/CISA/STIG/FedRAMP/NZ/ASD frameworks.
- **Deploy:** Support air-gapped and connected government networks; run as on-prem appliance or hardened cloud offering.

---

## 2. Product Pillars (Design Principles)

- **Detection fidelity** — broad plugin coverage, credentialed checks, agent + agentless hybrid, passive discovery.
- **Risk realism** — prioritize fixes by exploitability and mission impact, not raw CVSS alone.
- **Safe remediation** — automated fixes only when safe; every action is reversible and auditable.
- **Government readiness** — support air-gapped installs, FIPS/TLS, role separation, change control integration.
- **Explainability** — every finding includes root cause, exact affected artifacts, and step-by-step remediation instructions.
- **Minimal blast radius** — remediation workflows respect maintenance windows, canary rings, and approval gates.

---

## 3. Core Capabilities (MVP → Enterprise)

### MVP (deliverable in 8–12 weeks)

- **Scanner Engine:** Network scanner + credentialed host checks (SSH/WinRM), plugin engine (scriptable checks), scheduled scans, ad-hoc scans.
- **Asset Inventory:** Auto discovery (network, cloud accounts, AD/LDAP), canonical asset registry with ownership and criticality tags.
- **Vulnerability Database (VDB):** Local VDB with CVE mapping, KEV/EPSS ingestion, and daily updates.
- **Findings & Reports:** Per-asset findings, CVSS, exploit likelihood, evidence (stdout, packet capture, registry keys). PDF/CSV export and compliance templates (NIST 800-53, STIG).
- **Remediation Guidance:** Per-finding remediation steps (manual), rollback instructions, risk notes.
- **Governed Auto-Remediation (basic):** Safe actions (close port, disable service, rotate secret) behind policy flags; require approval for critical systems.
- **Audit Trail:** Immutable logs for scans, findings, remediation actions, approvals.

### Enterprise (upsell)

- **Agents:** Lightweight endpoint agents for continuous posture and live remediation.
- **Passive Network Sensors:** For discovery and exploit detection.
- **Advanced Prioritization:** Asset context, business impact, threat intel feeds, ML exploit prediction.
- **Patch Orchestration:** Integrations with WSUS, SCCM, vendor patch APIs, and cloud patch services.
- **Change Control Integration:** ITSM (ServiceNow/Jira) connectors, automated RFC creation and status sync.
- **Air-gapped Deployment Kit:** Offline VDB updates, signed update bundles, appliance image.
- **Canary & Rollback Framework:** Staged rollout engine with health checks and automated rollback.
- **Forensics Mode:** Snapshot evidence packaging for incident response.

---

## 4. System Architecture (High level)

### Components

- **Console (Hardened Web UI / API)** — central orchestration, reporting, policy engine, RBAC, audit logs. Deployable as on-prem VM/appliance or in a government cloud tenancy.
- **Scanner Nodes** — distributed scanner appliances (containerized) for network segments; run credentialed and non-credentialed scans; communicate over TLS to Console.
- **Agents** — optional lightweight host agents for continuous checks and remediation hooks.
- **Passive Sensors** — optional taps for discovery and exploit telemetry.
- **VDB Updater** — signed update bundles; supports online sync and offline import for air-gapped sites.
- **Remediation Engine** — policy engine that maps findings → remediation playbooks; supports manual, semi-automated (approval), and automated modes.
- **State Store** — encrypted PostgreSQL/CosmosDB for assets, findings, policies; write-once audit store (WORM) for logs.
- **Integrations** — ITSM, SIEM, CMDB, patch systems, identity providers (SAML/AD/Entra), ticketing.

### Data flow (summary)

1. **Discovery** → assets registered.
2. **Scan** → scanner nodes run plugins; findings pushed to Console.
3. **Enrichment** → Console enriches with VDB, EPSS/KEV, asset criticality.
4. **Prioritization** → risk score computed; remediation policy evaluated.
5. **Action** → create ticket / send playbook / execute auto-fix (if policy allows).
6. **Verify** → post-action validation scan; health checks; rollback if failure.
7. **Audit** → immutable evidence stored and exported.

---

## 5. Plugin Engine & VDB

### Plugin model

- **Format:** sandboxed script format (WASM preferred) with strict resource/time limits.
- **Capabilities:** network probes, credentialed checks, file/registry reads, command execution (credentialed), safe remediation actions (dry-run).
- **Update cadence:** daily signed plugin bundles; emergency hotfix channel for KEV.
- **Testing:** plugin CI with test harness and simulated targets.

### VDB

- Local store of CVEs, vendor advisories, exploit proofs, KEV/EPSS scores, and remediation metadata.
- **Offline update:** signed bundles for air-gapped installs.
- **Mapping:** plugin → CVE mapping; remediation playbook linkage.

---

## 6. Remediation Model (Manual → Auto)

### Remediation taxonomy

- **Informational:** no action required.
- **Advisory:** recommended manual fix.
- **Safe Auto:** low-risk, reversible actions (close unused port, disable noncritical service, rotate non-production secret). Auto-apply allowed when policy and asset criticality permit.
- **Staged Patch:** vendor patch staged to canary hosts, validated, then rolled out.
- **Manual Only:** high-risk fixes (kernel updates, DB schema changes) require human approval and scheduled maintenance window.

### Governance controls

- **Policy matrix:** maps asset criticality × vulnerability severity × exploit likelihood → allowed remediation mode.
- **Approval workflow:** configurable approvers, SLA timers, escalation.
- **Canary & Rollback:** define canary groups, health checks, rollback playbooks.
- **Change windows:** respect maintenance windows; support emergency override with audit.
- **Simulation mode:** dry-run remediation to detect side effects.

### Remediation playbook template (per finding)

1. Finding ID
2. Affected assets
3. Root cause (one sentence)
4. Impact if exploited
5. Recommended fix (step-by-step) — commands, config diffs, registry keys, API calls
6. Pre-fix checks — backups, service dependencies, health probes
7. Post-fix validation — tests to run, expected outputs
8. Rollback steps — exact reversal commands
9. Estimated downtime
10. Risk notes — known side effects, vendor caveats

---

## 7. Government Deployment Requirements

### Security & compliance

- **Hardened images:** CIS benchmarks, STIGs where applicable.
- **Encryption:** FIPS-validated crypto for data at rest and in transit.
- **Authentication:** SAML/AD/Entra integration, MFA for privileged roles.
- **Separation of duties:** scanner operators vs approvers vs auditors.
- **WORM audit store:** tamper-evident logs for forensic evidence.
- **Supply chain:** signed plugin and VDB bundles; reproducible builds.

### Air-gapped operation

- **Offline update process:** signed bundle export/import workflow with integrity checks.
- **Local-only telemetry:** no outbound telemetry by default; opt-in secure telemetry for connected sites.
- **Appliance mode:** single VM/physical appliance with web UI accessible only from internal network.

### Operational controls

- **Change control integration:** automatic RFC creation and status sync with ServiceNow/Jira.
- **Maintenance windows:** policy enforcement to prevent auto-fixes outside windows.
- **High-availability:** active/passive Console clustering; scanner node failover.

---

## 8. Reporting, Evidence & Audit

### Report types

- **Executive summary:** top risks, trend lines, projected savings from remediation.
- **Technical report:** per-asset findings, evidence, remediation steps.
- **Compliance pack:** mapped controls to NIST/CISA/STIG with evidence artifacts.
- **Remediation ledger:** chronological record of actions, approvals, and verification results.

### Evidence artifacts

- Raw scan outputs, command outputs, packet captures (where applicable), pre/post checks, signed remediation receipts.

### Retention & export

- Configurable retention policies; exportable bundles for auditors; WORM mode for critical evidence.

---

## 9. MVP Roadmap & Milestones

**Phase 0 — Foundation (Weeks 0–4)**
Console skeleton, RBAC, asset registry, basic scanner node (network TCP/UDP probes), VDB schema, plugin sandbox prototype.

**Phase 1 — Core Scanning & Reporting (Weeks 5–10)**
Credentialed host checks (SSH/WinRM), plugin engine with 50 initial checks, scheduled scans, basic PDF/CSV reports, evidence capture.

**Phase 2 — Prioritization & Playbooks (Weeks 11–16)**
EPSS/KEV ingestion, risk scoring engine, remediation playbook authoring UI, manual remediation workflow.

**Phase 3 — Safe Auto-Remediation (Weeks 17–24)**
Policy matrix, approval workflows, canary rollout engine, rollback automation, post-fix validation.

**Phase 4 — Government Hardening (Weeks 25–36)**
Air-gapped update bundles, FIPS/TLS hardening, WORM audit store, ServiceNow integration, appliance packaging.

**Phase 5 — Agents & Passive Sensors (Quarter 3)**
Endpoint agents, passive network sensors, continuous posture, advanced forensics.

**Deliverables per phase:** working build, test harness, playbook examples, DELTA.md style verification checklist, deployment guide.

---

## 10. Success Metrics & Business Model

### Technical success metrics

- **Detection coverage:** % of known CVEs detected in benchmark suite.
- **False positive rate:** target < 5% for credentialed checks.
- **Remediation verification success:** % of auto-fixes that pass post-validation.
- **Mean time to remediate (MTTR):** target reduction vs baseline.

### Business model

- **SaaS / On-prem license:** annual subscription per asset or per site.
- **Savings share model:** optional fee as percentage of validated cost avoidance (e.g., ransomware risk reduction, incident avoidance) for large agencies.
- **Professional services:** deployment, hardening, custom playbooks, compliance mapping.

---

## 11. Risks, Mitigations, and Ethical Controls

- **Risk: automated fixes cause outages** — *Mitigation:* strict policy matrix, canary rollouts, pre-checks, rollback playbooks, human approval for high-risk assets.
- **Risk: false positives waste ops time** — *Mitigation:* credentialed checks, evidence capture, confidence scoring, feedback loop to plugin authors.
- **Risk: supply-chain compromise of plugins/VDB** — *Mitigation:* signed bundles, reproducible builds, vendor attestation, offline verification.
- **Risk: misuse for offensive actions** — *Mitigation:* role separation, audit trails, export controls, legal agreements, restricted features for high-risk actions.

---

## 12. Appendix (Templates & Examples)

### A. Minimal plugin DSL (example)

- `metadata`: id, name, cve[], severity, requires_credentials
- `check()`: returns {status, evidence, remediation_hint}
- `remediate()`: optional, returns {action_id, dry_run_output, rollback_steps}
- `constraints`: max_runtime_ms, network_access boolean

### B. Sample remediation playbook (short)

**Finding:** Open RDP on internet-facing host (CVE: N/A)

- **Pre-checks:** confirm owner, snapshot VM, check active sessions
- **Manual fix:** remove public NSG rule; update firewall ACL; notify owner
- **Auto fix (policy allowed):** apply NSG rule to block 3389 from 0.0.0.0/0; validate connectivity from allowed IPs; rollback if critical service fails.

### C. Verification checklist (for each remediation)

- [ ] Pre-fix snapshot exists
- [ ] Backup completed (if required)
- [ ] Health probe passed before fix
- [ ] Post-fix validation tests passed
- [ ] Rollback tested in staging

---

## Final acceptance criteria (MVP)

- **Scan:** Console + at least one scanner node can discover assets and run credentialed checks across a representative government network segment.
- **Report:** Findings include evidence, CVE mapping, EPSS/KEV enrichment, and exportable compliance report.
- **Remediation:** Manual playbooks generated for every finding; at least three safe auto-fix actions implemented and validated in canary mode with rollback.
- **Audit:** Immutable logs of scans and remediation actions with signed receipts.
- **Air-gap:** Offline VDB/plugin update import workflow tested end-to-end.

---

*Delivery note for Fable5: this prd.md is intentionally prescriptive — it contains product vision, pillars, architecture, phased roadmap, governance rules, and templates required to generate code, tests, and deployment artifacts. Use it to produce the initial code scaffold, plugin harness, scanner node prototype, Console UI wireframes, and the remediation engine with policy matrix and canary rollout simulation.*
