# SentinelFix — Architecture Notes

This document summarizes the runtime topology. The authoritative source is
[`../../sentinelfix-prd.md`](../../sentinelfix-prd.md) §4–§7.

## Components

- **Console** — central orchestration, reporting, policy engine, RBAC, audit
  logs. On-prem VM/appliance or government cloud tenancy.
- **Scanner Nodes** — distributed, containerized; credentialed + non-credentialed
  scans; TLS to Console.
- **Remediation Engine** — maps findings → playbooks; manual / approval /
  automated modes with canary + rollback.
- **VDB Updater** — signed bundles; online sync and offline (air-gap) import.
- **State Store** — encrypted PostgreSQL/CosmosDB for assets/findings/policies;
  WORM store for audit logs.

## Data flow

```
Discovery ─▶ Scan ─▶ Enrichment ─▶ Prioritization ─▶ Action ─▶ Verify ─▶ Audit
 (assets)   (nodes)  (VDB/EPSS/KEV)  (risk score)   (ticket/  (post-fix  (WORM
                                                     auto-fix)  scan)     evidence)
```

## Trust & isolation boundaries (to be enforced during implementation)

- Plugins run **sandboxed** (WASM preferred) with runtime/network/time limits.
- Auto-remediation gated by the **policy matrix**
  (asset criticality × severity × exploit likelihood).
- Audit store is **write-once (WORM)**; remediation actions produce **signed receipts**.
- Air-gapped sites: **no outbound telemetry by default**; updates via signed,
  integrity-checked bundles.

> All boundaries above are described here for design intent only. No enforcement
> logic exists in this scaffold yet.
