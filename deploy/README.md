# Deployment

Scaffold placeholders for the deployment story (PRD §4, §7).

- [`docker-compose.yml`](docker-compose.yml) — intended local service graph
  (console, scanner-node, remediation-engine, vdb-updater, state-store). Does
  not build or run anything yet.

## Planned deployment modes (PRD §7)

- **Appliance mode** — single hardened VM/physical appliance; web UI reachable
  only from the internal network.
- **Air-gapped** — offline signed-bundle import for VDB/plugin updates; no
  outbound telemetry by default.
- **Government cloud tenancy** — hardened images (CIS/STIG), FIPS-validated
  crypto, SAML/AD/Entra auth with MFA for privileged roles.
- **High availability** — active/passive Console clustering; scanner node
  failover.

None of the above is implemented in this scaffold.
