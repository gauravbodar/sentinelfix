# Azure NSG — Live Tenant Switch (Phase 4 D5)

The `AzureNsgBackend` runs against a simulated NSG by default and against a **real
tenant** when given credentials. Flipping it is configuration only — no code
change — so it can be done on demo day or in pilot week 1.

## What's already done
- `AzureSdkNsgClient` (`avmp/azure_client.py`) implements create/delete/list NSG
  security rules via `azure-mgmt-network` (imported lazily).
- `AzureNsgBackend` routes apply/validate/rollback through the client when a
  scope is mapped for the asset; otherwise it stays simulated (fail-safe — it
  never guesses a live target).
- `build_from_env()` returns a live client only when the SDK **and** credentials
  are present; otherwise `None`. The `phase4` demo calls it automatically.
- Live routing is covered by tests using a fake client (`test_azure_backend.py`),
  so the switch is verified without the SDK installed.

## Go-live checklist (≈ 30 min on a lab subscription)

1. **Install the SDK** on the (connected) console host:
   ```
   pip install azure-identity azure-mgmt-network
   ```
2. **Grant least-privilege RBAC** to the identity SentinelFix runs as —
   **Network Contributor** scoped to the target resource group (enough to manage
   NSG security rules; nothing broader).
3. **Set environment** (DefaultAzureCredential picks these up — service
   principal shown; managed identity also works):
   ```
   set AZURE_SUBSCRIPTION_ID=<sub-guid>
   set AZURE_TENANT_ID=<tenant-guid>
   set AZURE_CLIENT_ID=<sp-app-id>
   set AZURE_CLIENT_SECRET=<sp-secret>
   set AZURE_RESOURCE_GROUP=rg-sentinelfix
   set AZURE_NSG_NAME=nsg-web-dmz-01
   ```
4. **Run the demo** — `python -m avmp phase4`. Section D now prints
   `LIVE Azure client detected` and the preview is tagged `[LIVE]`; the deny rule
   is created on the real NSG, validated by reading it back, and removed on
   rollback.

## Safety on a live tenant
- **Preview first.** `backend.preview(action)` shows the exact `az network nsg
  rule create` before anything is applied; the engine still requires policy
  approval + an approved ServiceNow RFC before `apply`.
- **Rollback is exact.** If the deny rule didn't pre-exist, rollback deletes it;
  if it did, rollback leaves it untouched.
- **Scoped blast radius.** Only assets with a mapped `NsgScope` are ever touched
  live; everything else remains simulated.
- Recommend a **dedicated lab RG** for the first live run, and a canary NSG that
  fronts a non-production host.

## Production mapping
For a fleet, replace the single-asset `scopes` dict with a resolver that maps
each asset_id to its `NsgScope` from your CMDB / Azure Resource Graph. The
backend interface is unchanged.
