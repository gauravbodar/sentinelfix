# Plugin SDK

Defines the SentinelFix plugin contract (PRD §5, §12.A).

- `check()` — read-only probe → `CheckResult { status, evidence, remediation_hint }`.
- `remediate()` — optional, **dry-run by default** → `RemediationResult { action_id, dry_run_output, rollback_steps }`.
- `metadata` — id, name, cve[], severity, requires_credentials.
- `constraints` — `max_runtime_ms`, `network_access`.

**Safety rule:** a plugin never decides to apply a fix. It only *proposes* one.
The remediation engine's policy matrix + approval workflow decide whether a
non-dry-run apply is permitted. See [`plugin_base.py`](plugin_base.py) and the
reference plugin in [`../../plugins/example_open_rdp/`](../../plugins/example_open_rdp/).
