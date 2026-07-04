# Air-Gapped Deployment & Feed Update Guide (Phase 2)

How to load KEV/EPSS vulnerability data into a sealed SentinelFix appliance with
no outbound network access (PRD §7 Air-gapped operation).

## Prerequisites

- Python 3.11+ (standard library only — no pip installs).
- A **bundle signing key** shared between the trusted build host and the
  appliance. In production this lives in an HSM / FIPS keystore; for evaluation a
  32-byte key is used (`avmp` demo key when `--key` is omitted).

## 1. On a connected/trusted build host — obtain the feeds

- CISA KEV catalog: `known_exploited_vulnerabilities.json`
- FIRST.org EPSS: `epss_scores-YYYY-MM-DD.csv.gz`
- (optional) a CVSS extract CSV with columns `cve,cvss`

## 2. Build + sign the offline bundle

```bash
python -m avmp ingest \
  --kev  known_exploited_vulnerabilities.json \
  --epss epss_scores-2024-01-01.csv.gz \
  --cvss nvd_cvss.csv \
  --db   avmp.db \
  --key  <64-hex-char key> \
  --bundle-out feeds-2024-01-01.vdbundle \
  --date 2024-01-01
```

This parses the feeds, writes a **signed** `.vdbundle` (SHA-256 + HMAC), verifies
it, and loads it into `avmp.db`. Copy the `.vdbundle` to removable media.

## 3. On the air-gapped appliance — import

Transfer the `.vdbundle`, then ingest it. Import **fails closed** if the hash or
signature does not match the key — a corrupted or untrusted bundle is rejected:

```python
from avmp.store import Store
from avmp.ingest import ingest_offline
store = Store("avmp.db")
count = ingest_offline("feeds-2024-01-01.vdbundle", KEY_BYTES, store)
print(count, "entries;", store.vdb_count(), "total;", store.vdb_latest_update())
```

No network calls occur. `sync_online()` is intentionally disabled on air-gapped
builds.

## 4. Verify

```bash
python -m avmp phase2      # exercises ingest → score → playbook → workflow → report
python -m unittest discover -s tests -t .
```

Check `store.vdb_latest_update()` for staleness; schedule bundle refreshes per
site policy (KEV changes frequently; EPSS refreshes daily).

## Notes

- The WORM audit log and the VDB share the SQLite DB; back up `avmp.db` and its
  `*.audit.key` together, and store the audit key with the same protections as
  the signing key.
- Remediation remains **simulated** in this build (PRD §6); Phase 2 adds the
  human-operated workflow, not automated apply.
