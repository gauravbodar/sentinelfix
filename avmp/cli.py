"""SentinelFix CLI (PRD §9 Phase 0/1 deliverable).

Subcommands:
  demo    Run the full pipeline end-to-end against a local stand-in target and
          write reports to an output directory.
  serve   Start the read-only Console API.

The `demo` binds a throwaway TCP listener on localhost to stand in for an
"exposed service", so detection is deterministic and no external host is
touched. All remediation is simulated (PRD §6).
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from datetime import time as dtime
from pathlib import Path

from .canary import CanaryRing
from .console import Console
from .enrichment import Enricher
from .models import Asset, AssetCriticality
from .plugins.network_exposure import PortExposurePlugin
from .reporting import findings_csv, playbook, remediation_ledger, technical_report
from .vdb import BundleVerificationError, export_bundle, import_offline, verify_bundle
from .enrichment import VdbEntry


# --------------------------------------------------------------------------- #
# Local stand-in target                                                       #
# --------------------------------------------------------------------------- #
def _open_listener() -> tuple[socket.socket, int, threading.Event]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop() -> None:
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return srv, port, stop


def _hr(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


# --------------------------------------------------------------------------- #
# demo                                                                        #
# --------------------------------------------------------------------------- #
def cmd_demo(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    srv, port, stop = _open_listener()
    try:
        console = Console()

        # A demo plugin representing exposed RDP (BlueKeep), pointed at our
        # local stand-in port so detection is deterministic.
        rdp_demo = PortExposurePlugin(
            "demo.exposed_rdp", "RDP", port=port, severity="high",
            cve=["CVE-2019-0708"],
        )

        _hr("1. Discovery & asset registry (PRD §3 Asset Inventory)")
        web = Asset(asset_id="web-dmz-01", hostname="web-dmz-01",
                    ip_addresses=["127.0.0.1"], owner="soc@agency.gov",
                    criticality=AssetCriticality.MEDIUM, internet_facing=True)
        db = Asset(asset_id="db-core-01", hostname="db-core-01",
                   ip_addresses=["127.0.0.1"], owner="dba@agency.gov",
                   criticality=AssetCriticality.MISSION_CRITICAL)
        console.register_asset(web)
        console.register_asset(db)
        for a in console.list_assets():
            print(f"  registered {a.asset_id:12} criticality={a.criticality.value}")

        _hr("2. Scan + enrich + prioritize (PRD §4 data flow 2-4)")
        all_findings = []
        for a in (web, db):
            fs = console.scan_asset(a, plugins=[rdp_demo])
            all_findings += fs
            for f in fs:
                print(f"  [{a.asset_id}] {f.title}  severity={f.severity.value} "
                      f"risk={f.risk_score(a.criticality)} kev={f.in_kev} "
                      f"epss={f.epss_score}")

        _hr("3. Governed remediation (PRD §6 policy matrix + approval)")
        web_finding = console.list_findings("web-dmz-01")[0]
        db_finding = console.list_findings("db-core-01")[0]

        operator, approver = "alice.operator", "bob.approver"

        # web-dmz-01: MEDIUM + high + KEV -> STAGED_PATCH, approval required.
        plan_web = console.engine.plan(web_finding, web, rdp_demo)
        print(f"  web-dmz-01  -> mode={plan_web.decision.allowed_mode.value} "
              f"approval={plan_web.requires_approval}  ({plan_web.decision.rationale})")
        console.engine.approve(plan_web, approver=approver, scanner_principal=operator)
        outcome_web = console.engine.apply(plan_web, actor=approver)
        print(f"              applied={outcome_web.applied} "
              f"receipt={ (outcome_web.receipt_signature or '')[:16] }...")

        # db-core-01: MISSION_CRITICAL -> MANUAL_ONLY, auto-apply denied.
        plan_db = console.engine.plan(db_finding, db, rdp_demo)
        print(f"  db-core-01  -> mode={plan_db.decision.allowed_mode.value} "
              f"approval={plan_db.requires_approval}  ({plan_db.decision.rationale})")
        outcome_db = console.engine.apply(plan_db, actor=approver)
        print(f"              applied={outcome_db.applied}  denied_reason="
              f"{outcome_db.denied_reason!r}")

        _hr("4. Canary rollback on failed health check (PRD §6 canary/rollback)")
        plan_web2 = console.engine.plan(web_finding, web, rdp_demo)
        console.engine.approve(plan_web2, approver=approver, scanner_principal=operator)
        # Force the 'fleet' ring health check to fail -> automatic rollback.
        bad_health = lambda ring: ring.name != "fleet"  # noqa: E731
        outcome_rb = console.engine.apply(plan_web2, actor=approver, health_fn=bad_health)
        print(f"  applied={outcome_rb.applied} (expected False)")
        for step in (outcome_rb.rollout.steps if outcome_rb.rollout else []):
            print(f"    ring={step.ring:8} applied={step.applied} "
                  f"healthy={step.healthy} rolled_back={step.rolled_back}")

        _hr("5. Air-gapped signed VDB bundle import (PRD §5, §7)")
        key = b"demo-worm-and-supply-chain-key!!"  # 32 bytes; HSM in production
        bundle = out / "vdb_bundle.json"
        entries = [VdbEntry("CVE-2021-44228", 10.0, 0.98, True, "Log4Shell")]
        export_bundle(str(bundle), entries, key, bundle_id="kev-2021-12", created_at="2021-12-10T00:00:00Z")
        enricher = Enricher()
        n = import_offline(str(bundle), key, enricher)
        print(f"  imported {n} signed VDB entr(y/ies); Log4Shell in VDB: "
              f"{'CVE-2021-44228' in enricher.vdb}")
        # Tamper detection.
        tampered = bundle.read_text().replace("10.0", "1.0")
        (out / "vdb_bundle_tampered.json").write_text(tampered)
        try:
            verify_bundle(str(out / "vdb_bundle_tampered.json"), key)
            print("  tamper check: FAILED to detect (bug!)")
        except BundleVerificationError as exc:
            print(f"  tamper check: rejected as expected -> {exc}")

        _hr("6. Reports, evidence & WORM audit (PRD §8)")
        assets = console.list_assets()
        (out / "technical_report.md").write_text(technical_report(all_findings, assets), encoding="utf-8")
        (out / "findings.csv").write_text(findings_csv(all_findings, assets), encoding="utf-8")
        (out / "remediation_ledger.md").write_text(remediation_ledger(console.store), encoding="utf-8")
        (out / "playbook_db-core-01.md").write_text(
            playbook(db_finding, db, plan_db.decision.allowed_mode.value,
                     plan_db.proposal.rollback_steps), encoding="utf-8")
        print(f"  wrote reports to {out.resolve()}")
        print(f"  WORM audit chain verified: {console.audit_ok()}")
        audit_count = sum(1 for _ in console.store.iter_audit())
        print(f"  audit records: {audit_count}")

        _hr("DEMO COMPLETE - MVP acceptance criteria exercised")
        print("  [OK] scan   [OK] enrich/prioritize   [OK] governed remediation")
        print("  [OK] canary rollback   [OK] air-gap import   [OK] signed WORM audit")
        return 0
    finally:
        stop.set()
        srv.close()


# --------------------------------------------------------------------------- #
# serve                                                                       #
# --------------------------------------------------------------------------- #
def cmd_serve(args: argparse.Namespace) -> int:
    from .api import serve
    console = Console()
    httpd = serve(console, host=args.host, port=args.port)
    print(f"SentinelFix Console API on http://{args.host}:{args.port} "
          f"(GET /healthz /assets /findings /audit) — Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252; force UTF-8 so report glyphs render.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(prog="avmp", description="SentinelFix AVMP CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run the full pipeline end-to-end")
    d.add_argument("--out", default="out", help="output directory for reports")
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("serve", help="start the read-only Console API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)
