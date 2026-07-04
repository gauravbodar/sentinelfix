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
# phase2 — prioritization & playbooks pipeline                                #
# --------------------------------------------------------------------------- #
_DEMO_KEY = b"demo-worm-and-supply-chain-key!!"  # 32 bytes; HSM/FIPS in prod


def cmd_phase2(args: argparse.Namespace) -> int:
    from .ingest import build_entries, build_signed_bundle, ingest_offline
    from .models import Asset, AssetCriticality
    from .reporting import executive_summary, playbook
    from .workflow import FindingState

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    srv, port, stop = _open_listener()
    try:
        console = Console()

        _hr("D1. Ingest signed KEV/EPSS bundle into VDB (air-gapped)")
        kev = {"CVE-2019-0708": {"in_kev": True, "title": "BlueKeep RDP RCE"}}
        epss = {"CVE-2019-0708": {"epss": 0.94, "percentile": 0.995}}
        cvss = {"CVE-2019-0708": 9.8}
        entries = build_entries(kev, epss, cvss, last_updated="2024-01-01")
        bundle = out / "kev_epss.vdbundle"
        build_signed_bundle(str(bundle), entries, _DEMO_KEY, "kev-epss-2024", "2024-01-01T00:00:00Z")
        n = ingest_offline(str(bundle), _DEMO_KEY, console.store)
        print(f"  ingested {n} VDB entr(y/ies); count={console.store.vdb_count()} "
              f"updated={console.store.vdb_latest_update()}")

        _hr("D2. Scan + configurable, explainable risk score")
        rdp = PortExposurePlugin("demo.exposed_rdp", "RDP", port=port,
                                 severity="high", cve=["CVE-2019-0708"])
        web = Asset("web-dmz-01", hostname="web-dmz-01", ip_addresses=["127.0.0.1"],
                    owner="soc@agency.gov", criticality=AssetCriticality.MEDIUM,
                    internet_facing=True)
        console.register_asset(web)
        findings = console.scan_asset(web, plugins=[rdp], open_tickets=True)
        f = findings[0]
        breakdown = console.score(f, web)
        print(f"  finding: {f.title}  score={breakdown.score} (model {breakdown.model_version})")
        for fac in breakdown.factors:
            print(f"    factor {fac.name:12} raw={fac.raw:<7} contribution={fac.contribution}")

        _hr("D3. Linked remediation playbook")
        pb_id = console.linked_playbook(f)
        print(f"  linked playbook: {pb_id}  (published library: "
              f"{len(console.playbooks.published())} playbooks)")

        _hr("D4. Manual remediation workflow (state machine + SLA + WORM audit)")
        wf = console.workflow
        t = wf.get(f.finding_id)
        print(f"  opened ticket state={t.state.value} sla_due={t.sla_due}")
        wf.transition(f.finding_id, FindingState.TRIAGED, "alice.operator")
        wf.assign(f.finding_id, "eng.team", "team.lead")
        wf.transition(f.finding_id, FindingState.IN_PROGRESS, "eng.team")
        wf.transition(f.finding_id, FindingState.REMEDIATED, "eng.team")
        # Verification requires a passing re-scan (simulated True here).
        wf.transition(f.finding_id, FindingState.VERIFIED, "qa", verify_fn=lambda: True)
        final = wf.transition(f.finding_id, FindingState.CLOSED, "qa")
        print(f"  lifecycle -> {final.state.value}; transitions={len(final.history)}")

        _hr("D5. Executive summary with trend + MTTR")
        console.record_risk_snapshot()
        console.record_risk_snapshot()
        (out / "executive_summary.md").write_text(
            executive_summary(console.list_findings(), console.list_assets(), console.store),
            encoding="utf-8")
        (out / f"playbook_{pb_id}.md").write_text(
            playbook(f, web, "staged_patch", console.playbooks.match(f).rollback_steps
                     if console.playbooks.match(f) else []), encoding="utf-8")
        print(f"  wrote executive_summary.md to {out.resolve()}")
        print(f"  WORM audit chain verified: {console.audit_ok()}  "
              f"records={sum(1 for _ in console.store.iter_audit())}")

        _hr("PHASE 2 DEMO COMPLETE")
        print("  [OK] KEV/EPSS ingest   [OK] explainable scoring   [OK] playbook linkage")
        print("  [OK] manual workflow   [OK] exec summary + trend + MTTR")
        return 0
    finally:
        stop.set()
        srv.close()


# --------------------------------------------------------------------------- #
# ingest — load real KEV/EPSS feed files                                      #
# --------------------------------------------------------------------------- #
def cmd_ingest(args: argparse.Namespace) -> int:
    from .ingest import ingest_feeds
    from .store import Store

    store = Store(args.db)
    key = bytes.fromhex(args.key) if args.key else _DEMO_KEY
    n = ingest_feeds(args.kev, args.epss, store, key, cvss_path=args.cvss,
                     bundle_out=args.bundle_out, last_updated=args.date)
    print(f"Ingested {n} VDB entries into {args.db} (total {store.vdb_count()}).")
    return 0


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

    p2 = sub.add_parser("phase2", help="run the Phase 2 prioritization & playbooks pipeline")
    p2.add_argument("--out", default="out", help="output directory for reports")
    p2.set_defaults(func=cmd_phase2)

    ing = sub.add_parser("ingest", help="ingest KEV/EPSS feed files into the VDB")
    ing.add_argument("--kev", required=True, help="path to CISA KEV JSON")
    ing.add_argument("--epss", required=True, help="path to FIRST.org EPSS CSV(.gz)")
    ing.add_argument("--cvss", default=None, help="optional CVSS CSV (cve,cvss)")
    ing.add_argument("--db", default="avmp.db", help="SQLite DB path")
    ing.add_argument("--key", default=None, help="bundle signing key (hex); demo key if omitted")
    ing.add_argument("--bundle-out", dest="bundle_out", default=None, help="signed bundle output path")
    ing.add_argument("--date", default="", help="feed date (ISO) for provenance")
    ing.set_defaults(func=cmd_ingest)

    s = sub.add_parser("serve", help="start the read-only Console API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)
