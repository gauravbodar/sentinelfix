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
# phase3 — safe auto-remediation with real, reversible backends               #
# --------------------------------------------------------------------------- #
def cmd_phase3(args: argparse.Namespace) -> int:
    from .backends import HostModelBackend, RemediationAction
    from .models import Asset, AssetCriticality
    from .targets import SimulatedHost, TargetRegistry

    srv, port, stop = _open_listener()
    try:
        console = Console()
        registry = TargetRegistry()
        host = registry.register(SimulatedHost(
            asset_id="web-dmz-01", open_ports={port},
            services={"telnetd": True}, secrets={"svc-account": "P@ssw0rd-old"},
        ))
        backend = HostModelBackend(registry)

        rdp = PortExposurePlugin("demo.exposed_rdp", "RDP", port=port,
                                 severity="high", cve=["CVE-2019-0708"])
        web = Asset("web-dmz-01", hostname="web-dmz-01", ip_addresses=["127.0.0.1"],
                    criticality=AssetCriticality.MEDIUM, internet_facing=True)
        console.register_asset(web)

        _hr("1. Scan -> finding -> plan (derives safe auto-fix action)")
        finding = console.scan_asset(web, plugins=[rdp])[0]
        plan = console.engine.plan(finding, web, rdp)
        print(f"  finding: {finding.title}")
        print(f"  policy mode: {plan.decision.allowed_mode.value} "
              f"(approval={plan.requires_approval})")
        print(f"  derived action: {plan.action.action_type} params={plan.action.params}")
        print(f"  host before: port {port} exposed = {host.is_port_exposed(port)}")

        _hr("2. Approve + apply via REAL backend (canary -> validate -> receipt)")
        console.engine.approve(plan, approver="bob.approver", scanner_principal="alice.operator")
        out = console.engine.apply(plan, actor="bob.approver", backend=backend)
        print(f"  applied={out.applied} validated={out.validated} simulated={out.simulated}")
        print(f"  host after:  port {port} exposed = {host.is_port_exposed(port)}")
        print(f"  signed receipt: {(out.receipt_signature or '')[:16]}...")

        _hr("3. Failed post-fix validation -> automatic rollback restores host")
        plan2 = console.engine.plan(finding, web, rdp)
        console.engine.approve(plan2, approver="bob.approver", scanner_principal="alice.operator")
        out2 = console.engine.apply(plan2, actor="bob.approver", backend=backend,
                                    health_fn=lambda ring: ring.name != "fleet")
        print(f"  applied={out2.applied} (expected False after rollback)")
        print(f"  host restored: port {port} exposed = {host.is_port_exposed(port)}")

        _hr("4. All three safe auto-fix actions (apply -> validate -> rollback)")
        for atype, params, probe in [
            ("close_port", {"port": str(port)}, lambda: host.is_port_exposed(port)),
            ("disable_service", {"service": "telnetd"}, lambda: host.service_enabled("telnetd")),
            ("rotate_secret", {"secret": "svc-account", "old_value": "P@ssw0rd-old"},
             lambda: host.get_secret("svc-account")),
        ]:
            act = RemediationAction(f"act-{atype}", atype, "web-dmz-01", params)
            before = probe()
            backend.apply(act)
            ok = backend.validate(act)
            after = probe()
            backend.rollback(act)
            print(f"  {atype:16} before={before!s:22} validated={ok!s:5} "
                  f"after_apply={after!s:22} rolled_back={probe()!r}")

        _hr("PHASE 3 DEMO COMPLETE")
        print(f"  WORM audit chain verified: {console.audit_ok()}  "
              f"records={sum(1 for _ in console.store.iter_audit())}")
        print("  [OK] real reversible apply   [OK] post-fix validation")
        print("  [OK] canary rollback         [OK] 3 safe auto-fix actions")
        return 0
    finally:
        stop.set()
        srv.close()


def cmd_phase4(args: argparse.Namespace) -> int:
    from . import crypto, sbom, supplychain, worm
    from .authn import AuthManager, IdentityProvider, MFARequired, totp_now
    from .backends import AzureNsgBackend, RemediationAction
    from .ha import HACluster, ScannerPool
    from .itsm import MockServiceNow
    from .models import Asset, AssetCriticality, AuditRecord, utcnow
    from .rbac import Permission, Role
    from .remediation import RemediationEngine
    from .store import AuditSigner, Store

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    srv, port, stop = _open_listener()
    try:
        console = Console()

        _hr("A. Supply-chain: asymmetric signing + SBOM (D2 / P4-AC-1, AC-6)")
        priv = crypto.generate_keypair(2048)
        pub = priv.public()
        print("  RSA-2048 keypair — private key on build host, PUBLIC KEY on appliance")
        bom = sbom.generate_sbom("avmp")
        bundle = out / "signed_feed.bundle"
        digest = supplychain.build_signed_bundle(
            str(bundle), [{"cve": "CVE-2021-44228", "kev": True}], priv, bom,
            "kev-2024-12", "2024-12-01T00:00:00Z")
        body = supplychain.verify_signed_bundle(str(bundle), pub)
        print(f"  bundle verified with public key only; SBOM components={body['sbom']['component_count']}")
        repro = supplychain.reproducible_digest(body["payload"], body["sbom"],
                                                body["bundle_id"], body["created_at"])
        print(f"  reproducible build digest matches: {repro == digest}")
        tampered = out / "signed_feed_tampered.bundle"
        tampered.write_text(bundle.read_text().replace("CVE-2021-44228", "CVE-EVIL"))
        try:
            supplychain.verify_signed_bundle(str(tampered), pub)
            print("  tamper NOT detected (bug!)")
        except supplychain.BundleVerificationError as exc:
            print(f"  tampered bundle rejected fail-closed: {exc}")

        _hr("B. Hardened WORM audit: signed checkpoint (D3 / P4-AC-4)")
        web = Asset("web-dmz-01", hostname="web-dmz-01", ip_addresses=["127.0.0.1"],
                    criticality=AssetCriticality.MEDIUM, internet_facing=True)
        console.register_asset(web)
        finding = console.scan_asset(web, plugins=[PortExposurePlugin(
            "demo.exposed_rdp", "RDP", port=port, severity="high", cve=["CVE-2019-0708"])])[0]
        cp = worm.create_checkpoint(console.store, priv, utcnow().isoformat())
        print(f"  signed checkpoint at count={cp['count']}; verifies={worm.verify_checkpoint(console.store, pub, cp)}")
        console.store._conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
        console.store._conn.commit()
        print(f"  simulated truncation detected: {not worm.verify_checkpoint(console.store, pub, cp)}")

        _hr("C. SSO + MFA enforcement (D4 / P4-AC-5)")
        idp = IdentityProvider()
        approver = idp.add_user("bob.approver", [Role.APPROVER], mfa_required=True)
        auth = AuthManager(idp)
        session = auth.login("bob.approver")
        try:
            auth.authorize(session.token, Permission.EXECUTE_REMEDIATION)
        except MFARequired as exc:
            print(f"  privileged action blocked before MFA: {exc}")
        auth.verify_mfa(session.token, totp_now(approver.mfa_secret))
        auth.authorize(session.token, Permission.EXECUTE_REMEDIATION)
        print("  TOTP MFA passed -> remediation authorized (UI no longer trusts a plain actor field)")

        _hr("D. Azure NSG remediation under change control (D5, D6 / P4-AC-7, AC-8)")
        snow = MockServiceNow()
        engine = RemediationEngine(console.store, itsm=snow)
        # Credentials-only switch: use a live Azure client if one is configured,
        # otherwise the tested simulated NSG. Nothing else in the flow changes.
        import os as _os
        from .azure_client import NsgScope, build_from_env
        live = build_from_env()
        if live is not None:
            scopes = {"web-dmz-01": NsgScope(
                _os.environ["AZURE_SUBSCRIPTION_ID"],
                _os.environ.get("AZURE_RESOURCE_GROUP", "rg-sentinelfix"),
                _os.environ.get("AZURE_NSG_NAME", "nsg-web-dmz-01"))}
            nsg_backend = AzureNsgBackend(client=live, scopes=scopes)
            print("  LIVE Azure client detected -> issuing real NSG calls")
        else:
            nsg_backend = AzureNsgBackend()
            print("  no Azure credentials -> simulated NSG (set AZURE_SUBSCRIPTION_ID "
                  "+ install azure SDK to go live)")
        plan = engine.plan(finding, web, PortExposurePlugin("demo.exposed_rdp", "RDP", port))
        print(f"  dry-run:\n    {nsg_backend.preview(plan.action)}")
        engine.approve(plan, approver="bob.approver", scanner_principal="alice.operator")
        rfc_id = engine.open_change_request(plan, actor="bob.approver")
        print(f"  RFC auto-created: {rfc_id} (state={snow.get(rfc_id).state.value})")
        denied = engine.apply(plan, actor="bob.approver", backend=nsg_backend)
        print(f"  apply blocked until RFC approved: applied={denied.applied} — {denied.denied_reason}")
        snow.approve(rfc_id, approver="cab.manager")
        ok = engine.apply(plan, actor="bob.approver", backend=nsg_backend)
        print(f"  RFC approved -> applied={ok.applied} validated={ok.validated} "
              f"nsg_deny_in_effect={nsg_backend.validate(plan.action)}")
        print(f"  RFC {rfc_id} now {snow.get(rfc_id).state.value}; receipt {(ok.receipt_signature or '')[:16]}...")
        # Isolated rollback demonstration on a distinct action.
        rb = RemediationAction("nsg-rollback-demo", "close_port", "web-dmz-01", {"port": "9999"})
        nsg_backend.apply(rb)
        applied_ok = nsg_backend.validate(rb)
        nsg_backend.rollback(rb)
        print(f"  rollback safety: applied={applied_ok} -> after rollback deny present={nsg_backend.validate(rb)}")

        _hr("E. Air-gapped operation (D7 / P4-AC-9)")
        print("  offline signed bundle import: verified above (no network fetch)")
        print("  outbound telemetry: DISABLED by default (local-only)")
        print(f"  VDB entries local: {console.store.vdb_count()} (updated {console.store.vdb_latest_update() or 'n/a'})")

        _hr("F. High availability: failover with zero audit loss (D8 / P4-AC-10)")
        ha_key = AuditSigner(b"ha-demo-32-byte-key-000000000000"[:32])
        primary = Store(":memory:", signer=ha_key)
        standby = Store(":memory:", signer=ha_key)
        cluster = HACluster(primary, standby)
        for i in range(5):
            cluster.append_audit(AuditRecord(str(i), "soc", "scan.completed", "asset", utcnow()))
        print(f"  primary={primary.audit_count()} standby={standby.audit_count()} audit_loss={cluster.audit_loss()}")
        active = cluster.failover()
        print(f"  primary DOWN -> promoted standby: records={active.audit_count()} "
              f"chain_ok={cluster.standby_chain_ok()}")
        pool = ScannerPool(["scanner-a", "scanner-b"])
        first = pool.route()
        pool.mark_down(first)
        print(f"  scan routed to {first}; {first} DOWN -> rerouted to {pool.route()}")

        _hr("PHASE 4 DEMO COMPLETE — government-hardening capabilities")
        print("  [OK] asymmetric signing + SBOM    [OK] WORM signed checkpoints")
        print("  [OK] SSO + TOTP MFA               [OK] Azure NSG remediation + RFC gate")
        print("  [OK] air-gapped + no telemetry    [OK] HA failover, zero audit loss")
        print(f"\n  Reports/bundles written to {out.resolve()}")
        return 0
    finally:
        stop.set()
        srv.close()


def cmd_benchmark(args: argparse.Namespace) -> int:
    from .benchmark import run_benchmark
    r = run_benchmark(n_vulnerable=args.vulnerable, n_clean=args.clean)
    _hr("Detection benchmark (Phase 2 AC-10)")
    print(f"  vulnerable={r.vulnerable} clean={r.clean} "
          f"TP={r.true_positives} FP={r.false_positives} FN={r.false_negatives}")
    print(f"  detection rate     : {r.detection_rate * 100:.1f}%")
    print(f"  false-positive rate: {r.false_positive_rate * 100:.2f}%  "
          f"(target < 5% -> {'PASS' if r.false_positive_rate < 0.05 else 'FAIL'})")
    return 0 if r.false_positive_rate < 0.05 else 1


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


def cmd_authoring(args: argparse.Namespace) -> int:
    from .playbooks import PlaybookRepository, load_builtin_library
    from .store import Store
    from .ui import serve_ui

    store = Store(args.db) if args.db else Store(":memory:")
    repo = PlaybookRepository(store=store)
    if not repo.list():
        load_builtin_library(repo)
    httpd = serve_ui(repo, host=args.host, port=args.port)
    print(f"SentinelFix playbook authoring UI on http://{args.host}:{args.port}/playbooks "
          f"— Ctrl+C to stop")
    print("  (dev only: trusts the actor/role form fields; run behind an "
          "authenticated proxy in production)")
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

    p3 = sub.add_parser("phase3", help="run the Phase 3 safe auto-remediation pipeline")
    p3.set_defaults(func=cmd_phase3)

    p4 = sub.add_parser("phase4", help="run the Phase 4 government-hardening pipeline")
    p4.add_argument("--out", default="out", help="output directory for bundles/reports")
    p4.set_defaults(func=cmd_phase4)

    bm = sub.add_parser("benchmark", help="measure detection & false-positive rate (AC-10)")
    bm.add_argument("--vulnerable", type=int, default=10)
    bm.add_argument("--clean", type=int, default=20)
    bm.set_defaults(func=cmd_benchmark)

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

    au = sub.add_parser("authoring", help="start the playbook authoring UI (D3.2)")
    au.add_argument("--host", default="127.0.0.1")
    au.add_argument("--port", type=int, default=8600)
    au.add_argument("--db", default=None, help="SQLite DB for persistence (in-memory if omitted)")
    au.set_defaults(func=cmd_authoring)

    args = parser.parse_args(argv)
    return args.func(args)
