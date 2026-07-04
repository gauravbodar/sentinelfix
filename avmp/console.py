"""Console facade (PRD §4 Console).

Ties together the store, scanner, enrichment, scoring, playbooks, remediation,
and manual workflow. This is the orchestration surface the API/CLI call into.
"""

from __future__ import annotations

from typing import Optional

from .enrichment import Enricher
from .models import Asset, Finding, utcnow
from .playbooks import PlaybookRepository, load_builtin_library
from .plugin_sdk import Plugin, PluginTarget
from .plugins import builtin_plugins
from .remediation import ChangeWindow, RemediationEngine
from .scanner import ScannerNode
from .scoring import ScoringModel
from .store import Store
from .workflow import WorkflowEngine


class Console:
    def __init__(
        self,
        store: Optional[Store] = None,
        change_windows: Optional[list[ChangeWindow]] = None,
        scoring_model: Optional[ScoringModel] = None,
        load_playbooks: bool = True,
    ) -> None:
        self.store = store or Store(":memory:")
        # Enricher reads ingested VDB entries from the store (Phase 2 D1), with
        # the built-in slice as fallback.
        self.enricher = Enricher(store=self.store)
        self.scanner = ScannerNode()
        self.engine = RemediationEngine(self.store, change_windows=change_windows)
        self.plugins: list[Plugin] = builtin_plugins()
        self.scoring = scoring_model or ScoringModel()
        self.playbooks = PlaybookRepository(store=self.store)
        self.workflow = WorkflowEngine(self.store)
        if load_playbooks:
            load_builtin_library(self.playbooks)

    # --- assets ---------------------------------------------------------
    def register_asset(self, asset: Asset, actor: str = "system") -> None:
        if asset.discovered_at is None:
            asset.discovered_at = utcnow()
        self.store.upsert_asset(asset)
        self.engine._audit(actor, "asset.registered", asset.asset_id,
                           {"criticality": asset.criticality.value})

    def list_assets(self) -> list[Asset]:
        return self.store.list_assets()

    # --- scan + enrich + prioritize (PRD data flow steps 2-4) -----------
    def scan_asset(self, asset: Asset, actor: str = "scanner-operator",
                   plugins: Optional[list[Plugin]] = None,
                   open_tickets: bool = False) -> list[Finding]:
        address = (asset.ip_addresses or [asset.hostname or ""])[0]
        target = PluginTarget(asset_id=asset.asset_id, address=address)
        findings = self.scanner.run_plugins(target, plugins or self.plugins)
        for f in findings:
            self.enricher.enrich(f)
            self.store.upsert_finding(f)
            if open_tickets:
                risk = self.scoring.score(f, asset).score
                self.workflow.open_ticket(f, risk, asset, actor=actor)
        self.engine._audit(actor, "scan.completed", asset.asset_id,
                           {"findings": str(len(findings))})
        return findings

    def list_findings(self, asset_id: Optional[str] = None) -> list[Finding]:
        return self.store.list_findings(asset_id)

    # --- prioritization / playbook linkage (Phase 2 D2/D3) --------------
    def score(self, finding: Finding, asset: Asset):
        return self.scoring.score(finding, asset)

    def linked_playbook(self, finding: Finding) -> str:
        return self.playbooks.attach(finding)

    def record_risk_snapshot(self) -> dict:
        """Persist a risk snapshot for trend lines (Phase 2 D5.2)."""
        assets = {a.asset_id: a for a in self.list_assets()}
        findings = self.list_findings()
        total = 0.0
        for f in findings:
            a = assets.get(f.asset_id)
            total += self.scoring.score(f, a).score
        snap = {"total_risk": round(total, 1), "finding_count": len(findings)}
        self.store.append_risk_snapshot(utcnow().isoformat(), snap)
        return snap

    # --- audit ----------------------------------------------------------
    def audit_ok(self) -> bool:
        return self.store.verify_audit_chain()
