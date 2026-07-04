"""Console facade (PRD §4 Console).

Ties together the store, scanner, enrichment, policy, and remediation engine.
This is the orchestration surface the API/CLI call into.
"""

from __future__ import annotations

import uuid
from typing import Optional

from .enrichment import Enricher
from .models import Asset, Finding, utcnow
from .plugin_sdk import Plugin, PluginTarget
from .plugins import builtin_plugins
from .remediation import ChangeWindow, RemediationEngine
from .scanner import ScannerNode
from .store import Store


class Console:
    def __init__(
        self,
        store: Optional[Store] = None,
        change_windows: Optional[list[ChangeWindow]] = None,
    ) -> None:
        self.store = store or Store(":memory:")
        self.enricher = Enricher()
        self.scanner = ScannerNode()
        self.engine = RemediationEngine(self.store, change_windows=change_windows)
        self.plugins: list[Plugin] = builtin_plugins()

    # --- assets ---------------------------------------------------------
    def register_asset(self, asset: Asset, actor: str = "system") -> None:
        if asset.discovered_at is None:
            asset.discovered_at = utcnow()
        self.store.upsert_asset(asset)
        self.engine._audit(actor, "asset.registered", asset.asset_id,
                           {"criticality": asset.criticality.value})

    def list_assets(self) -> list[Asset]:
        return self.store.list_assets()

    # --- scan + enrich (PRD data flow steps 2-4) ------------------------
    def scan_asset(self, asset: Asset, actor: str = "scanner-operator",
                   plugins: Optional[list[Plugin]] = None) -> list[Finding]:
        address = (asset.ip_addresses or [asset.hostname or ""])[0]
        target = PluginTarget(asset_id=asset.asset_id, address=address)
        findings = self.scanner.run_plugins(target, plugins or self.plugins)
        for f in findings:
            self.enricher.enrich(f)
            self.store.upsert_finding(f)
        self.engine._audit(actor, "scan.completed", asset.asset_id,
                           {"findings": str(len(findings))})
        return findings

    def list_findings(self, asset_id: Optional[str] = None) -> list[Finding]:
        return self.store.list_findings(asset_id)

    # --- audit ----------------------------------------------------------
    def audit_ok(self) -> bool:
        return self.store.verify_audit_chain()
