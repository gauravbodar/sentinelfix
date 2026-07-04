"""Live Azure NSG client (Phase 4 D5, credentials-only switch).

`AzureNsgBackend` runs against an in-process `SimulatedNsg` by default (fully
tested, air-gap-safe). Passing it an `AzureNsgClient` flips the same apply /
validate / rollback logic onto a real Network Security Group — no other code,
gate, or audit path changes.

The Azure SDK (`azure-identity`, `azure-mgmt-network`) is imported **lazily**,
inside methods, so importing this module never fails on a sealed appliance that
doesn't have the SDK. `build_from_env()` returns a live client only when both the
SDK and credentials are present; otherwise it returns None and the backend stays
simulated.

Wiring a real tenant on demo day is therefore: set the env vars, `pip install
azure-identity azure-mgmt-network`, pass `build_from_env()` as the client.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NsgScope:
    subscription_id: str
    resource_group: str
    nsg_name: str


class AzureNsgClient(ABC):
    """Minimal NSG operations the backend needs."""

    @abstractmethod
    def create_deny_rule(self, scope: NsgScope, name: str, port: int, priority: int = 100) -> None: ...

    @abstractmethod
    def delete_rule(self, scope: NsgScope, name: str) -> None: ...

    @abstractmethod
    def deny_exists(self, scope: NsgScope, port: int) -> bool: ...


class AzureSdkNsgClient(AzureNsgClient):
    """Real implementation over azure-mgmt-network. SDK imported lazily."""

    def __init__(self, credential=None) -> None:
        self._credential = credential
        self._clients: dict[str, object] = {}   # subscription_id -> NetworkManagementClient

    def _credential_or_default(self):
        if self._credential is not None:
            return self._credential
        from azure.identity import DefaultAzureCredential  # lazy
        self._credential = DefaultAzureCredential()
        return self._credential

    def _client(self, subscription_id: str):
        if subscription_id not in self._clients:
            from azure.mgmt.network import NetworkManagementClient  # lazy
            self._clients[subscription_id] = NetworkManagementClient(
                self._credential_or_default(), subscription_id)
        return self._clients[subscription_id]

    def create_deny_rule(self, scope: NsgScope, name: str, port: int, priority: int = 100) -> None:
        client = self._client(scope.subscription_id)
        params = {
            "protocol": "*",
            "source_address_prefix": "0.0.0.0/0",
            "destination_address_prefix": "*",
            "access": "Deny",
            "direction": "Inbound",
            "priority": priority,
            "source_port_range": "*",
            "destination_port_range": str(port),
        }
        client.security_rules.begin_create_or_update(
            scope.resource_group, scope.nsg_name, name, params).result()

    def delete_rule(self, scope: NsgScope, name: str) -> None:
        client = self._client(scope.subscription_id)
        client.security_rules.begin_delete(
            scope.resource_group, scope.nsg_name, name).result()

    def deny_exists(self, scope: NsgScope, port: int) -> bool:
        client = self._client(scope.subscription_id)
        for rule in client.security_rules.list(scope.resource_group, scope.nsg_name):
            if (getattr(rule, "access", "") == "Deny"
                    and getattr(rule, "direction", "") == "Inbound"
                    and str(port) == str(getattr(rule, "destination_port_range", ""))):
                return True
        return False


def sdk_available() -> bool:
    try:
        import azure.identity  # noqa: F401
        import azure.mgmt.network  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 - any import failure means not available
        return False


def build_from_env() -> Optional[AzureSdkNsgClient]:
    """Return a live client iff the Azure SDK and credentials are present.

    Honors AZURE_SUBSCRIPTION_ID (+ the standard DefaultAzureCredential env vars
    / managed identity). Returns None on an air-gapped box so the backend stays
    simulated. This is the entire 'credentials-only switch'."""
    if not sdk_available():
        return None
    if not os.environ.get("AZURE_SUBSCRIPTION_ID"):
        return None
    return AzureSdkNsgClient()
