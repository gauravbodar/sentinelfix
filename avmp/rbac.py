"""RBAC & separation of duties (PRD §7).

Enforces that scanner operators, approvers, and auditors are distinct. The
separation rule is explicit: no single role may both run scans and approve
remediation, and only APPROVER may approve.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    SCANNER_OPERATOR = "scanner_operator"
    APPROVER = "approver"
    AUDITOR = "auditor"
    SYSTEM_OWNER = "system_owner"
    ADMIN = "admin"


class Permission(str, Enum):
    RUN_SCAN = "run_scan"
    VIEW_FINDINGS = "view_findings"
    APPROVE_REMEDIATION = "approve_remediation"
    EXECUTE_REMEDIATION = "execute_remediation"
    VIEW_AUDIT = "view_audit"
    MANAGE_POLICY = "manage_policy"


_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.SCANNER_OPERATOR: {Permission.RUN_SCAN, Permission.VIEW_FINDINGS},
    Role.APPROVER: {
        Permission.VIEW_FINDINGS,
        Permission.APPROVE_REMEDIATION,
        Permission.EXECUTE_REMEDIATION,
    },
    Role.AUDITOR: {Permission.VIEW_FINDINGS, Permission.VIEW_AUDIT},
    Role.SYSTEM_OWNER: {Permission.VIEW_FINDINGS, Permission.MANAGE_POLICY},
    # ADMIN deliberately does NOT get APPROVE_REMEDIATION together with RUN_SCAN
    # in a way that lets one person scan-and-approve the same finding; approval
    # always routes to a distinct APPROVER principal (see remediation engine).
    Role.ADMIN: {
        Permission.RUN_SCAN,
        Permission.VIEW_FINDINGS,
        Permission.VIEW_AUDIT,
        Permission.MANAGE_POLICY,
    },
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in _ROLE_PERMISSIONS.get(role, set())


def enforce_separation_of_duties(scanner_principal: str, approver_principal: str) -> None:
    """Raise if the same principal tries to both scan and approve a fix."""
    if scanner_principal == approver_principal:
        raise PermissionError(
            "Separation of duties: the scan operator cannot approve their own remediation."
        )
