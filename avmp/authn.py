"""Authentication + MFA (Phase 4 D4 / P4-AC-5).

Enforces that privileged actions require an authenticated identity AND a passed
MFA challenge — the authoring UI/API no longer trust a plain `actor` field.

  * Identity: a local IdP stub stands in for SAML/AD/Entra SSO. The production
    swap is a real SAML/OIDC assertion validated against the IdP; the session +
    authorization logic below is unchanged.
  * MFA: a REAL RFC 6238 TOTP implementation (works with any authenticator app,
    or a code computed via `totp_now`). This is not a mock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .rbac import Permission, Role, has_permission


# --- TOTP (RFC 6238) --------------------------------------------------------
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(10)).decode("ascii")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def totp_now(secret: str, at: Optional[float] = None, step: int = 30) -> str:
    return _hotp(secret, int((at if at is not None else time.time()) // step))


def verify_totp(secret: str, code: str, at: Optional[float] = None,
                step: int = 30, window: int = 1) -> bool:
    now = int((at if at is not None else time.time()) // step)
    return any(_hotp(secret, now + i) == code for i in range(-window, window + 1))


# --- errors -----------------------------------------------------------------
class AuthenticationError(Exception): ...
class MFARequired(Exception): ...
class PermissionDenied(Exception): ...


# --- identities + sessions --------------------------------------------------
@dataclass
class User:
    username: str
    roles: list[Role]
    mfa_secret: str
    mfa_required: bool = True


@dataclass
class Session:
    token: str
    username: str
    roles: list[Role]
    mfa_verified: bool = False
    created_at: float = field(default_factory=time.time)


class IdentityProvider:
    """Local IdP stub (production: SAML/OIDC against AD/Entra)."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add_user(self, username: str, roles: list[Role],
                 mfa_required: bool = True) -> User:
        user = User(username, roles, generate_totp_secret(), mfa_required)
        self._users[username] = user
        return user

    def get(self, username: str) -> Optional[User]:
        return self._users.get(username)


class AuthManager:
    def __init__(self, idp: IdentityProvider) -> None:
        self.idp = idp
        self._sessions: dict[str, Session] = {}

    def login(self, username: str) -> Session:
        user = self.idp.get(username)
        if user is None:
            raise AuthenticationError(f"Unknown principal '{username}'.")
        session = Session(secrets.token_urlsafe(24), user.username, list(user.roles))
        self._sessions[session.token] = session
        return session

    def verify_mfa(self, token: str, code: str, at: Optional[float] = None) -> bool:
        session = self._sessions.get(token)
        if session is None:
            raise AuthenticationError("No such session.")
        user = self.idp.get(session.username)
        ok = verify_totp(user.mfa_secret, code, at=at)
        session.mfa_verified = ok
        return ok

    def authorize(self, token: str, permission: Permission,
                  require_mfa: bool = True) -> Session:
        """Return the session if it is authenticated, MFA-verified (when
        required), and holds `permission`. Otherwise raise."""
        session = self._sessions.get(token)
        if session is None:
            raise AuthenticationError("Not authenticated.")
        user = self.idp.get(session.username)
        if require_mfa and user.mfa_required and not session.mfa_verified:
            raise MFARequired("MFA challenge required for this action.")
        if not any(has_permission(r, permission) for r in session.roles):
            raise PermissionDenied(f"'{session.username}' lacks {permission.value}.")
        return session
