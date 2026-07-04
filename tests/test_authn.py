import unittest

from avmp.authn import (
    AuthManager,
    AuthenticationError,
    IdentityProvider,
    MFARequired,
    PermissionDenied,
    totp_now,
    verify_totp,
)
from avmp.rbac import Permission, Role


class TestTOTP(unittest.TestCase):
    def test_totp_roundtrip_and_reject(self):
        from avmp.authn import generate_totp_secret
        secret = generate_totp_secret()
        code = totp_now(secret, at=1_000_000)
        self.assertTrue(verify_totp(secret, code, at=1_000_000))
        self.assertFalse(verify_totp(secret, "000000", at=1_000_000 + 10_000))


class TestAuthManager(unittest.TestCase):
    def setUp(self):
        self.idp = IdentityProvider()
        self.approver = self.idp.add_user("bob", [Role.APPROVER], mfa_required=True)
        self.auditor = self.idp.add_user("carol", [Role.AUDITOR], mfa_required=True)
        self.auth = AuthManager(self.idp)

    def test_unknown_user_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.auth.login("mallory")

    def test_privileged_action_requires_mfa(self):
        s = self.auth.login("bob")
        with self.assertRaises(MFARequired):
            self.auth.authorize(s.token, Permission.EXECUTE_REMEDIATION)
        # Complete MFA -> allowed.
        self.assertTrue(self.auth.verify_mfa(s.token, totp_now(self.approver.mfa_secret)))
        session = self.auth.authorize(s.token, Permission.EXECUTE_REMEDIATION)
        self.assertEqual(session.username, "bob")

    def test_role_without_permission_denied(self):
        s = self.auth.login("carol")
        self.auth.verify_mfa(s.token, totp_now(self.auditor.mfa_secret))
        with self.assertRaises(PermissionDenied):
            self.auth.authorize(s.token, Permission.EXECUTE_REMEDIATION)

    def test_no_session_rejected(self):
        with self.assertRaises(AuthenticationError):
            self.auth.authorize("bogus-token", Permission.VIEW_FINDINGS)


if __name__ == "__main__":
    unittest.main()
