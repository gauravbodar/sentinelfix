import unittest

from avmp.models import AssetCriticality, RemediationMode, Severity
from avmp.policy_matrix import MatrixKey, resolve


class TestPolicyMatrix(unittest.TestCase):
    def test_low_low_no_exploit_is_safe_auto_no_approval(self):
        d = resolve(MatrixKey(AssetCriticality.LOW, Severity.LOW, False))
        self.assertEqual(d.allowed_mode, RemediationMode.SAFE_AUTO)
        self.assertFalse(d.requires_approval)

    def test_mission_critical_high_is_manual_only(self):
        d = resolve(MatrixKey(AssetCriticality.MISSION_CRITICAL, Severity.HIGH, True))
        self.assertEqual(d.allowed_mode, RemediationMode.MANUAL_ONLY)
        self.assertTrue(d.requires_approval)

    def test_medium_high_is_staged_patch_with_approval(self):
        d = resolve(MatrixKey(AssetCriticality.MEDIUM, Severity.HIGH, True))
        self.assertEqual(d.allowed_mode, RemediationMode.STAGED_PATCH)
        self.assertTrue(d.requires_approval)

    def test_critical_on_low_asset_fails_closed_to_manual(self):
        d = resolve(MatrixKey(AssetCriticality.LOW, Severity.CRITICAL, False))
        self.assertEqual(d.allowed_mode, RemediationMode.MANUAL_ONLY)
        self.assertTrue(d.requires_approval)


if __name__ == "__main__":
    unittest.main()
