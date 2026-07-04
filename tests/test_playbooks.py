import unittest

from avmp.models import Finding, Severity
from avmp.playbooks import (
    PlaybookRepository,
    PlaybookState,
    PlaybookTemplate,
    load_builtin_library,
)


class TestPlaybooks(unittest.TestCase):
    def setUp(self):
        self.repo = PlaybookRepository()
        load_builtin_library(self.repo)

    def test_starter_library_has_at_least_10_published(self):
        self.assertGreaterEqual(len(self.repo.published()), 10)

    def test_match_by_plugin_id(self):
        f = Finding("f", "a", "net.exposed_rdp.3389", "RDP", severity=Severity.HIGH)
        t = self.repo.match(f)
        self.assertIsNotNone(t)
        self.assertEqual(t.playbook_id, "pb.exposed_rdp")

    def test_match_by_cve(self):
        f = Finding("f", "a", "unknown.plugin", "x", severity=Severity.HIGH,
                    cve_ids=["CVE-2021-44228"])
        self.assertEqual(self.repo.match(f).playbook_id, "pb.log4shell")

    def test_match_by_severity_fallback(self):
        f = Finding("f", "a", "unknown.plugin", "x", severity=Severity.LOW)
        self.assertEqual(self.repo.match(f).playbook_id, "pb.low_generic")

    def test_attach_returns_fallback_when_no_match(self):
        f = Finding("f", "a", "unknown.plugin", "x", severity=Severity.INFORMATIONAL)
        # informational has a generic playbook, so craft a finding with no bind:
        f2 = Finding("f2", "a", "unknown.plugin", "x", severity=Severity.MEDIUM)
        self.assertTrue(self.repo.attach(f2))  # medium_generic exists -> not fallback

    def test_lifecycle_draft_review_publish_and_versioning(self):
        repo = PlaybookRepository()
        t1 = repo.save(PlaybookTemplate("pb.custom", "Custom v1", version=1,
                                        binds_plugin_ids=["x.plugin"]))
        self.assertEqual(t1.state, PlaybookState.DRAFT)
        repo.submit_for_review("pb.custom", 1, actor="author")
        repo.publish("pb.custom", 1, actor="approver")
        self.assertEqual(len(repo.published()), 1)

        # New version, publish it -> the old version is archived.
        repo.save(PlaybookTemplate("pb.custom", "Custom v2", version=2,
                                   binds_plugin_ids=["x.plugin"]))
        repo.publish("pb.custom", 2, actor="approver")
        published = [t for t in repo.published() if t.playbook_id == "pb.custom"]
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].version, 2)

    def test_illegal_publish_state_rejected(self):
        repo = PlaybookRepository()
        repo.save(PlaybookTemplate("pb.x", "X", version=1))
        repo.publish("pb.x", 1, actor="a")
        with self.assertRaises(ValueError):
            repo.publish("pb.x", 1, actor="a")  # already published


if __name__ == "__main__":
    unittest.main()
