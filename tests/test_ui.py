import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from avmp.playbooks import PlaybookRepository, PlaybookState
from avmp.ui import serve_ui


class TestAuthoringUI(unittest.TestCase):
    def setUp(self):
        self.repo = PlaybookRepository()
        self.httpd = serve_ui(self.repo, host="127.0.0.1", port=0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _get(self, path):
        try:
            with urllib.request.urlopen(self._url(path)) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post(self, path, fields):
        data = urllib.parse.urlencode(fields).encode()
        try:
            with urllib.request.urlopen(self._url(path), data=data) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_create_edit_submit_publish_flow(self):
        # Author (system_owner has MANAGE_POLICY) creates a draft.
        status, _ = self._post("/playbooks", {
            "playbook_id": "pb.ui", "title": "UI test", "role": "system_owner",
            "actor": "alice", "binds_plugin_ids": "x.plugin", "fix_steps": "step one\nstep two",
        })
        self.assertEqual(status, 200)  # urllib follows the 303 redirect to the view
        self.assertEqual(self.repo.get("pb.ui", 1).state, PlaybookState.DRAFT)
        self.assertEqual(self.repo.get("pb.ui", 1).fix_steps, ["step one", "step two"])

        # Submit for review.
        self._post("/playbooks/pb.ui/1/submit", {"actor": "alice", "role": "system_owner"})
        self.assertEqual(self.repo.get("pb.ui", 1).state, PlaybookState.IN_REVIEW)

        # Publish by a DIFFERENT actor -> succeeds.
        self._post("/playbooks/pb.ui/1/publish", {"actor": "bob", "role": "admin"})
        self.assertEqual(self.repo.get("pb.ui", 1).state, PlaybookState.PUBLISHED)

    def test_publish_by_author_blocked_separation_of_duties(self):
        self._post("/playbooks", {"playbook_id": "pb.sod", "title": "t",
                                  "role": "system_owner", "actor": "alice"})
        self._post("/playbooks/pb.sod/1/submit", {"actor": "alice", "role": "system_owner"})
        status, body = self._post("/playbooks/pb.sod/1/publish",
                                  {"actor": "alice", "role": "system_owner"})
        self.assertEqual(status, 403)
        self.assertIn("Separation of duties", body)
        self.assertEqual(self.repo.get("pb.sod", 1).state, PlaybookState.IN_REVIEW)

    def test_role_without_manage_policy_rejected(self):
        status, body = self._post("/playbooks", {
            "playbook_id": "pb.x", "title": "t", "role": "auditor", "actor": "carol"})
        self.assertEqual(status, 403)
        self.assertIn("lacks", body)

    def test_published_not_editable(self):
        self._post("/playbooks", {"playbook_id": "pb.e", "title": "t",
                                  "role": "admin", "actor": "alice"})
        self._post("/playbooks/pb.e/1/publish", {"actor": "bob", "role": "admin"})
        status, body = self._get("/playbooks/pb.e/1/edit")
        self.assertEqual(status, 400)
        self.assertIn("Only DRAFT", body)

    def test_list_page_renders(self):
        status, body = self._get("/playbooks")
        self.assertEqual(status, 200)
        self.assertIn("Playbooks", body)


if __name__ == "__main__":
    unittest.main()
