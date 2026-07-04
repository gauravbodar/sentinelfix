"""Minimal read-only Console API (PRD §4 Console API).

Standard-library http.server only (no external web framework), so it runs on an
air-gapped appliance. Exposes JSON read endpoints over the shared Console. This
is intentionally read-only: mutating actions (scan, approve, remediate) go
through authenticated, RBAC-checked paths not exposed by this MVP surface.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .console import Console


def make_handler(console: Console):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload) -> None:
            body = json.dumps(payload, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "audit_chain_ok": console.audit_ok()})
            elif self.path == "/assets":
                self._send(200, [a.to_dict() for a in console.list_assets()])
            elif self.path == "/findings":
                self._send(200, [f.to_dict() for f in console.list_findings()])
            elif self.path == "/audit":
                self._send(200, list(console.store.iter_audit()))
            else:
                self._send(404, {"error": "not found", "path": self.path})

        def log_message(self, *args) -> None:  # silence default stderr logging
            pass

    return Handler


def serve(console: Console, host: str = "127.0.0.1", port: int = 8443) -> ThreadingHTTPServer:
    """Create (not start) the server. Caller runs serve_forever()."""
    return ThreadingHTTPServer((host, port), make_handler(console))
