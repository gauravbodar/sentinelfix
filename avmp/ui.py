"""Server-rendered playbook authoring UI (Phase 2 D3.2).

Standard-library only (http.server + html) — no JS framework, no build step, no
npm supply chain — consistent with the air-gapped appliance model (PRD §7/§11).
Provides the draft -> review -> publish authoring workflow over HTML forms.

Security note: real authentication (SAML/AD/Entra, MFA), CSRF tokens, and mTLS
are Phase 4. This UI trusts the `actor`/`role` form fields and MUST run behind
the appliance's authenticated reverse proxy. RBAC (role -> permission) and
separation of duties (author != publisher) are enforced here regardless.
"""

from __future__ import annotations

import html
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .playbooks import PlaybookRepository, PlaybookState, PlaybookTemplate
from .rbac import Permission, Role, has_permission

_ROLES = [r.value for r in Role]

_STYLE = """
<style>
 body{font-family:system-ui,Arial,sans-serif;margin:2rem;max-width:900px;color:#1b1b1b}
 h1,h2{color:#0b3d66} a{color:#0b5cad}
 table{border-collapse:collapse;width:100%} th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}
 .state{font-weight:600} .draft{color:#8a6d00} .in_review{color:#8a4b00}
 .published{color:#0a6b2b} .archived{color:#777}
 form.inline{display:inline} label{display:block;margin:.5rem 0 .2rem;font-weight:600}
 input[type=text],textarea,select{width:100%;padding:6px;font:inherit;box-sizing:border-box}
 textarea{min-height:4rem} .btn{background:#0b5cad;color:#fff;border:0;padding:6px 12px;border-radius:4px;cursor:pointer}
 .btn.warn{background:#8a4b00} .muted{color:#666;font-size:.9rem} .err{color:#a10000;font-weight:600}
</style>
"""


def _page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{html.escape(title)}</title>{_STYLE}</head><body>"
            f"<p class='muted'><a href='/'>SentinelFix</a> &raquo; Playbook authoring</p>"
            f"{body}</body></html>").encode("utf-8")


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _lines(items) -> str:
    return "\n".join(items or [])


def _role_select(name: str = "role") -> str:
    opts = "".join(f"<option value='{r}'>{r}</option>" for r in _ROLES)
    return f"<select name='{name}'>{opts}</select>"


def _template_form(t: PlaybookTemplate | None, action: str, submit_label: str,
                   id_editable: bool) -> str:
    t = t or PlaybookTemplate(playbook_id="", title="")
    pid = (f"<label>Playbook id</label><input type='text' name='playbook_id' value='{_esc(t.playbook_id)}'>"
           if id_editable else f"<input type='hidden' name='playbook_id' value='{_esc(t.playbook_id)}'>")
    return f"""
    <form method='post' action='{action}'>
      {pid}
      <label>Title</label><input type='text' name='title' value='{_esc(t.title)}'>
      <label>Binds — plugin ids (comma-separated)</label>
      <input type='text' name='binds_plugin_ids' value='{_esc(",".join(t.binds_plugin_ids))}'>
      <label>Binds — CVE ids (comma-separated)</label>
      <input type='text' name='binds_cve_ids' value='{_esc(",".join(t.binds_cve_ids))}'>
      <label>Binds — severities (comma-separated)</label>
      <input type='text' name='binds_severities' value='{_esc(",".join(t.binds_severities))}'>
      <label>Root cause</label><input type='text' name='root_cause' value='{_esc(t.root_cause)}'>
      <label>Impact</label><input type='text' name='impact' value='{_esc(t.impact)}'>
      <label>Fix steps (one per line)</label><textarea name='fix_steps'>{_esc(_lines(t.fix_steps))}</textarea>
      <label>Pre-checks (one per line)</label><textarea name='pre_checks'>{_esc(_lines(t.pre_checks))}</textarea>
      <label>Post-validation (one per line)</label><textarea name='post_validation'>{_esc(_lines(t.post_validation))}</textarea>
      <label>Rollback steps (one per line)</label><textarea name='rollback_steps'>{_esc(_lines(t.rollback_steps))}</textarea>
      <label>Estimated downtime</label><input type='text' name='est_downtime' value='{_esc(t.est_downtime)}'>
      <label>Risk notes</label><input type='text' name='risk_notes' value='{_esc(t.risk_notes)}'>
      <label>Actor (author)</label><input type='text' name='actor' value=''>
      <label>Role</label>{_role_select()}
      <p><button class='btn' type='submit'>{_esc(submit_label)}</button></p>
    </form>
    """


def _split_csv(v: str) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _split_lines(v: str) -> list[str]:
    return [x.strip() for x in (v or "").splitlines() if x.strip()]


def make_handler(repo: PlaybookRepository):
    R_VIEW = re.compile(r"^/playbooks/([^/]+)/(\d+)$")
    R_EDIT = re.compile(r"^/playbooks/([^/]+)/(\d+)/edit$")
    R_ACTION = re.compile(r"^/playbooks/([^/]+)/(\d+)/(submit|publish)$")
    R_NEWVER = re.compile(r"^/playbooks/([^/]+)/newversion$")

    class Handler(BaseHTTPRequestHandler):
        # --- helpers ----------------------------------------------------
        def _html(self, code: int, body_html: str) -> None:
            body = _page("Playbook authoring", body_html)
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, location: str) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.end_headers()

        def _form(self) -> dict[str, str]:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8") if length else ""
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        def _require(self, role_value: str, permission: Permission) -> bool:
            try:
                role = Role(role_value)
            except ValueError:
                self._html(403, f"<p class='err'>Unknown role '{_esc(role_value)}'.</p>")
                return False
            if not has_permission(role, permission):
                self._html(403, f"<p class='err'>Role '{_esc(role_value)}' lacks "
                                f"{permission.value}.</p>")
                return False
            return True

        def log_message(self, *args) -> None:
            pass

        # --- routing ----------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/", "/playbooks"):
                return self._list()
            if self.path == "/playbooks/new":
                return self._html(200, "<h1>New playbook (draft)</h1>"
                                  + _template_form(None, "/playbooks", "Create draft", id_editable=True))
            m = R_EDIT.match(self.path)
            if m:
                return self._edit_form(m.group(1), int(m.group(2)))
            m = R_VIEW.match(self.path)
            if m:
                return self._view(m.group(1), int(m.group(2)))
            self._html(404, "<p class='err'>Not found.</p>")

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/playbooks":
                return self._create()
            m = R_EDIT.match(self.path)
            if m:
                return self._save(m.group(1), int(m.group(2)))
            m = R_ACTION.match(self.path)
            if m:
                return self._action(m.group(1), int(m.group(2)), m.group(3))
            m = R_NEWVER.match(self.path)
            if m:
                return self._new_version(m.group(1))
            self._html(404, "<p class='err'>Not found.</p>")

        # --- views ------------------------------------------------------
        def _list(self) -> None:
            rows = []
            for t in sorted(repo.list(), key=lambda x: (x.playbook_id, x.version)):
                view = f"/playbooks/{t.playbook_id}/{t.version}"
                rows.append(
                    f"<tr><td><a href='{view}'>{_esc(t.playbook_id)}</a></td>"
                    f"<td>{t.version}</td><td>{_esc(t.title)}</td>"
                    f"<td class='state {t.state.value}'>{t.state.value}</td>"
                    f"<td>{_esc(', '.join(t.binds_plugin_ids or t.binds_cve_ids or t.binds_severities))}</td></tr>")
            body = (f"<h1>Playbooks ({len(repo.list())})</h1>"
                    f"<p><a class='btn' href='/playbooks/new'>+ New playbook</a></p>"
                    f"<table><tr><th>ID</th><th>Ver</th><th>Title</th><th>State</th><th>Binds</th></tr>"
                    f"{''.join(rows)}</table>")
            self._html(200, body)

        def _view(self, pid: str, ver: int) -> None:
            try:
                t = repo.get(pid, ver)
            except KeyError:
                return self._html(404, "<p class='err'>Playbook not found.</p>")
            can_edit = t.state is PlaybookState.DRAFT
            actions = []
            if t.state is PlaybookState.DRAFT:
                actions.append(self._action_form(pid, ver, "submit", "Submit for review"))
            if t.state in (PlaybookState.DRAFT, PlaybookState.IN_REVIEW):
                actions.append(self._action_form(pid, ver, "publish", "Publish", warn=True))
            if t.state in (PlaybookState.PUBLISHED, PlaybookState.ARCHIVED):
                actions.append(
                    f"<form class='inline' method='post' action='/playbooks/{pid}/newversion'>"
                    f"<input type='hidden' name='actor' value='author'>"
                    f"<button class='btn' type='submit'>New draft version</button></form>")
            edit_link = (f"<p><a href='/playbooks/{pid}/{ver}/edit'>Edit draft</a></p>"
                         if can_edit else "")
            body = (f"<h1>{_esc(t.title)} <span class='muted'>({_esc(pid)} v{ver})</span></h1>"
                    f"<p class='state {t.state.value}'>state: {t.state.value} · "
                    f"updated_by: {_esc(t.updated_by)}</p>{edit_link}"
                    f"<h2>Root cause</h2><p>{_esc(t.root_cause)}</p>"
                    f"<h2>Impact</h2><p>{_esc(t.impact)}</p>"
                    f"<h2>Fix steps</h2><ol>{''.join(f'<li>{_esc(s)}</li>' for s in t.fix_steps)}</ol>"
                    f"<h2>Rollback</h2><ol>{''.join(f'<li>{_esc(s)}</li>' for s in t.rollback_steps)}</ol>"
                    f"<h2>Binds</h2><p>plugins: {_esc(', '.join(t.binds_plugin_ids))}<br>"
                    f"cves: {_esc(', '.join(t.binds_cve_ids))}<br>"
                    f"severities: {_esc(', '.join(t.binds_severities))}</p>"
                    f"<hr><p>{''.join(actions)}</p>")
            self._html(200, body)

        def _edit_form(self, pid: str, ver: int) -> None:
            try:
                t = repo.get(pid, ver)
            except KeyError:
                return self._html(404, "<p class='err'>Playbook not found.</p>")
            if t.state is not PlaybookState.DRAFT:
                return self._html(400, "<p class='err'>Only DRAFT playbooks are editable. "
                                       "Create a new version instead.</p>")
            self._html(200, f"<h1>Edit {_esc(pid)} v{ver}</h1>"
                       + _template_form(t, f"/playbooks/{pid}/{ver}/edit", "Save draft", id_editable=False))

        def _action_form(self, pid: str, ver: int, action: str, label: str, warn: bool = False) -> str:
            cls = "btn warn" if warn else "btn"
            hint = " (must differ from author)" if action == "publish" else ""
            return (f"<form class='inline' method='post' action='/playbooks/{pid}/{ver}/{action}'>"
                    f"<input type='text' name='actor' placeholder='actor{hint}'> {_role_select()} "
                    f"<button class='{cls}' type='submit'>{label}</button></form> ")

        # --- mutations --------------------------------------------------
        def _template_from_form(self, form: dict, playbook_id: str, version: int) -> PlaybookTemplate:
            return PlaybookTemplate(
                playbook_id=playbook_id, title=form.get("title", ""), version=version,
                state=PlaybookState.DRAFT,
                binds_plugin_ids=_split_csv(form.get("binds_plugin_ids", "")),
                binds_cve_ids=_split_csv(form.get("binds_cve_ids", "")),
                binds_severities=_split_csv(form.get("binds_severities", "")),
                root_cause=form.get("root_cause", ""), impact=form.get("impact", ""),
                fix_steps=_split_lines(form.get("fix_steps", "")),
                pre_checks=_split_lines(form.get("pre_checks", "")),
                post_validation=_split_lines(form.get("post_validation", "")),
                rollback_steps=_split_lines(form.get("rollback_steps", "")),
                est_downtime=form.get("est_downtime", "unknown"),
                risk_notes=form.get("risk_notes", ""),
                updated_by=form.get("actor") or "author",
            )

        def _create(self) -> None:
            form = self._form()
            if not self._require(form.get("role", ""), Permission.MANAGE_POLICY):
                return
            pid = (form.get("playbook_id") or "").strip()
            if not pid:
                return self._html(400, "<p class='err'>playbook_id is required.</p>")
            t = self._template_from_form(form, pid, version=1)
            repo.save(t)
            self._redirect(f"/playbooks/{pid}/1")

        def _save(self, pid: str, ver: int) -> None:
            form = self._form()
            if not self._require(form.get("role", ""), Permission.MANAGE_POLICY):
                return
            try:
                existing = repo.get(pid, ver)
            except KeyError:
                return self._html(404, "<p class='err'>Playbook not found.</p>")
            if existing.state is not PlaybookState.DRAFT:
                return self._html(400, "<p class='err'>Only DRAFT playbooks are editable.</p>")
            repo.save(self._template_from_form(form, pid, ver))
            self._redirect(f"/playbooks/{pid}/{ver}")

        def _action(self, pid: str, ver: int, action: str) -> None:
            form = self._form()
            actor = (form.get("actor") or "").strip()
            if not actor:
                return self._html(400, "<p class='err'>actor is required.</p>")
            perm = Permission.MANAGE_POLICY
            if not self._require(form.get("role", ""), perm):
                return
            try:
                if action == "submit":
                    repo.submit_for_review(pid, ver, actor)
                else:  # publish
                    repo.publish(pid, ver, actor)
            except (ValueError, KeyError) as exc:
                return self._html(400, f"<p class='err'>{_esc(exc)}</p>")
            except PermissionError as exc:
                return self._html(403, f"<p class='err'>{_esc(exc)}</p>")
            self._redirect(f"/playbooks/{pid}/{ver}")

        def _new_version(self, pid: str) -> None:
            form = self._form()
            actor = (form.get("actor") or "author").strip()
            try:
                t = repo.new_version(pid, actor)
            except KeyError:
                return self._html(404, "<p class='err'>Playbook not found.</p>")
            self._redirect(f"/playbooks/{pid}/{t.version}")

    return Handler


def serve_ui(repo: PlaybookRepository, host: str = "127.0.0.1", port: int = 8600) -> ThreadingHTTPServer:
    """Create (not start) the authoring UI server. Caller runs serve_forever()."""
    return ThreadingHTTPServer((host, port), make_handler(repo))
