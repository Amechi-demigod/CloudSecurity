#!/usr/bin/env python3
"""Fake GitHub API + GHCR registry for testing `cnapp-ctl update` without --tag (CI only).

    python3 fake_github.py --port 18081 --state state.json &
    sudo env CNAPP_GITHUB_API=http://127.0.0.1:18081/api CNAPP_REGISTRY_API=http://127.0.0.1:18081 cnapp-ctl update

The state file is re-read on every request, so a test can change it while
cnapp-ctl is waiting:

    {"commits": ["<sha newest>", "<sha older>", ...],      # main, newest first
     "published": ["<sha>", ...],                          # tags with backend+frontend images
     "runs": {"<sha>": {"status": "in_progress", "conclusion": null}}}

Endpoints: GET /api/repos/O/R/commits, GET /api/repos/O/R/actions/runs?head_sha=,
GET /token, HEAD|GET /v2/<prefix>/cloudsecurity-<svc>/manifests/<tag>.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

STATE = ""


def state() -> dict:
    with open(STATE, encoding="utf-8") as f:
        return json.load(f)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: object | None = None, headers: dict | None = None) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        st = state()
        if re.fullmatch(r"/api/repos/[^/]+/[^/]+/commits", u.path):
            n = int(q.get("per_page", ["30"])[0])
            return self._send(200, [{"sha": s, "commit": {"tree": {"sha": "0" * 40}}, "parents": []}
                                    for s in st.get("commits", [])[:n]])
        if re.fullmatch(r"/api/repos/[^/]+/[^/]+/actions/runs", u.path):
            sha = q.get("head_sha", [""])[0]
            runs = []
            if sha in st.get("runs", {}):
                r = st["runs"][sha]
                runs.append({"name": "CI", "head_sha": sha, "event": "push", "status": r.get("status"),
                             "conclusion": r.get("conclusion"),
                             "html_url": f"https://github.invalid/actions/runs/{sha[:8]}"})
            return self._send(200, {"total_count": len(runs), "workflow_runs": runs})
        if u.path == "/token":
            return self._send(200, {"token": "fake-registry-token"})
        m = re.fullmatch(r"/v2/[^/]+/cloudsecurity-(backend|frontend)/manifests/([^/]+)", u.path)
        if m:
            if self.headers.get("Authorization") != "Bearer fake-registry-token":
                return self._send(401, {"errors": [{"code": "UNAUTHORIZED"}]})
            if m.group(2) in st.get("published", []):
                digest = "sha256:" + hashlib.sha256(f"{m.group(1)}:{m.group(2)}".encode()).hexdigest()
                return self._send(200, {"schemaVersion": 2}, {"Docker-Content-Digest": digest})
            return self._send(404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]})
        return self._send(404, {"message": "Not Found"})

    def log_message(self, fmt: str, *args) -> None:
        print("fake-github:", fmt % args, flush=True)


def main() -> None:
    global STATE
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=18081)
    p.add_argument("--state", required=True)
    a = p.parse_args()
    STATE = a.state
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
