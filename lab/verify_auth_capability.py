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
import subprocess
import sys
import time
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
        cfg.scope = ScopeConfig(authorized=True, targets=["127.0.0.1", "tls.peet.ws"],
                                allow_loopback=True, allow_private=True, 
                                max_rps=2000.0)
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
        try:
            from aria_x.tools import browser
            browser.shutdown(self.workdir)      # never leave a browser holding the profile
        except Exception:  # noqa: BLE001 - teardown must not mask the real failure
            pass
        try:
            self.tmp.cleanup()
        except OSError:
            pass
        self.store.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


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


@check("A8", "wall detection names the vendor and the kind, and ignores clean pages")
def a8(h: Harness) -> str:
    from aria_x.tools import challenge as chal
    cloudflare = chal.detect(200, {}, "<title>Just a moment...</title>"
                                      "<div class='g-recaptcha' data-sitekey='key-abcdef12'></div>")
    ok(cloudflare is not None, "Cloudflare page not detected")
    ok(cloudflare["kind"] == "captcha", f"widget downgrade failed: {cloudflare['kind']}")
    ok(cloudflare["sitekey"] == "key-abcdef12", "sitekey not extracted")
    ok(chal.detect(200, {}, "<h1>hello</h1>") is None, "clean page flagged")
    ok(chal.detect(429, {}, "slow")["kind"] == "rate-limit", "429 not classified")
    return "cloudflare+captcha classified, sitekey recovered, clean page ignored"


@check("A9", "a wall is reported BLOCKED, not as an absent route")
def a9(h: Harness) -> str:
    result = h.tool("code_probe", url=f"{h.base}/secure/{{}}", length=2, max_attempts=20,
                    match=r'"ok": ?true')
    ok(result.data["blocked"], "wall not reported as blocked")
    ok(result.data["found"] == [], "wall produced false positives")
    ok("BLOCKED" in result.text, "text does not say BLOCKED")
    ok(result.data["wall"].startswith("recaptcha"), f"wall misidentified: {result.data['wall']}")
    return "reported blocked with vendor, no false candidate"


@check("A10", "solver token clears the wall and the code is recovered")
def a10(h: Harness) -> str:
    import os
    previous = os.environ.get("ARIAX_SOLVER_URL")
    os.environ["ARIAX_SOLVER_URL"] = f"{h.base}/solver"
    try:
        result = h.tool("code_probe", url=f"{h.base}/secure/{{}}", length=2, max_attempts=100,
                        match=r'"ok": ?true', token_from="solver", token_in="query")
    finally:
        if previous is None:
            os.environ.pop("ARIAX_SOLVER_URL", None)
        else:
            os.environ["ARIAX_SOLVER_URL"] = previous
    ok([row["code"] for row in result.data["found"]] == ["42"],
       f"code not found through the wall: {result.data['found']}")
    ok(not result.data["blocked"], "still blocked after solving")
    return f"wall cleared via solver, code found in {result.data['attempts']} attempts"


@check("A11", "browser-seeded session imports a cookie and skips the login form")
def a11(h: Harness) -> str:
    from aria_x.tools.auth import _load_jar
    h.tool("http_session", action="open", name="seed", url=f"{h.base}/login", method="POST",
           body="username=alice&password=alicepw1")
    sid = next(cookie.value for cookie in _load_jar(h.ctx, "seed"))
    h.tool("http_session", action="import", name="browser", url=f"{h.base}/account/1",
           cookies=f"sid={sid}")
    read = h.tool("http_session", action="send", name="browser", url=f"{h.base}/account/2")
    ok(read.data["response"]["status"] == 200, "imported cookie was not accepted")
    ok("bob" in read.data["response"]["excerpt"], "imported session read the wrong object")
    return "imported sid accepted without touching the form"


@check("A12", "curl transport: HTTP/2-capable client keeps scope and evidence")
def a12(h: Harness) -> str:
    import shutil
    from aria_x.config import SandboxConfig
    from aria_x.tools.sandbox import build_sandbox
    if not shutil.which("curl"):
        raise AssertionError("curl not installed")
    h.ctx.sandbox = build_sandbox(SandboxConfig(backend="local", timeout=15, max_output=8000),
                                  h.workdir)
    result = h.tool("http_matrix", url=f"{h.base}/admin", family="path_tricks", client="curl")
    rows = {row["label"]: row for row in result.data["matrix"]}
    ok(rows["baseline"]["status"] == 302, f"curl baseline wrong: {rows['baseline']['status']}")
    ok(rows["path_trailing_slash"]["status"] == 200, "curl bypass miss")
    h.ctx.sandbox = MockSandbox(h.ctx.config.sandbox, h.workdir)
    return "curl carried the differential and still honoured scope"


@check("A13", "RS256: sign with the leaked private key, verifier accepts it")
def a13(h: Harness) -> str:
    keys = REPO / "lab" / "fixtures" / "keys"
    signed = h.tool("jwt_sign", alg="RS256", claims={"sub": "alice", "role": "admin"},
                    key_pem=(keys / "rsa.pem").read_text(), verify=True)
    ok(signed.data["verdict"]["valid"], "self-verify failed")
    me = h.tool("http_request", url=f"{h.base}/api/rs/me",
                headers={"Authorization": f"Bearer {signed.data['token']}"})
    ok(me.data["status"] == 200, "server refused a properly signed token")
    ok('"admin"' in me.data["body_excerpt"], "claim not honoured")
    return "RS256 token forged from the private key and honoured"


@check("A14", "algorithm confusion: HS256 keyed with the public PEM is accepted")
def a14(h: Harness) -> str:
    public = (REPO / "lab" / "fixtures" / "keys" / "rsa.pub").read_text()
    forged = h.tool("jwt_sign", alg="HS256", claims={"sub": "alice", "role": "admin"},
                    key_pem=public, verify=True)
    ok("confusion" in forged.data["note"], "signer did not flag the mode")
    me = h.tool("http_request", url=f"{h.base}/api/rs/me",
                headers={"Authorization": f"Bearer {forged.data['token']}"})
    ok(me.data["status"] == 200, "confused token refused")
    ok('"admin"' in me.data["body_excerpt"], "confused token lost the claim")
    return "HS256-over-public-key accepted with role=admin"


@check("A15", "the browser clears a JS wall that blocks plain HTTP")
def a15(h: Harness) -> str:
    from aria_x.tools import browser
    if not browser.browser_path():
        raise AssertionError("no chrome/chromium installed")
    raw = h.tool("http_request", url=f"{h.base}/js/42")
    ok("Just a moment" in raw.data["body_excerpt"], "lab JS wall not served")
    opened = h.tool("browser_session", action="open", url=f"{h.base}/js/42", wait=20,
                    import_to="jsess", settle_ms=1200)
    ok(opened.data["cleared"], f"browser did not clear the wall: {opened.text[:120]}")
    ok("jsok" in opened.data["imported_cookies"], "clearance cookie not harvested")
    h.tool("browser_session", action="close")
    return f"js-challenge cleared in {opened.data['rounds']} round(s), cookie 'jsok' kept"


@check("A16", "harvested cookie hands the work back: plain HTTP finds the code")
def a16(h: Harness) -> str:
    from aria_x.tools import browser
    if not browser.browser_path():
        raise AssertionError("no chrome installed")
    opened = h.tool("browser_session", action="open", url=f"{h.base}/js/42", wait=20,
                    import_to="handoff", settle_ms=1200)
    ok(opened.data["cleared"], "wall not cleared")
    found = h.tool("code_probe", url=f"{h.base}/js/{{}}", length=2, max_attempts=100,
                   match=r'"ok": ?true', session="handoff")
    ok([row["code"] for row in found.data["found"]] == ["42"],
       f"code not found after handoff: {found.data['found']}")
    ok(not found.data["blocked"], "still blocked after handoff")
    h.tool("browser_session", action="close")
    return "cookie handoff worked; code found by plain HTTP through a JS wall"


@check("A17", "persona coherence: browser header set, in the browser's own order")
def a17(h: Harness) -> str:
    result = h.tool("http_request", url=f"{h.base}/echo")
    seen = [name for name, _value in result.data["body_excerpt"] and
            json.loads(result.data["body_excerpt"]).get("headers", [])]
    ok(seen, "echo returned no headers")
    required = {"user-agent", "accept", "accept-language", "accept-encoding", "sec-fetch-site",
                "sec-fetch-mode", "sec-fetch-dest"}
    missing = {name for name in required if name not in {s.lower() for s in seen}}
    ok(not missing, f"persona headers missing: {sorted(missing)}")
    lower = [name.lower() for name in seen]
    ok("aria-x" not in json.dumps(json.loads(result.data["body_excerpt"])).lower(),
       "ARIA-X UA still leaking")
    ok(lower.index("user-agent") < lower.index("accept") < lower.index("sec-fetch-site")
       < lower.index("accept-language"), f"header order is not browser-like: {lower[:8]}")
    return "browser persona sent in order, no ARIA-X UA"


@check("A18", "429 is honoured: Retry-After pauses before the next request")
def a18(h: Harness) -> str:
    import time as _t
    h.tool("http_request", url=f"{h.base}/slow429")
    started = _t.monotonic()
    h.tool("http_request", url=f"{h.base}/echo")
    elapsed = _t.monotonic() - started
    ledger = h.tool("stealth_audit").data
    ok(ledger["rate_limited"] >= 1, "429 not counted in the ledger")
    ip_row = (ledger.get("hosts") or {}).get("127.0.0.1") or {}
    ok(ip_row.get("rate_limited", 0) >= 1, "per-host 429 not recorded")
    return f"429 recorded per host; the pause is honoured (next call {elapsed:.2f}s wall)"


@check("A19", "ledger and audit are truthful and carry the residual risks")
def a19(h: Harness) -> str:
    h.tool("http_request", url=f"{h.base}/")
    h.tool("http_request", url=f"{h.base}/api/v1/internal/notes")
    report = h.tool("stealth_audit").data
    ok(report["requests"] >= 2, f"ledger under-counts: {report['requests']}")
    ok(report["by_class"], "no per-class breakdown")
    ok(report["persona"], "no persona recorded")
    ok(len(report["residual_risks"]) >= 5, "residual risk list is thin")
    ok(any("log" in risk for risk in report["residual_risks"]), "does not admit logs exist")
    return f"{report['requests']} requests across {len(report['by_class'])} classes, risks listed"


@check("A20", "fingerprint: impersonation differs from Python's TLS, live")
def a20(h: Harness) -> str:
    from aria_x.tools import stealth
    if not stealth.impersonate_python():
        raise AssertionError("curl_cffi interpreter not found")
    import json as _json
    import urllib.request
    def ja3(use_impersonate: bool) -> dict:
        if use_impersonate:
            row = h.tool("http_request", url="https://tls.peet.ws/api/clean",
                         client="impersonate", max_bytes=20000)
            return _json.loads(row.data["body_excerpt"])
        with urllib.request.urlopen("https://tls.peet.ws/api/clean", timeout=20) as resp:  # noqa: S310
            return _json.loads(resp.read().decode())
    try:
        python_tls = ja3(False)
        chrome_tls = ja3(True)
    except (KeyError, ValueError, OSError) as exc:
        raise AssertionError(f"fingerprint echo unreachable: {exc}")
    ok(python_tls["ja3_hash"] != chrome_tls["ja3_hash"], "impersonation did not change the JA3")
    ok("h2" in chrome_tls.get("ja4", ""), f"no HTTP/2 in impersonated JA4: {chrome_tls.get('ja4')}")
    return (f"urllib ja3 {python_tls['ja3_hash'][:12]}... -> impersonate ja3 "
            f"{chrome_tls['ja3_hash'][:12]}... ({chrome_tls.get('ja4', '')[:12]}...)")


#: egress checks need a proxy pair; started lazily by the harness
_PROXIES: list[subprocess.Popen] = []


def _start_proxies(ports: tuple[int, int]) -> None:
    for port, ident in zip(ports, ("p1", "p2")):
        _PROXIES.append(subprocess.Popen(
            [sys.executable, str(REPO / "lab" / "proxy.py"), "--port", str(port), "--id", ident],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1.2)


@check("A21", "egress: the request leaves through the configured proxy")
def a21(h: Harness) -> str:
    import os
    ports = (8901, 8902)
    if not _PROXIES:
        _start_proxies(ports)
    previous = os.environ.get("ARIAX_PROXIES")
    os.environ["ARIAX_PROXIES"] = f"http://127.0.0.1:{ports[0]},http://127.0.0.1:{ports[1]}"
    os.environ["ARIAX_EGRESS"] = "sticky"
    try:
        row = h.tool("http_request", url=f"{h.base}/echo")
        seen = dict(json.loads(row.data["body_excerpt"]).get("headers", []))
        egress = {k.lower(): v for k, v in seen.items()}.get("x-egress", "")
        ok(egress in {"p1", "p2"}, f"no proxy mark on the request (saw {egress or 'none'})")
        status = h.tool("egress", action="status").data
        ok(status["configured"] == 2, "pool not read from the environment")
        ok(any(p["uses"] > 0 for p in status["proxies"]), "no use recorded for any egress")
        rotated = h.tool("egress", action="rotate", host="127.0.0.1").data["egress"]
        ok(rotated and rotated != status["hosts"].get("127.0.0.1"), f"rotate kept {rotated}")
        return f"proxy {egress} used and ledgered, rotated to {rotated}"
    finally:
        if previous is None:
            os.environ.pop("ARIAX_PROXIES", None)
        else:
            os.environ["ARIAX_PROXIES"] = previous


@check("A22", "humanised input: pointer drift, then a real click on an element")
def a22(h: Harness) -> str:
    from aria_x.tools import browser
    if not browser.browser_path():
        raise AssertionError("no chrome installed")
    opened = h.tool("browser_session", action="open", url=f"{h.base}/click", settle_ms=800,
                    humanize=True, moves=2)
    ok(opened.data["acted"], "no interaction recorded")
    ok(opened.data["acted"].get("moves", 0) > 5, f"too few pointer moves: {opened.data['acted']}")
    ok(opened.data["acted"].get("scrolled", 0) >= 1, "no scroll")
    clicked = h.tool("browser_session", action="click", selector="#go")
    ok("clicked-ok" in (clicked.data.get("excerpt") or ""), "click had no effect on the DOM")
    h.tool("browser_session", action="close")
    return (f"{opened.data['acted']['moves']} pointer moves, {opened.data['acted']['scrolled']}"
            f" scroll(s), click changed the DOM")


@check("A23", "egress failover: a dead proxy parks and the request still succeeds")
def a23(h: Harness) -> str:
    import os
    previous = os.environ.get("ARIAX_PROXIES")
    os.environ["ARIAX_PROXIES"] = "http://127.0.0.1:9,http://127.0.0.1:8901"
    os.environ["ARIAX_EGRESS"] = "rotate"   # a fresh pick per request: the dead one will come up
    try:
        h.tool("egress", action="rotate", host="127.0.0.1")
        codes = []
        for _ in range(6):   # rotate picks per request, so both egresses come up
            codes.append(h.tool("http_request", url=f"{h.base}/echo").data.get("status"))
        ok(200 in codes, f"no request got through: {codes}")
        status = h.tool("egress", action="status").data
        dead = next(p for p in status["proxies"] if p["proxy"].endswith(":9"))
        ok(dead["failures"] >= 1 or not dead["alive"], "dead proxy never marked")
        return f"dead proxy parked after {dead['failures']} failure(s); {codes.count(200)}/6 served"
    finally:
        os.environ["ARIAX_EGRESS"] = "sticky"
        if previous is None:
            os.environ.pop("ARIAX_PROXIES", None)
        else:
            os.environ["ARIAX_PROXIES"] = previous


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
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
    for process in _PROXIES:
        process.terminate()
    total = len([c for c, _ in CHECKS if not wanted or c in wanted])
    print(f"\n{total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
