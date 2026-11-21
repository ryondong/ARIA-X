"""Auth-neighbourhood tool tests, run against the bundled lab app.

These are the acceptance tests for the capability the skill claims: session
continuity, differential detection, JWT analysis, route mining, artifact
recovery, code enumeration and object-reference walking. If one of these breaks,
the corresponding skill section is a lie until it is fixed.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "lab"))

import lab_app  # noqa: E402
from aria_x.tools import challenge as chal  # noqa: E402

from aria_x.config import AriaXConfig, SandboxConfig, ScopeConfig  # noqa: E402
from aria_x.events import EventBus  # noqa: E402
from aria_x.models import Project  # noqa: E402
from aria_x.store import Store  # noqa: E402
from aria_x.tools.base import ToolContext  # noqa: E402
from aria_x.tools.builtin import build_registry  # noqa: E402
from aria_x.tools.sandbox import MockSandbox  # noqa: E402
from aria_x.tools.scope import Scope  # noqa: E402


class AuthToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        lab_app.build_fixtures()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), lab_app.Handler)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        # keep the suite fast: stealth stays ON, its delays are scaled right down
        __import__("os").environ.setdefault("ARIAX_STEALTH_SCALE", "0.02")
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name) / "work"
        self.workdir.mkdir(parents=True, exist_ok=True)
        config = AriaXConfig()
        config.scope = ScopeConfig(authorized=True, targets=["127.0.0.1"], allow_loopback=True,
                                   allow_private=True, max_rps=2000.0)
        config.sandbox = SandboxConfig(backend="mock", max_output=4000, timeout=5)
        project = Project.new("auth-tests", "Prove the auth tools work")
        self.store = Store(":memory:")
        self.store.create_project(project)
        self.ctx = ToolContext(project=project, run_id="r1", task_id="t1", agent="tester",
                               role="worker", store=self.store, config=config,
                               events=EventBus(), scope=Scope(config.scope),
                               sandbox=MockSandbox(config.sandbox, self.workdir),
                               workdir=self.workdir)
        self.registry = build_registry(self.ctx)
        lab_app.ATTEMPTS.clear()
        lab_app.SESSIONS.clear()
        lab_app.RESET_CODES.clear()

    def tearDown(self) -> None:
        # a browser left running holds the profile and ~9 chrome processes
        try:
            from aria_x.tools import browser
            browser.shutdown(self.workdir)
        except Exception:  # noqa: BLE001 - teardown must not mask the real failure
            pass
        self.store.close()
        self._tmp.cleanup()

    def run_tool(self, tool: str, **args: object):
        result = self.registry.execute(tool, args, self.ctx)
        self.assertFalse(not result.ok and "unknown tool" in result.error, result.error)
        return result

    # -- session + authz -------------------------------------------------

    def test_login_captures_session_and_reads_another_object(self):
        opened = self.run_tool("http_session", action="open", name="alice",
                               url=f"{self.base}/login", method="POST",
                               body="username=alice&password=alicepw1")
        self.assertTrue(opened.ok, opened.error)
        self.assertTrue(opened.data["response"]["set_cookie"])
        self.assertGreaterEqual(opened.data["cookies"], 1)
        own = self.run_tool("http_session", action="send", name="alice",
                            url=f"{self.base}/account/1")
        self.assertEqual(own.data["response"]["status"], 200)
        self.assertIn("alice", own.data["response"]["excerpt"])
        # L3: the id is not bound to the session, so id=2 is readable too.
        other = self.run_tool("http_session", action="send", name="alice",
                              url=f"{self.base}/account/2")
        self.assertEqual(other.data["response"]["status"], 200)
        self.assertIn("bob", other.data["response"]["excerpt"])

    def test_session_without_login_is_redirected(self):
        anon = self.run_tool("http_session", action="open", name="anon",
                             url=f"{self.base}/account/1")
        self.assertEqual(anon.data["response"]["status"], 302)
        self.assertIn("/login", anon.data["response"]["location"])

    def test_session_capture_lifts_token_from_json(self):
        got = self.run_tool("http_session", action="open", name="tok",
                            url=f"{self.base}/api/token?user=alice")
        token = json.loads(got.data["response"]["excerpt"].replace(" ", ""))["token"]
        logged = self.run_tool("http_session", action="open", name="bearer",
                               url=f"{self.base}/api/token?user=alice",
                               capture=[{"from": "json", "path": "token",
                                         "as_header": "Authorization", "prefix": "Bearer "}])
        self.assertTrue(logged.data["captured_headers"])
        me = self.run_tool("http_session", action="send", name="bearer",
                           url=f"{self.base}/api/me")
        self.assertEqual(me.data["response"]["status"], 200)
        self.assertIn("alice", me.data["response"]["excerpt"])

    # -- challenge detection ---------------------------------------------

    def test_detect_names_the_wall_and_its_kind(self):
        wall = chal.detect(200, {}, "<title>Just a moment...</title><div class='g-recaptcha' "
                                    "data-sitekey='sitekey-abc123'></div>")
        # the wall is Cloudflare's, but the thing you can actually solve is the widget
        self.assertEqual(wall["wall_vendor"], "cloudflare")
        self.assertEqual(wall["vendor"], "recaptcha")
        self.assertEqual(wall["kind"], "captcha")
        self.assertEqual(wall["sitekey"], "sitekey-abc123")

    def test_detect_ignores_a_clean_page_and_calls_out_a_captcha(self):
        self.assertIsNone(chal.detect(200, {}, "<h1>hello</h1>"))
        self.assertEqual(chal.detect(200, {}, "<div class='h-captcha'></div>")["kind"], "captcha")
        self.assertEqual(chal.detect(429, {}, "slow down")["kind"], "rate-limit")

    def test_captcha_wall_is_reported_blocked_not_absent(self):
        result = self.run_tool("code_probe", url=f"{self.base}/secure/{{}}", length=2,
                               max_attempts=20, match=r'"ok": ?true')
        self.assertTrue(result.ok, result.error)
        self.assertTrue(result.data["blocked"])
        self.assertEqual(result.data["found"], [])
        self.assertIn("BLOCKED", result.text)

    def test_solver_token_clears_the_wall_and_the_code_is_found(self):
        lab_app.ATTEMPTS.clear()
        old = __import__("os").environ.get("ARIAX_SOLVER_URL")
        __import__("os").environ["ARIAX_SOLVER_URL"] = f"{self.base}/solver"
        try:
            result = self.run_tool("code_probe", url=f"{self.base}/secure/{{}}", length=2,
                                   max_attempts=100, match=r'"ok": ?true', token_from="solver",
                                   token_in="query")
        finally:
            if old is None:
                __import__("os").environ.pop("ARIAX_SOLVER_URL", None)
            else:
                __import__("os").environ["ARIAX_SOLVER_URL"] = old
        self.assertEqual([row["code"] for row in result.data["found"]], ["42"])
        self.assertFalse(result.data["blocked"])

    def test_vault_token_beats_the_wall_too(self):
        self.run_tool("vault", action="put", name="cap", value="tok-sitekey-secure")
        result = self.run_tool("code_probe", url=f"{self.base}/secure/{{}}", length=2,
                               max_attempts=100, match=r'"ok": ?true',
                               token_from="vault:cap", token_in="query")
        self.assertEqual([row["code"] for row in result.data["found"]], ["42"])

    # -- differential ----------------------------------------------------

    def test_auth_presence_family_exposes_the_slash_bypass(self):
        result = self.run_tool("http_matrix", url=f"{self.base}/admin", family="auth_presence")
        self.assertTrue(result.ok, result.error)
        rows = {row["label"]: row for row in result.data["matrix"]}
        self.assertEqual(rows["baseline"]["status"], 302)
        self.assertEqual(rows["path_trailing_slash"]["status"], 200)
        self.assertEqual(rows["path_trailing_slash"]["verdict"], "DIFF")
        self.assertTrue(any("status" in s for s in rows["path_trailing_slash"]["signals"]))

    def test_header_trust_family_exposes_forwarded_for(self):
        result = self.run_tool("http_matrix", url=f"{self.base}/api/admin/users",
                               family="header_trust")
        self.assertTrue(result.ok, result.error)
        rows = {row["label"]: row for row in result.data["matrix"]}
        self.assertEqual(rows["baseline"]["status"], 401)
        self.assertEqual(rows["xff_loopback"]["status"], 200)
        self.assertEqual(rows["original_url_root"]["status"], 200)

    def test_custom_variants_and_token_substitution(self):
        result = self.run_tool("http_matrix", url=f"{self.base}/account/{{}}",
                               variants=[{"label": "one", "path": "/account/1"},
                                         {"label": "two", "path": "/account/2"}],
                               token="1")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(len(result.data["matrix"]), 3)

    # -- jwt -------------------------------------------------------------

    def test_jwt_flags_and_cracks_the_weak_secret(self):
        token = json.loads(self.run_tool("http_request", url=f"{self.base}/api/token?user=alice")
                           .data["body_excerpt"])["token"]
        result = self.run_tool("jwt_inspect", token=token, crack=True)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.data["cracked_secret"], "secret")
        self.assertTrue(any("privilege-ish" in flag for flag in result.data["flags"]))

    def test_jwt_forge_with_cracked_secret_is_accepted_by_the_target(self):
        token = json.loads(self.run_tool("http_request", url=f"{self.base}/api/token?user=alice")
                           .data["body_excerpt"])["token"]
        forged = self.run_tool("jwt_inspect", token=token, secret="secret",
                              forge={"claims": {"sub": "alice", "role": "admin"}})
        self.assertTrue(forged.data["forged"], forged.text)
        me = self.run_tool("http_request", url=f"{self.base}/api/me",
                           headers={"Authorization": f"Bearer {forged.data['forged']}"})
        self.assertEqual(me.data["status"], 200)
        self.assertIn("admin", me.data["body_excerpt"])

    def test_jwt_alg_none_forge(self):
        result = self.run_tool("jwt_inspect", token="a.b.c",
                               forge={"header": {"alg": "none"}, "claims": {"sub": "root"}})
        self.assertTrue(result.data["forged"].endswith("."))

    # -- mining ----------------------------------------------------------

    def test_route_mine_returns_paths_secrets_and_maps(self):
        result = self.run_tool("route_mine", url=f"{self.base}/")
        self.assertTrue(result.ok, result.error)
        inventory = result.data["inventory"]
        self.assertIn("/api/v1/", inventory["paths"])
        self.assertTrue(any("stripe" in s for s in inventory["secrets"]))
        self.assertTrue(result.data["sourcemaps"] or inventory["sourcemaps"])
        self.assertIn("src/config.ts", inventory["paths"])

    # -- artifacts -------------------------------------------------------

    def test_artifact_probe_hits_env_git_and_dump(self):
        result = self.run_tool("artifact_probe", base_url=self.base, tier="s,m")
        self.assertTrue(result.ok, result.error)
        verdicts = {row["path"]: row["verdict"] for row in result.data["rows"]}
        self.assertEqual(verdicts[".env"], "HIT")
        self.assertEqual(verdicts[".git/config"], "HIT")
        self.assertEqual(verdicts["backup.sql"], "HIT")
        self.assertEqual(verdicts["graphql"], "SOFT404")  # not served by the lab

    def test_artifact_hit_carries_a_hash_and_evidence_path(self):
        result = self.run_tool("artifact_probe", base_url=self.base, paths=[".env"])
        row = next(r for r in result.data["hit_rows"] if r["path"] == ".env")
        self.assertEqual(row["sniff"], "env-file")
        self.assertEqual(Path(row["evidence_path"]).parts[0], "evidence")

    # -- enumeration -----------------------------------------------------

    def test_code_probe_finds_the_two_digit_code(self):
        result = self.run_tool("code_probe", url=f"{self.base}/otp/{{}}", length=2,
                               max_attempts=100, match=r'"ok": ?true', xff_rotate=True,
                               stop_on_match=True)
        self.assertTrue(result.ok, result.error)
        self.assertEqual([row["code"] for row in result.data["found"]], ["42"])
        self.assertGreater(result.data["attempts"], 20)

    def test_code_probe_reports_rate_limit_as_no_candidate(self):
        result = self.run_tool("code_probe", url=f"{self.base}/otp/{{}}", length=2,
                               max_attempts=10, xff_rotate=False)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.data["found"], [])
        self.assertIn("candidate", result.text + "  ")

    def test_id_walk_flags_403_and_outliers(self):
        self.run_tool("http_session", action="open", name="alice", url=f"{self.base}/login",
                      method="POST", body="username=alice&password=alicepw1")
        result = self.run_tool("id_walk", url=f"{self.base}/account/{{}}", session="alice",
                               start=1, count=5)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.data["probed"], 5)

    def test_import_action_seeds_a_jar_from_a_browser_cookie(self):
        opened = self.run_tool("http_session", action="open", name="src", url=f"{self.base}/login",
                               method="POST", body="username=alice&password=alicepw1")
        self.assertTrue(opened.ok, opened.error)
        sid = next(c.value for c in self.registry.execute("http_session",
                                                          {"action": "list"}, self.ctx).data["sessions"]
                   if False) if False else None
        jar = self.ctx and None
        # read the sid straight from the live session jar
        from aria_x.tools.auth import _load_jar
        sid = next(c.value for c in _load_jar(self.ctx, "src"))
        imported = self.run_tool("http_session", action="import", name="browser",
                                 url=f"{self.base}/account/1", cookies=f"sid={sid}")
        self.assertTrue(imported.ok, imported.error)
        read = self.run_tool("http_session", action="send", name="browser",
                             url=f"{self.base}/account/2")
        self.assertEqual(read.data["response"]["status"], 200)
        self.assertIn("bob", read.data["response"]["excerpt"])

    def test_curl_client_reports_its_transport(self):
        from aria_x.tools.sandbox import build_sandbox
        import shutil
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        self.ctx.sandbox = build_sandbox(self.ctx.config.sandbox.__class__(
            backend="local", timeout=10, max_output=4000), self.workdir)
        result = self.run_tool("http_matrix", url=f"{self.base}/admin", family="path_tricks",
                               client="curl")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.data["baseline"]["status"], 302)
        rows = {row["label"]: row for row in result.data["matrix"]}
        self.assertEqual(rows["path_trailing_slash"]["status"], 200)

    # -- JWT signing lane -----------------------------------------------

    def _lab_keys(self) -> tuple[str, str]:
        keys = REPO / "lab" / "fixtures" / "keys"
        return (keys / "rsa.pem").read_text(), (keys / "rsa.pub").read_text()

    def test_rs256_signed_with_the_private_key_is_accepted(self):
        private, _public = self._lab_keys()
        signed = self.run_tool("jwt_sign", alg="RS256", claims={"sub": "alice", "role": "admin"},
                               key_pem=private, verify=True)
        self.assertTrue(signed.data["verdict"]["valid"], signed.text)
        me = self.run_tool("http_request", url=f"{self.base}/api/rs/me",
                           headers={"Authorization": f"Bearer {signed.data['token']}"})
        self.assertEqual(me.data["status"], 200)
        self.assertIn("admin", me.data["body_excerpt"])

    def test_algorithm_confusion_hs256_over_the_public_key(self):
        _private, public = self._lab_keys()
        forged = self.run_tool("jwt_sign", alg="HS256", claims={"sub": "alice", "role": "admin"},
                               key_pem=public, verify=True)
        self.assertIn("confusion", forged.data["note"])
        me = self.run_tool("http_request", url=f"{self.base}/api/rs/me",
                           headers={"Authorization": f"Bearer {forged.data['token']}"})
        self.assertEqual(me.data["status"], 200, "confused token refused")
        self.assertIn("admin", me.data["body_excerpt"])

    def test_es256_round_trip_and_tamper_detection(self):
        from aria_x.tools import jwtkeys
        ec = (REPO / "lab" / "fixtures" / "keys" / "ec.pem").read_text()
        signed = jwtkeys.sign("ES256", {"sub": "alice"}, key_pem=ec)
        self.assertTrue(jwtkeys.verify(signed["token"], key_pem=ec)["valid"])
        tampered = signed["token"][:-3] + "AAA"
        self.assertFalse(jwtkeys.verify(tampered, key_pem=ec)["valid"])
        self.assertEqual(signed["token"].count("."), 2)
        self.assertEqual(len(jwtkeys._b64d(signed["token"].split(".")[2])), 64)

    def test_none_alg_is_unsigned(self):
        signed = self.run_tool("jwt_sign", alg="none", claims={"sub": "root"})
        self.assertTrue(signed.data["token"].endswith("."))

    # -- browser lane ----------------------------------------------------

    def _browser(self):
        from aria_x.tools import browser
        if not browser.browser_path():
            self.skipTest("no chrome/chromium installed")
        return browser

    def test_urllib_sees_the_wall_but_the_browser_clears_it(self):
        browser = self._browser()
        raw = self.run_tool("http_request", url=f"{self.base}/js/42")
        self.assertIn("Just a moment", raw.data["body_excerpt"])
        self.assertEqual(raw.data["status"], 200)   # a wall is a 200
        opened = self.run_tool("browser_session", action="open", url=f"{self.base}/js/42",
                               wait=20, import_to="jsess", settle_ms=1200)
        self.assertTrue(opened.ok, opened.error)
        self.assertTrue(opened.data["cleared"], opened.text)
        self.assertIn("true", opened.data["excerpt"])
        self.assertIn("jsok", opened.data["imported_cookies"])
        self.run_tool("browser_session", action="close")

    def test_browser_cookie_hands_the_work_back_to_plain_http(self):
        self._browser()
        opened = self.run_tool("browser_session", action="open", url=f"{self.base}/js/42",
                               wait=20, import_to="handoff", settle_ms=1200)
        self.assertTrue(opened.data["cleared"], opened.text)
        found = self.run_tool("code_probe", url=f"{self.base}/js/{{}}", length=2,
                              max_attempts=100, match=r'"ok": ?true', session="handoff")
        self.assertEqual([row["code"] for row in found.data["found"]], ["42"])
        self.assertFalse(found.data["blocked"])
        self.run_tool("browser_session", action="close")

    # -- vault -----------------------------------------------------------

    def test_vault_masks_by_default_and_reveals_on_request(self):
        self.run_tool("vault", action="put", name="cookie", value="sid=abc123456789xyz")
        masked = self.run_tool("vault", action="get", name="cookie")
        self.assertNotIn("abc123456789xyz", masked.text)
        revealed = self.run_tool("vault", action="get", name="cookie", reveal=True)
        self.assertEqual(revealed.data["value"], "sid=abc123456789xyz")

    def test_vault_file_is_under_workdir_state(self):
        self.run_tool("vault", action="put", name="k", value="v")
        self.assertTrue((self.workdir / "state" / "vault.json").exists())


if __name__ == "__main__":
    unittest.main()
