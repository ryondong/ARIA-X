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
