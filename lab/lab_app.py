#!/usr/bin/env python3
"""ARIA-X auth lab — a deliberately broken little app on loopback.

Every defence in here is a *pattern* worth practising, not a realistic app: the
point is that each one has a single clean probe that exposes it, so a run can be
scored pass/fail. Loopback only, no dependencies, throwaway passwords.

Faults planted (see lab/README.md for the probe that proves each):

  L1  username enumeration by response differential      POST /login
  L2  auth-by-Cookie with no signature                   GET  /account/{id}
  L3  IDOR on the object id                              GET  /account/{id}
  L4  trailing-slash handler skips the role check        GET  /admin/
  L5  X-Forwarded-For trust on the admin API             GET  /api/admin/users
  L6  X-Original-URL trust                               GET  /api/admin/users
  L7  JWT HS256 with a weak secret + trusted role claim   GET /api/me
  L8  one-time reset code, no lockout, 4 digits          POST /reset/verify
  L9  reset code leaked in the response                  POST /reset
  L10 served .git, .env, dump and database               GET  /.git/HEAD ...
  L11 unsourced source map carrying a credential         GET  /static/app.js.map
  L12 unauthenticated export endpoint                    GET  /export
  L13 soft-404 (200 + "Not Found") masks real misses     GET  /nope
  L14 internal notes JSON with no auth                   GET  /api/v1/internal/notes
  L15 session cookie set before auth completes           GET  /login
  L16 captcha wall in front of a 2-digit code            GET  /secure/{code}
  L17 local solver stand-in (returns tok-<sitekey>)      POST /solver
  L18 RS256 JWT whose verifier trusts the header's alg   GET  /api/rs/me
  L19 JS challenge wall that sets a clearance cookie     GET  /js/{code}
  L20 header echo (order preserved) for persona checks   GET  /echo
  L21 429 with Retry-After for backoff checks            GET  /slow429
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import sqlite3
import sys
import base64
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
JWT_SECRET = "secret"
USERS = {
    "alice": {"password": "alicepw1", "role": "user", "id": 1},
    "bob": {"password": "bobpw2", "role": "user", "id": 2},
    "root": {"password": "rootpw3", "role": "admin", "id": 3},
}
RESET_CODES: dict[str, str] = {}
ATTEMPTS: dict[str, int] = {}
SESSIONS: dict[str, str] = {}
SOFT_404_BODY = b"<html><title>Not Found</title><p>The page you asked for is not here.</p></html>"

KEYS = FIXTURES / "keys"

# reuse the engine's own key math instead of a second copy of ASN.1 parsing
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from aria_x.tools import jwtkeys as _jk  # noqa: E402


def _pem(name: str) -> str:
    return (KEYS / name).read_text(encoding="utf-8")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_jwt(claims: dict) -> str:
    """HS256 with the lab's weak secret (the crackable one)."""
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def check_jwt(token: str) -> dict | None:
    try:
        head, body, sig = token.split(".")
    except ValueError:
        return None
    expected = b64(hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None


def rs256(claims: dict) -> str:
    return _jk.sign("RS256", claims, key_pem=_pem("rsa.pem"))["token"]


def verify_any(token: str) -> dict | None:
    """L18: the algorithm comes out of the token, and HS* is keyed with the PUBLIC pem."""
    try:
        head = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except (ValueError, TypeError, IndexError):
        return None
    alg = str(header.get("alg") or "").upper()
    if alg == "HS256":
        verdict = _jk.verify(token, hmac_secret=_pem("rsa.pub"))
    elif alg == "RS256":
        verdict = _jk.verify(token, key_pem=_pem("rsa.pub"))
    else:
        return None
    if not verdict.get("valid"):
        return None
    body = token.split(".")[1]
    try:
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "AriaLab/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # quiet
        return

    # -- plumbing ---------------------------------------------------------
    def cookies(self) -> SimpleCookie:
        raw = self.headers.get("Cookie", "")
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            pass
        return jar

    def send(self, status: int, body: bytes | str, ctype: str = "text/html; charset=utf-8",
             extra: dict[str, str] | None = None) -> None:
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def not_found(self) -> None:
        self.send(200, SOFT_404_BODY)  # L13: soft 404 on purpose

    def body_text(self) -> str:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def form(self) -> dict[str, str]:
        ctype = (self.headers.get("Content-Type") or "").lower()
        raw = getattr(self, "raw", "") or self.body_text()
        if "json" in ctype:
            try:
                return {str(k): str(v) for k, v in json.loads(raw or "{}").items()}
            except ValueError:
                return {}
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def client_ip(self) -> str:
        return (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()

    def user(self) -> str | None:
        return SESSIONS.get(self.cookies().get("sid").value if self.cookies().get("sid") else "")

    # -- routing ----------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send(204, b"", "text/plain", {"Allow": "GET, HEAD, POST, OPTIONS"})

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        # L4: strip a trailing slash segment for the admin console *after* the
        # equality check on the exact path, and forget to re-check the role.
        if path == "/admin/":
            return self.send(200, "<h1>Admin console</h1><p>mounted at the slash variant</p>")
        if path == "/":
            return self.send(200, (FIXTURES / "index.html").read_bytes())
        if path == "/login":
            # L15: session issued before authentication
            sid = hashlib.sha1(os.urandom(8)).hexdigest()[:12]
            SESSIONS.setdefault(sid, None)  # type: ignore[arg-type]
            return self.send(200, (FIXTURES / "login.html").read_bytes(),
                             extra={"Set-Cookie": f"sid={sid}; Path=/; HttpOnly"})
        if path == "/logout":
            return self.send(302, b"", extra={"Location": "/"})
        if path == "/admin":
            who = self.user()
            if not who:
                return self.send(302, b"", extra={"Location": "/login"})
            if USERS[who]["role"] != "admin":
                return self.send(403, "<h1>Forbidden</h1><p>admins only</p>")
            return self.send(200, "<h1>Admin console</h1><p>users: alice bob root</p>")
        if path == "/api/admin/users":
            # L5/L6: a proxy is trusted to say who we are
            trusted = (self.headers.get("X-Forwarded-For", "").startswith("127.")
                       or bool(self.headers.get("X-Original-URL"))
                       or bool(self.headers.get("X-Rewrite-URL")))
            if not trusted and not self.user():
                return self.send(401, '{"error":"unauthorized"}', "application/json")
            return self.send(200, json.dumps([{"id": u["id"], "user": n, "role": u["role"]}
                                              for n, u in USERS.items()]), "application/json")
        if path.startswith("/account/"):
            if not self.user():
                return self.send(302, b"", extra={"Location": "/login"})
            try:
                wanted = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self.not_found()
            return self.account(wanted)
        if path == "/api/me":
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            claims = check_jwt(token)
            if not claims:
                return self.send(401, '{"error":"bad token"}', "application/json")
            return self.send(200, json.dumps(claims), "application/json")
        if path == "/api/token":
            who = query.get("user", "alice")
            if who not in USERS:
                return self.send(404, '{"error":"no such user"}', "application/json")
            return self.send(200, json.dumps({"token": make_jwt(
                {"sub": who, "role": USERS[who]["role"], "exp": int(time.time()) + 600})}),
                "application/json")
        if path == "/export":
            return self.export(query.get("format", "csv"))
        if path == "/api/v1/internal/notes":
            return self.send(200, (FIXTURES / "notes.json").read_bytes(), "application/json")
        if path == "/swagger.json":
            return self.send(200, (FIXTURES / "swagger.json").read_bytes(), "application/json")
        if path == "/robots.txt":
            return self.send(200, (FIXTURES / "robots.txt").read_bytes(), "text/plain")
        if path == "/reset/verify":
            return self.verify_code(query.get("code", ""), json_body=False)
        if path.startswith("/otp/"):
            return self.otp(path.rsplit("/", 1)[1])
        if path.startswith("/secure/"):
            return self.secure(path.rsplit("/", 1)[1])
        if path == "/echo":
            return self.send(200, json.dumps({"headers": list(self.headers.items()),
                                              "path": self.path}), "application/json")
        if path == "/slow429":
            return self.send(429, '{"error":"slow down"}', "application/json",
                             {"Retry-After": "1"})
        if path == "/api/rs/token":
            who = query.get("user", "alice")
            if who not in USERS:
                return self.send(404, '{"error":"no such user"}', "application/json")
            return self.send(200, json.dumps({"token": rs256(
                {"sub": who, "role": USERS[who]["role"], "exp": int(time.time()) + 600})}),
                "application/json")
        if path == "/api/rs/me":
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            claims = verify_any(token)
            if not claims:
                return self.send(401, '{"error":"bad token"}', "application/json")
            return self.send(200, json.dumps(claims), "application/json")
        if path.startswith("/js/"):
            return self.js_wall(path.rsplit("/", 1)[1])
        if path.startswith("/static/"):
            target = FIXTURES / "static" / path.rsplit("/", 1)[1]
            if target.exists():
                ctype = "text/javascript" if target.suffix == ".js" else "application/json"
                return self.send(200, target.read_bytes(), ctype)
        return self.served_artifact(path)

    def do_POST(self):
        path = urlsplit(self.path).path
        self.raw = self.body_text()  # drain first: an unread body desyncs keep-alive
        if path == "/login":
            form = self.form()
            name, password = form.get("username", ""), form.get("password", "")
            jar = self.cookies()
            sid = jar.get("sid").value if jar.get("sid") else hashlib.sha1(os.urandom(8)).hexdigest()[:12]
            if name not in USERS:
                # L1: distinct message for an unknown user
                return self.send(401, "<p>No account with that username.</p>",
                                 extra={"Set-Cookie": f"sid={sid}; Path=/"})
            if USERS[name]["password"] != password:
                return self.send(401, "<p>Wrong password for that account.</p>",
                                 extra={"Set-Cookie": f"sid={sid}; Path=/"})
            SESSIONS[sid] = name
            return self.send(302, b"", extra={"Location": f"/account/{USERS[name]['id']}",
                                              "Set-Cookie": f"sid={sid}; Path=/; HttpOnly"})
        if path == "/reset":
            form = self.form()
            name = form.get("username", "")
            if name not in USERS:
                return self.send(404, "<p>no such user</p>")
            code = f"{int(time.time() * 1000) % 9000 + 1000}"
            RESET_CODES[name] = code
            # L9: the code is in the response body
            return self.send(200, f"<p>reset code sent by email</p><p>debug: {code}</p>")
        if path == "/reset/verify":
            return self.verify_code(self.form().get("code", ""), json_body=True)
        if path.startswith("/otp/"):
            return self.otp(path.rsplit("/", 1)[1])
        if path.startswith("/secure/"):
            return self.secure(path.rsplit("/", 1)[1])
        if path == "/echo":
            return self.send(200, json.dumps({"headers": list(self.headers.items()),
                                              "path": self.path}), "application/json")
        if path == "/slow429":
            return self.send(429, '{"error":"slow down"}', "application/json",
                             {"Retry-After": "1"})
        if path == "/api/rs/token":
            who = query.get("user", "alice")
            if who not in USERS:
                return self.send(404, '{"error":"no such user"}', "application/json")
            return self.send(200, json.dumps({"token": rs256(
                {"sub": who, "role": USERS[who]["role"], "exp": int(time.time()) + 600})}),
                "application/json")
        if path == "/api/rs/me":
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            claims = verify_any(token)
            if not claims:
                return self.send(401, '{"error":"bad token"}', "application/json")
            return self.send(200, json.dumps(claims), "application/json")
        if path.startswith("/js/"):
            return self.js_wall(path.rsplit("/", 1)[1])
        if path == "/solver":
            body = json.loads(self.raw or "{}")
            return self.send(200, json.dumps({"token": "tok-" + str(body.get("sitekey") or "")}),
                             "application/json")
        return self.not_found()

    # -- features ---------------------------------------------------------
    def account(self, wanted: int) -> None:
        # L2/L3: signed-in as anyone is enough, and any id is readable
        row = next(((n, u) for n, u in USERS.items() if u["id"] == wanted), None)
        if not row:
            return self.not_found()
        name, record = row
        self.send(200, f"<h1>Account {wanted}</h1><p>{html.escape(name)} · {record['role']} · "
                       f"balance {wanted * 1250}</p>")

    def otp(self, code: str) -> None:
        """Two-digit one-time code behind a per-IP limiter (XFF keyed)."""
        ip = self.client_ip()
        ATTEMPTS[ip] = ATTEMPTS.get(ip, 0) + 1
        if ATTEMPTS[ip] > 6:
            return self.send(429, '{"error":"slow down"}', "application/json",
                             {"Retry-After": "5"})
        return self.send(200, json.dumps({"ok": code == "42"}), "application/json")

    def js_wall(self, code: str) -> None:
        """L19: JS challenge — sets a clearance cookie, then reloads into JSON."""
        jar = self.cookies()
        if jar.get("jsok"):
            return self.send(200, json.dumps({"ok": code == "42"}), "application/json")
        page = ("<html><head><title>Checking your browser</title></head><body>"
                "<div id='w'>Just a moment... cf-challenge running</div>"
                f"<script>setTimeout(function(){{document.cookie='jsok=1;path=/';"
                f"location.reload();}},900);</script></body></html>")
        self.send(200, page)

    def secure(self, code: str) -> None:
        """L16: a hard captcha wall in front of a 2-digit code (reCAPTCHA-shaped)."""
        source = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
        try:
            source.update(self.form())
        except (ValueError, OSError):
            pass
        token = (source.get("g-recaptcha-response") or "").strip()
        if token != "tok-sitekey-secure":
            return self.send(200, (
                "<html><head><title>Just a moment...</title>"
                "<script src='https://www.google.com/recaptcha/api.js'></script></head>"
                "<body><form><div class='g-recaptcha' data-sitekey='sitekey-secure'></div>"
                "<input name='g-recaptcha-response'><button>verify</button></form></body></html>"))
        return self.send(200, json.dumps({"ok": code == "42"}), "application/json")

    def verify_code(self, code: str, *, json_body: bool) -> None:
        ip = self.client_ip()
        ATTEMPTS[ip] = ATTEMPTS.get(ip, 0) + 1
        # L8: limiter keyed on the X-Forwarded-For header, no lockout, 4 digits
        if ATTEMPTS[ip] > 6:
            return self.send(429, '{"error":"slow down"}', "application/json",
                             {"Retry-After": "5"})
        if not code:
            return self.send(400, '{"error":"code required"}', "application/json")
        if code in RESET_CODES.values():
            who = next(n for n, c in RESET_CODES.items() if c == code)
            return self.send(200, json.dumps({"ok": True, "user": who, "new_password": "temp-1234"}),
                             "application/json")
        return self.send(200, json.dumps({"ok": False, "attempts": ATTEMPTS[ip]}), "application/json")

    def export(self, fmt: str) -> None:
        rows = [("id", "user", "role", "balance")]
        rows += [(str(u["id"]), n, u["role"], str(u["id"] * 1250)) for n, u in USERS.items()]
        if fmt == "json":
            return self.send(200, json.dumps([dict(zip(rows[0], r)) for r in rows[1:]]),
                             "application/json")
        text = "\n".join(",".join(r) for r in rows)
        self.send(200, text, "text/csv",
                  {"Content-Disposition": 'attachment; filename="accounts.csv"'})

    def served_artifact(self, path: str) -> None:
        rel = path.lstrip("/")
        for candidate in (FIXTURES / rel, FIXTURES / "gitdir" / rel):
            if candidate.is_file():
                ctype = {".sql": "text/plain", ".db": "application/octet-stream",
                         ".env": "text/plain", ".json": "application/json"}.get(candidate.suffix,
                                                                                "text/plain")
                return self.send(200, candidate.read_bytes(), ctype)
        return self.not_found()


def build_fixtures() -> None:
    """Create the served artifacts: git dir, env, dump, sqlite with a deleted row."""
    (FIXTURES / ".git").mkdir(parents=True, exist_ok=True)
    (FIXTURES / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (FIXTURES / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n'
        '\turl = https://deploy:lab-deploy-token-9c1@git.example.test/arialab.git\n')
    (FIXTURES / ".env").write_text(
        "APP_ENV=production\nAPP_KEY=base64:Q2hhbmdlTWVQbGVhc2UxMjM0NTY=\n"
        "DB_PASSWORD=lab-db-pass-77\nSTRIPE_SECRET=sk_live_labkey9f2b1c77aa\n")
    (FIXTURES / "backup.sql").write_text(
        "-- MySQL dump 10.13\nCREATE TABLE users (id int, user text, role text);\n"
        "INSERT INTO users VALUES (1,'alice','user'),(2,'bob','user'),(3,'root','admin');\n")
    (FIXTURES / "robots.txt").write_text("User-agent: *\nDisallow: /api/v1/internal\n"
                                         "Disallow: /admin\n")

    db = FIXTURES / "db.sqlite3"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE invoices (id INTEGER PRIMARY KEY, customer TEXT, amount INTEGER)")
    conn.executemany("INSERT INTO invoices VALUES (?,?,?)",
                     [(1, "Acme", 12000), (2, "Beta", 4500), (3, "Secret Co", 99000),
                      (4, "Delta", 700)])
    conn.commit()
    conn.execute("DELETE FROM invoices WHERE id = 3")  # recoverable from the freelist
    conn.commit()
    conn.close()

    statics = FIXTURES / "static"
    statics.mkdir(exist_ok=True)
    (statics / "app.js").write_text(
        "// build 41f2\nconst API='/api/v1/';const ADMIN='/api/admin/users';\n"
        "const STRIPE='pk_test_TYooMQauvdEDq54NiTphI7jx';\n"
        "const KEY='ak_live_9f2b1c77aa';\n"
        "fetch(API+'internal/notes');checkout(ADMIN);\n"
        "//# sourceMappingURL=app.js.map\n")
    (statics / "app.js.map").write_text(json.dumps({
        "version": 3, "file": "app.js",
        "sources": ["src/api.ts", "src/config.ts", "src/auth/guard.ts"],
        "sourcesContent": [
            "export const API = '/api/v1/';\nexport const ADMIN = '/api/admin/users';\n",
            "// hardcoded for staging, honest\nexport const DB_PASSWORD='lab-db-pass-77';\n",
            "export const ADMIN_ROLES = ['admin','superuser'];\n"]}))

    (FIXTURES / "index.html").write_text(
        "<html><title>AriaLab</title><body><h1>AriaLab</h1>"
        "<p>Internal ledger console.</p><a href='/login'>sign in</a>"
        "<script src='/static/app.js'></script></body></html>")
    (FIXTURES / "login.html").write_text(
        "<html><title>Sign in</title><body><form method='post' action='/login'>"
        "<input name='username'><input name='password' type='password'>"
        "<button>sign in</button></form></body></html>")
    notes = [{"id": 1, "note": "vendor renewal in March"},
             {"id": 2, "note": "CUTOVER window Thu 03:00 — contact ops on 0917xxxx"}]
    (FIXTURES / "notes.json").write_text(json.dumps(notes, indent=2))
    (FIXTURES / "swagger.json").write_text(json.dumps(
        {"openapi": "3.0.0", "paths": {"/login": {"post": {}}, "/account/{id}": {"get": {}},
                                       "/export": {"get": {}}, "/api/admin/users": {"get": {}}}},
        indent=2))


def main() -> int:
    port = int(os.environ.get("PORT") or (sys.argv[sys.argv.index("--port") + 1]
                                          if "--port" in sys.argv else 8899))
    build_fixtures()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"aria lab on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
