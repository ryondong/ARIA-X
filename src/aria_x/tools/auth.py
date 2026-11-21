"""Authentication, authorization and data-recovery tools.

The stock catalog can send one request and read the answer. Auth work needs four
things the stock catalog does not have: **session continuity** (a cookie jar that
survives across calls), **differential probing** (the same request with one
controlled variation, compared against a baseline automatically), **artifact
mining** (endpoints and secrets out of the app's own JavaScript, plus the served
files that are not supposed to be there), and a **vault** so a captured token is
not lost to evidence redaction.

Every tool here follows the net.py pipeline: scope check before any socket, rate
limit per host, bounded bytes/time, audit row, redacted evidence file.

Design rules that keep this module honest:

* a differential row is a *hint*, never a finding — ``verdict`` says which byte
  changed, the planner still has to prove it means authentication;
* no tool invents a request the caller did not describe (no hidden wordlists
  beyond a named, documented tier);
* brute-force loops are bounded by explicit attempts AND by wall clock, and stop
  on the first confirmed match;
* secrets never enter an observation unmasked unless the caller asks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from ..util import json_dumps, json_loads, now_iso, redact, truncate
from .base import ToolContext, ToolRegistry, ToolResult, ToolSpec
from . import browser as br
from . import challenge as chal
from . import stealth
from . import jwtkeys
from .net import (_ALLOWED_METHODS, DEFAULT_HTTP_TIMEOUT, MAX_EVIDENCE_EXCERPT, MAX_HTTP_BYTES,
                  _clean_headers,
                  _decode_body, _redact_headers, _response_headers, _save_evidence,
                  _ScopedRedirectHandler)
from .terminal import audit, clamp_float, clamp_int

#: Backends on which a real ``curl`` binary is reachable; others fall back to urllib.
_CURL_BACKENDS = {"local"}

MAX_MATRIX_VARIANTS = 48
MAX_ATTEMPTS = 400
MAX_LANES = 40
_B64URL = re.compile(r"^[A-Za-z0-9_\-]+\.?$")
_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]", "0.0.0.0")

#: Verdict markers that make a differential row worth a second look.
_AUTH_MARKERS = re.compile(
    r"(?i)\b(unauthoriz\w*|forbidden|sign[ _-]?in|log[ _-]?in|authenticat\w*|"
    r"permission denied|access denied|session expired|not signed in|please log)\b")

#: Secret shapes worth surfacing from a JavaScript bundle.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_secret", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{10,}\b")),
    ("stripe_publishable", re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}\b")),
    ("assigned_key", re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|"
        r"auth[_-]?token|[a-z_]*password|[a-z_]*passwd|[a-z_]*secret)\b\s*[:=]\s*[\"']([^\"'\s]{6,120})[\"']")),
)

#: Endpoint-ish strings inside JavaScript, HTML and manifests.
_ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""["'`](/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]{2,120})["'`]"""),
    re.compile(r"""["'`](https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{6,200})["'`]"""),
    re.compile(r"""(?i)\b(?:ws|wss)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,200}"""),
    re.compile(r"""(?i)["'`](/?(?:api|rest|graphql|gql|rpc|v\d)/[A-Za-z0-9._~/\-{}$:]{1,120})["'`]"""),
)

#: Files that should not be served, cheapest first. Quiet first, loud last.
_ARTIFACT_PATHS: dict[str, tuple[str, ...]] = {
    "s": (".git/HEAD", ".env", "robots.txt", "sitemap.xml", "manifest.json",
          "asset-manifest.json", ".well-known/security.txt", "package.json"),
    "m": (".git/config", ".git/packed-refs", ".env.local", ".env.example", ".env.production",
          ".DS_Store", "composer.lock", "yarn.lock", "web.config", "crossdomain.xml",
          "actuator", "actuator/env", "swagger.json", "openapi.json", "v2/api-docs",
          "api-docs", "graphql", "server-status", "phpinfo.php", ".svn/entries",
          "backup.zip", "www.zip", "db.sql", "dump.sql", "backup.sql", "build/manifest.json",
          "static/js/main.js", "_next/static/", "master.js", "app.js", "main.js"),
    "l": (".git/index", ".git/logs/HEAD", "config.php.bak", "config.php~", "wp-config.php.bak",
          ".htaccess", ".htpasswd", ".gitignore", ".editorconfig", "Jenkinsfile",
          ".github/workflows/main.yml", "Dockerfile", "docker-compose.yml", "tsconfig.json",
          ".babelrc", "stats.json", "WEB-INF/web.xml", "META-INF/MANIFEST.MF",
          "actuator/heapdump", "actuator/mappings", "actuator/beans", "actuator/configprops",
          "metrics", "health", "trace", "env", "debug/pprof/", "debug/vars",
          "console", "admin", "login", "signin", "signup", "register", "forgot-password",
          "reset", "invite", "verify", "mfa", "otp", "me", "profile", "api/users", "admin/users",
          "oauth/token", "oauth/authorize", "sso", "saml/metadata"),
}

#: Common JWT secrets, tried before any caller-supplied wordlist.
_JWT_WORDLIST: tuple[str, ...] = (
    "secret", "password", "changeme", "jwt", "jwtsecret", "supersecret", "secretkey",
    "mysecret", "my_secret", "s3cr3t", "admin", "test", "dev", "development",
    "your-256-bit-secret", "your_jwt_secret", "1234567890", "qwerty", "letmein",
    "secret123", "jwt_secret_key", "token", "tokenkey", "key", "private",
    "hs256", "sha256", "aria", "app", "application", "api", "api_secret",
)


# ---------------------------------------------------------------------------
# shared plumbing
# ---------------------------------------------------------------------------


def _state_dir(ctx: ToolContext) -> Path:
    path = Path(ctx.workdir) / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _headers(raw: Any, *, keep_host: bool = False) -> dict[str, str]:
    """Clean caller headers but keep ``Host`` (net._clean_headers drops it)."""
    if not isinstance(raw, dict):
        return {}
    out = _clean_headers({k: v for k, v in raw.items() if keep_host
                          or str(k).lower() != "host"})
    if keep_host:
        for key, value in raw.items():
            if str(key).lower() == "host":
                out["Host"] = str(value)[:255]
    return out


def _b64d(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _jar_path(ctx: ToolContext, name: str) -> Path:
    return _state_dir(ctx) / f"jar_{re.sub(r'[^A-Za-z0-9_.-]', '_', name)[:40]}.cookies"


def _load_jar(ctx: ToolContext, name: str) -> http.cookiejar.MozillaCookieJar:
    jar = http.cookiejar.MozillaCookieJar(str(_jar_path(ctx, name)))
    try:
        if _jar_path(ctx, name).exists():
            jar.load(ignore_discard=True, ignore_expires=True)
    except (OSError, http.cookiejar.LoadError):
        pass
    return jar


def _save_jar(ctx: ToolContext, jar: http.cookiejar.MozillaCookieJar) -> None:
    try:
        jar.save(ignore_discard=True, ignore_expires=True)
    except (OSError, http.cookiejar.LoadError):
        pass


def _sessions_file(ctx: ToolContext) -> Path:
    return _state_dir(ctx) / "sessions.json"


def _sessions(ctx: ToolContext) -> dict[str, Any]:
    return json_loads(Path(_sessions_file(ctx)).read_text(encoding="utf-8")
                      if _sessions_file(ctx).exists() else None, default={}) or {}


def _write_sessions(ctx: ToolContext, data: dict[str, Any]) -> None:
    try:
        _sessions_file(ctx).write_text(json_dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def _vault_file(ctx: ToolContext) -> Path:
    return _state_dir(ctx) / "vault.json"


def _vault(ctx: ToolContext) -> dict[str, Any]:
    try:
        return json_loads(_vault_file(ctx).read_text(encoding="utf-8"), default={}) or {}
    except OSError:
        return {}


def _mask(value: str) -> str:
    text = str(value)
    if len(text) <= 12:
        return text[:3] + "***" if len(text) > 4 else "***"
    return f"{text[:6]}...{text[-4:]} ({len(text)} chars)"


def _session_headers(ctx: ToolContext, name: str) -> tuple[http.cookiejar.MozillaCookieJar | None, dict[str, str]]:
    """The jar and stored headers for a session; ``None`` when it does not exist.

    Note the membership test, not a truthiness test: a session created by an
    import is a record with no headers yet, i.e. an empty dict, and ``{}`` is
    falsy — treating that as "no session" silently dropped every imported cookie.
    """
    if not name:
        return None, {}
    sessions = _sessions(ctx)
    if name not in sessions:
        return None, {}
    return _load_jar(ctx, name), dict((sessions.get(name) or {}).get("headers") or {})


_REDIRECTS = (301, 302, 303, 307, 308)
_MAX_HOPS = 5


def _send(ctx: ToolContext, *, url: str, method: str = "GET", headers: dict[str, str] | None = None,
          body: str | None = None, session: str = "", follow: bool = False,
          timeout: float = DEFAULT_HTTP_TIMEOUT, max_bytes: int = 65536,
          jar: http.cookiejar.MozillaCookieJar | None = None, client: str = "",
          curl_extra: str = "") -> dict[str, Any]:
    """One logical request: the transport, plus scope-checked redirects.

    Redirects are followed here rather than inside the client so that every hop is
    re-authorized (deny on an out-of-scope bounce), re-rate-limited and recorded —
    libcurl and urllib would both follow silently otherwise.
    """
    row = _dispatch(ctx, url=url, method=method, headers=headers, body=body, session=session,
                    follow=follow, timeout=timeout, max_bytes=max_bytes, jar=jar,
                    client=client, curl_extra=curl_extra)
    hops: list[dict[str, Any]] = []
    current = url
    for _ in range(_MAX_HOPS if follow else 0):
        location = row.get("location") or ""
        if (row.get("status") or 0) not in _REDIRECTS or not location:
            break
        target = urllib.parse.urljoin(current, location)
        ctx.scope.require_url(target)          # raises ScopeViolation on a bounce out of scope
        audit(ctx, "http_request", "redirect", target,
              {"from": current, "status": row.get("status")})
        hops.append({"from": current, "to": target, "status": row.get("status")})
        if (row.get("status") or 0) in (301, 302, 303) and (row.get("method") or "GET") != "GET":
            method = "GET"
            body = None
        current = target
        row = _dispatch(ctx, url=target, method=method, headers=headers, body=body,
                        session=session, follow=False, timeout=timeout, max_bytes=max_bytes,
                        jar=jar, client=client, curl_extra=curl_extra)
    row["redirects"] = hops
    row["final_url"] = current
    return row


def _dispatch(ctx: ToolContext, *, url: str, method: str = "GET",
              headers: dict[str, str] | None = None,
              body: str | None = None, session: str = "", follow: bool = False,
              timeout: float = DEFAULT_HTTP_TIMEOUT, max_bytes: int = 65536,
              jar: http.cookiejar.MozillaCookieJar | None = None, client: str = "",
              curl_extra: str = "") -> dict[str, Any]:
    """One scoped, rate-limited, bounded request. Never raises for 4xx/5xx.

    ``client='curl'`` shells out to curl when the sandbox is local: that buys
    HTTP/2, ALPN and a browser-ish TLS stack, which urllib cannot do. The scope
    check, rate limit, evidence and challenge detection are identical either way.
    """
    workdir = Path(ctx.workdir)
    stealth_on = str(kwargs_client := client or "").lower() != "off" and \
        os.environ.get("ARIAX_STEALTH", "1") != "0"

    # Manner before content: the wall pushes back first on a host that keeps
    # challenging, then on pace. Neither is a protocol error, so neither is raised.
    host_for_pace = urllib.parse.urlsplit(url).hostname or ""
    if stealth_on:
        wait = stealth.breaker_open(workdir, host_for_pace)
        if wait > 0:
            time.sleep(min(wait, 15.0))
            stealth.mark_paid(workdir)
        kind = stealth.classify(url)
        time.sleep(stealth.next_delay(workdir, kind,
                                      scale=stealth.host_scale(workdir, host_for_pace)))
    else:
        kind = "api"

    chosen = client.lower()
    if chosen in {"", "auto"}:
        chosen = "impersonate" if stealth.impersonate_python() else ""
    if chosen == "impersonate":
        result = _send_impersonate(ctx, url=url, method=method.upper(), headers=headers,
                                   body=body, follow=False, timeout=timeout,
                                   max_bytes=max_bytes, jar=jar)
        if not result.get("transport_unavailable"):
            if stealth_on:
                stealth.record(workdir, url=url, kind=kind, status=result.get("status") or 0,
                               size=result.get("length") or 0, elapsed_ms=result.get("ms") or 0,
                               transport="impersonate", fingerprint="chrome/ja3+ja4+h2",
                               challenge=(result.get("challenge") or {}).get("vendor", ""))
            return result
    if client.lower() == "curl" and getattr(ctx.sandbox, "backend", "") in _CURL_BACKENDS:
        result = _send_curl(ctx, url=url, method=method.upper(), headers=headers, body=body,
                            follow=False, timeout=timeout, max_bytes=max_bytes, jar=jar,
                            extra=curl_extra)
        if not result.get("curl_unavailable"):
            if stealth_on:
                stealth.record(workdir, url=url, kind=kind, status=result.get("status") or 0,
                               size=result.get("length") or 0, elapsed_ms=result.get("ms") or 0,
                               transport="curl", fingerprint="schannel/ja3")
            return result
    method = method.upper()
    decision = ctx.scope.require_url(url, method)
    host = decision.host or (urllib.parse.urlsplit(url).hostname or "")
    ctx.scope.acquire_slot(host)
    audit(ctx, "http_request", "allowed", url,
          {"method": method, "host": host, "port": decision.port, "via": "auth"})

    # urllib cannot decode brotli; do not advertise it on that transport
    polite = stealth.headers_for(workdir, url, method,
                                 encodings="gzip, deflate") if stealth_on else {}
    request_headers = {**polite}
    request_headers.update(_headers(headers, keep_host=True))
    if not stealth_on:
        request_headers.setdefault("User-Agent", "ARIA-X/0.1 (authorized security research)")
        request_headers.setdefault("Accept", "*/*")
    data: bytes | None = None
    if body is not None and method not in {"GET", "HEAD"}:
        data = str(body).encode("utf-8")
        if not any(k.lower() == "content-type" for k in request_headers):
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

    row: dict[str, Any] = {"url": url, "method": method, "status": 0, "error": ""}
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        handlers: list[Any] = [urllib.request.ProxyHandler({})]
        if jar is not None:
            handlers.append(urllib.request.HTTPCookieProcessor(jar))
        redirects: list[dict[str, Any]] = []
        handlers.append(_ScopedRedirectHandler(ctx, redirects) if follow else _NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        try:
            resp = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            resp = exc
        except urllib.error.URLError as exc:
            row["error"] = str(getattr(exc, "reason", exc))
            row["ms"] = int((time.monotonic() - started) * 1000)
            audit(ctx, "http_request", "error", url, {"error": row["error"]})
            return row
        except (socket.timeout, TimeoutError):
            row["error"] = "timeout"
            row["ms"] = int((time.monotonic() - started) * 1000)
            return row
        except (ssl.SSLError, OSError, ValueError) as exc:
            row["error"] = str(exc)[:300]
            row["ms"] = int((time.monotonic() - started) * 1000)
            return row
        with resp:
            status = int(getattr(resp, "status", 0) or getattr(resp, "code", 0) or 0)
            response_headers = _response_headers(resp)
            try:
                raw = resp.read(max_bytes + 1)
            except (OSError, socket.timeout) as exc:
                row.update({"status": status, "error": f"body: {exc}"})
                row["ms"] = int((time.monotonic() - started) * 1000)
                return row
    except urllib.error.URLError as exc:  # scope refusal surfaces here
        row["error"] = str(exc)[:300]
        row["ms"] = int((time.monotonic() - started) * 1000)
        return row

    body_text = _decode_body(raw[:max_bytes], response_headers.get("Content-Type", ""))
    lower = {k.lower(): v for k, v in response_headers.items()}
    row.update({
        "status": status,
        "ms": int((time.monotonic() - started) * 1000),
        "length": len(raw),
        "truncated": len(raw) > max_bytes,
        "content_type": lower.get("content-type", ""),
        "location": lower.get("location", ""),
        "www_authenticate": lower.get("www-authenticate", ""),
        "set_cookie": bool(lower.get("set-cookie")),
        "body_sha": _sha(body_text),
        "body": body_text,
        "headers": response_headers,
    })
    flagged = chal.detect(status, response_headers, body_text)
    if flagged:
        row["challenge"] = flagged
        audit(ctx, "http_request", "challenge", url, {"vendor": flagged["vendor"],
                                                      "kind": flagged["kind"]})
    if stealth_on:
        stealth.record(workdir, url=url, kind=stealth.classify(url), status=status,
                       size=len(raw), elapsed_ms=elapsed_ms, transport="urllib",
                       fingerprint="python-ssl/ja3",
                       challenge=(flagged or {}).get("vendor", ""))
        row["transport"] = "urllib"
        if status in (429, 503):
            retry_after = response_headers.get("Retry-After", "")
            try:
                pause = min(float(retry_after), 30.0)
            except (TypeError, ValueError):
                pause = 0.0
            if pause:
                time.sleep(pause)
    return row


def _send_impersonate(ctx: ToolContext, *, url: str, method: str, headers: dict[str, str] | None,
                      body: str | None, follow: bool, timeout: float, max_bytes: int,
                      jar: http.cookiejar.MozillaCookieJar | None) -> dict[str, Any]:
    """The request through libcurl-impersonate: Chrome's TLS and h2 fingerprint."""
    python = stealth.impersonate_python()
    if not python:
        return {"transport_unavailable": True}
    method = method.upper()
    decision = ctx.scope.require_url(url, method)
    host = decision.host or (urllib.parse.urlsplit(url).hostname or "")
    ctx.scope.acquire_slot(host)
    audit(ctx, "http_request", "allowed", url,
          {"method": method, "host": host, "port": decision.port, "via": "impersonate"})

    ordered = stealth.headers_for(Path(ctx.workdir), url, method)
    ordered.update(_headers(headers, keep_host=True))
    if jar is not None:
        request = urllib.request.Request(url)
        jar.add_cookie_header(request)
        cookie = request.get_header("Cookie")
        if cookie:
            ordered.setdefault("Cookie", cookie)
    worker = Path(__file__).with_name("_impersonate_worker.py")
    spec = json.dumps({
        "url": url, "method": method, "headers": list(ordered.items()),
        "body_b64": base64.b64encode(body.encode()).decode() if body else "",
        "timeout": timeout, "max_bytes": max_bytes, "follow": follow,
        "impersonate": str(__import__("os").environ.get("ARIAX_IMPERSONATE") or "chrome"),
    })
    started = time.monotonic()
    try:
        run = subprocess.run([python, str(worker)], input=spec, capture_output=True, text=True,
                             timeout=timeout + 20)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"transport_unavailable": True, "error": f"impersonate unavailable: {exc}"}
    try:
        payload = json.loads(run.stdout or "{}")
    except ValueError:
        return {"transport_unavailable": True, "error": "impersonate worker returned no JSON"}
    if payload.get("error"):
        row: dict[str, Any] = {"url": url, "method": method, "status": 0,
                              "error": str(payload["error"])[:300],
                              "ms": int((time.monotonic() - started) * 1000)}
        return row

    raw = base64.b64decode(payload.get("body_b64") or "")
    response_headers = {str(k): str(v) for k, v in (payload.get("headers") or {}).items()}
    lower = {k.lower(): v for k, v in response_headers.items()}
    body_text = _decode_body(raw, response_headers.get("Content-Type", ""))
    if jar is not None:
        for value in ([lower.get("set-cookie")] if lower.get("set-cookie") else []):
            for piece in re.split(r",(?=[^;]+=)", str(value)):
                name, _, val = piece.partition("=")
                if name.strip():
                    parts = urllib.parse.urlsplit(url)
                    jar.set_cookie(http.cookiejar.Cookie(
                        version=0, name=name.strip(), value=val.split(";")[0].strip(), port=None,
                        port_specified=False, domain=parts.hostname or "",
                        domain_specified=False, domain_initial_dot=False, path="/",
                        path_specified=True, secure=parts.scheme == "https", expires=None,
                        discard=True, comment=None, comment_url=None, rest={}, rfc2109=False))
    row = {
        "url": url, "method": method, "status": int(payload.get("status") or 0),
        "ms": int(payload.get("elapsed_ms") or 0), "length": len(raw),
        "content_type": lower.get("content-type", ""), "location": lower.get("location", ""),
        "www_authenticate": lower.get("www-authenticate", ""),
        "set_cookie": bool(lower.get("set-cookie")), "body_sha": _sha(body_text),
        "body": body_text, "headers": response_headers, "transport": "impersonate",
    }
    flagged = chal.detect(row["status"], response_headers, body_text)
    if flagged:
        row["challenge"] = flagged
    return row


#: curl write-out fields, space separated, captured on one stdout line.
_CURL_FORMAT = "%{http_code} %{size_download} %{time_total} %{content_type}"


def _send_curl(ctx: ToolContext, *, url: str, method: str, headers: dict[str, str] | None,
               body: str | None, follow: bool, timeout: float, max_bytes: int,
               jar: http.cookiejar.MozillaCookieJar | None, extra: str) -> dict[str, Any]:
    """Same contract as the urllib path, executed through the local curl binary."""
    import shlex

    method = method.upper()
    decision = ctx.scope.require_url(url, method)
    host = decision.host or (urllib.parse.urlsplit(url).hostname or "")
    ctx.scope.acquire_slot(host)
    audit(ctx, "http_request", "allowed", url,
          {"method": method, "host": host, "port": decision.port, "via": "curl"})

    state = _state_dir(ctx)
    stamp = f"{int(time.time() * 1000)}"
    header_path = state / f"curl_{stamp}.hdr"
    body_path = state / f"curl_{stamp}.body"
    request_headers = {"User-Agent": "ARIA-X/0.1 (authorized security research)", "Accept": "*/*"}
    request_headers.update(_headers(headers, keep_host=True))

    argv = ["curl", "-sS", "--http2", "--compressed", "--max-time", f"{int(max(timeout, 1))}",
            "--max-filesize", str(max_bytes), "-X", method, "-D", str(header_path),
            "-o", str(body_path), "--write-out", _CURL_FORMAT]
    if follow:
        argv += ["--location", "--max-redirs", "5"]
    if jar is not None:
        argv += ["-b", str(_jar_path(ctx, "_curl")), "-c", str(_jar_path(ctx, "_curl"))]
    data: bytes | None = None
    if body is not None and method not in {"GET", "HEAD"}:
        data = str(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    for name, value in request_headers.items():
        if value:
            argv += ["-H", f"{name}: {value}"]
    if data is not None:
        # --data-binary @file keeps the exact bytes and avoids shell re-quoting
        payload_path = state / f"curl_{stamp}.data"
        payload_path.write_bytes(data)
        argv += ["--data-binary", f"@{payload_path.as_posix()}"]
    if extra:
        argv += shlex.split(extra)
    argv.append(url)

    started = time.monotonic()
    run = ctx.sandbox.run(" ".join(shlex.quote(part) for part in argv), timeout=timeout + 15)
    elapsed = int((time.monotonic() - started) * 1000)
    row: dict[str, Any] = {"url": url, "method": method, "status": 0, "ms": elapsed}
    if run.exit_code == 127 or (run.exit_code == 126 and "curl" in (run.stderr or "")):
        row["curl_unavailable"] = True
        return row
    stdout = (run.stdout or "").strip().splitlines()
    fields = (stdout[-1] if stdout else "").split(" ", 3)
    try:
        row["status"] = int(fields[0] or 0)
    except (ValueError, IndexError):
        row["status"] = 0
    if run.timed_out:
        row["error"] = "curl timeout"
        return row
    if row["status"] == 0 and run.stderr:
        row["error"] = truncate(run.stderr.strip(), 300)
        return row

    response_headers: dict[str, str] = {}
    try:
        for line in header_path.read_text("utf-8", "replace").splitlines():
            if ":" in line and not line.startswith("HTTP/"):
                name, _, value = line.partition(":")
                response_headers[name.strip()] = truncate(value.strip(), 1000)
    except OSError:
        pass
    try:
        raw = body_path.read_bytes()[:max_bytes]
    except OSError:
        raw = b""
    for path in (header_path, body_path):
        path.unlink(missing_ok=True)
    if jar is not None:
        saved = _load_jar(ctx, "_curl")
        for cookie in saved:
            jar.set_cookie(cookie)

    body_text = _decode_body(raw, response_headers.get("Content-Type", ""))
    lower = {k.lower(): v for k, v in response_headers.items()}
    row.update({
        "status": row["status"], "length": len(raw),
        "content_type": lower.get("content-type", ""),
        "location": lower.get("location", ""),
        "www_authenticate": lower.get("www-authenticate", ""),
        "set_cookie": bool(lower.get("set-cookie")), "body_sha": _sha(body_text),
        "body": body_text, "headers": response_headers, "transport": "curl",
    })
    flagged = chal.detect(row["status"], response_headers, body_text)
    if flagged:
        row["challenge"] = flagged
    return row


def row_payload(ctx: ToolContext, row: dict[str, Any], *, headers: dict[str, str] | None = None,
                body: str | None = None) -> dict[str, Any]:
    """Assemble the ``http_request``-shaped payload (and evidence) from a row.

    ``net.http_request`` funnels through this so the plain tool inherits the same
    persona headers, pacing, fingerprint transport and ledger as everything else.
    """
    status = int(row.get("status") or 0)
    text_body = row.get("body") or ""
    excerpt = truncate(text_body, MAX_EVIDENCE_EXCERPT)
    payload: dict[str, Any] = {
        "url": row.get("url"), "final_url": row.get("url"), "method": row.get("method"),
        "status": status,
        "reason": "ok" if 200 <= status < 300 else ("redirect" if 300 <= status < 400 else "error"),
        "ok": 200 <= status < 300,
        "headers": {k: v for k, v in (row.get("headers") or {}).items()},
        "body_excerpt": excerpt, "body_length": row.get("length") or 0,
        "truncated": bool(row.get("truncated")), "elapsed_ms": row.get("ms") or 0,
        "server": (row.get("headers") or {}).get("Server", ""),
        "content_type": row.get("content_type") or "",
        "redirect": row.get("location") or "", "redirects": [],
        "transport": row.get("transport") or "",
    }
    if row.get("challenge"):
        payload["challenge"] = chal.describe(row["challenge"])
    if row.get("error"):
        payload["error"] = row["error"]
    evidence = _save_evidence(ctx, {
        "request": {"url": row.get("url"), "method": row.get("method"),
                    "headers": _redact_headers(headers or {}),
                    "body_excerpt": truncate(redact(str(body or "")), 2000)},
        "response": {"status": status, "headers": row.get("headers") or {},
                     "body_excerpt": truncate(redact(excerpt), MAX_EVIDENCE_EXCERPT),
                     "length": row.get("length") or 0, "truncated": bool(row.get("truncated"))},
        "transport": row.get("transport") or "", "elapsed_ms": row.get("ms") or 0,
        "challenge": row.get("challenge"),
    }, prefix="http")
    if evidence:
        payload["evidence_path"] = evidence
    return payload


def _row_summary(row: dict[str, Any], body_chars: int = 400) -> dict[str, Any]:
    out = {k: row.get(k) for k in ("method", "url", "status", "length", "ms", "content_type",
                                   "location", "set_cookie", "body_sha", "error")}
    if row.get("challenge"):
        out["challenge"] = chal.describe(row["challenge"])
    body = row.get("body") or ""
    if body:
        out["excerpt"] = truncate(re.sub(r"\s+", " ", body), body_chars)
    return out


# ---------------------------------------------------------------------------
# tools: vault
# ---------------------------------------------------------------------------


def vault(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    action = str(kwargs.get("action") or "list").lower()
    name = str(kwargs.get("name") or "").strip()
    store = _vault(ctx)

    if action == "list":
        rows = [{"name": k, "masked": _mask(v.get("value", "")), "note": v.get("note", ""),
                 "created_at": v.get("created_at", "")} for k, v in store.items()]
        return ToolResult.success({"entries": rows, "count": len(rows)},
                                  text=json_dumps(rows, indent=2) if rows else "vault is empty")
    if not name:
        return ToolResult.failure("name is required for put/get")
    if action == "put":
        value = kwargs.get("value")
        if value is None:
            return ToolResult.failure("value is required for put")
        store[name] = {"value": str(value), "note": str(kwargs.get("note") or ""),
                       "created_at": now_iso()}
        _write_sessions(ctx, _sessions(ctx))  # keep state dir alive
        _vault_file(ctx).write_text(json_dumps(store, indent=2), encoding="utf-8")
        return ToolResult.success({"name": name, "stored": True, "masked": _mask(str(value))},
                                  text=f"stored '{name}' = {_mask(str(value))} "
                                       f"(file: {_vault_file(ctx).relative_to(Path(ctx.workdir))})")
    if action == "get":
        entry = store.get(name)
        if not entry:
            return ToolResult.success({"name": name, "found": False, "known": sorted(store)},
                                      text=f"not in vault: {name}")
        masked = _mask(entry["value"])
        payload = {"name": name, "found": True, "masked": masked, "note": entry.get("note", "")}
        if kwargs.get("reveal"):
            payload["value"] = entry["value"]
        return ToolResult.success(payload,
                                  text=json_dumps(payload, indent=2) if kwargs.get("reveal")
                                  else f"{name} = {masked}")
    if action == "remove":
        store.pop(name, None)
        _vault_file(ctx).write_text(json_dumps(store, indent=2), encoding="utf-8")
        return ToolResult.success({"name": name, "removed": True}, text=f"removed '{name}'")
    return ToolResult.failure(f"unknown action '{action}'", data={"actions": ["put", "get", "list", "remove"]})


# ---------------------------------------------------------------------------
# tools: session (cookie jar + captured auth headers)
# ---------------------------------------------------------------------------


def http_session(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    action = str(kwargs.get("action") or "list").lower()
    name = str(kwargs.get("name") or "default").strip()
    sessions = _sessions(ctx)

    if action == "list":
        reveal = bool(kwargs.get("reveal"))
        rows: list[dict[str, Any]] = []
        for key, record in sessions.items():
            jar_items = list(_load_jar(ctx, key))
            row = {"name": key, "cookies": len(jar_items),
                   "cookie_names": sorted({c.name for c in jar_items}),
                   "headers": sorted((record.get("headers") or {}).keys()),
                   "note": record.get("note", "")}
            if reveal:
                # the exact Cookie header, so it can be handed to another session or a vault
                row["cookie_header"] = "; ".join(f"{c.name}={c.value}" for c in jar_items)
            rows.append(row)
        return ToolResult.success({"sessions": rows}, text=json_dumps(rows, indent=2))

    if action == "close":
        _jar_path(ctx, name).unlink(missing_ok=True)
        sessions.pop(name, None)
        _write_sessions(ctx, sessions)
        return ToolResult.success({"name": name, "closed": True}, text=f"closed session '{name}'")

    if action not in {"open", "send", "import"}:
        return ToolResult.failure(f"unknown action '{action}'",
                                  data={"actions": ["open", "send", "import", "list", "close"]})

    url = str(kwargs.get("url") or "").strip()
    if not url:
        return ToolResult.failure("url is required for open/send/import")
    jar, stored_headers = _session_headers(ctx, name)
    if action in {"open", "import"}:
        jar = http.cookiejar.MozillaCookieJar(str(_jar_path(ctx, name)))
        stored_headers = {}
        sessions.setdefault(name, {})
        if action == "import":
            sessions[name]["headers"] = (sessions[name].get("headers") or {})
            import_headers = _headers(kwargs.get("headers"))
            sessions[name]["headers"].update(import_headers)
            stored_headers.update(import_headers)
            raw_cookies = str(kwargs.get("cookies") or "")
            cookie_file = str(kwargs.get("cookie_file") or "")
            if cookie_file:
                path = Path(cookie_file) if Path(cookie_file).is_absolute() else Path(ctx.workdir) / cookie_file
                try:
                    raw_cookies += "; " + path.read_text("utf-8", "replace")
                except OSError as exc:
                    return ToolResult.failure(f"cookie_file unreadable: {exc}")
            parts = urllib.parse.urlsplit(url)
            injected = 0
            for piece in re.split(r"[;\n]", raw_cookies):
                cookie_name, _, cookie_value = piece.strip().partition("=")
                cookie_name = cookie_name.strip()
                if not cookie_name or not cookie_value.strip():
                    continue
                jar.set_cookie(http.cookiejar.Cookie(
                    0, cookie_name, cookie_value.strip(), None, False, parts.hostname or "",
                    False, False, "/", True, False, None, False, None, None, {}))
                injected += 1
            _save_jar(ctx, jar)
            _write_sessions(ctx, sessions)
            if not injected and not import_headers:
                return ToolResult.failure("import needs cookies, cookie_file or headers")
            return ToolResult.success(
                {"session": name, "cookies": len(jar), "headers": sorted(stored_headers)},
                text=f"imported {injected} cookies and {len(stored_headers)} headers into '{name}'")
    elif jar is None:
        return ToolResult.failure(f"session '{name}' does not exist; call action=open first")

    headers = dict(stored_headers)
    headers.update(_headers(kwargs.get("headers")))
    body = kwargs.get("body")
    row = _send(ctx, method=str(kwargs.get("method") or "GET"), url=url, headers=headers,
                body=body if body is None else str(body), session=name,
                follow=bool(kwargs.get("follow")), timeout=clamp_float(kwargs.get("timeout"), 1.0, 90.0,
                                                                      DEFAULT_HTTP_TIMEOUT),
                max_bytes=clamp_int(kwargs.get("max_bytes"), 256, MAX_HTTP_BYTES, 131072), jar=jar,
                client=str(kwargs.get("client") or ""), curl_extra=str(kwargs.get("curl_extra") or ""))
    # A wall is not a result: solve or inject, then retry exactly once.
    retry: dict[str, Any] = {}
    if row.get("challenge"):
        solution = chal.resolve_token(ctx, kwargs, row["challenge"], url)
        retry = {"challenge": chal.describe(row["challenge"]), **solution}
        cookie_name = str(kwargs.get("token_cookie") or "")
        if solution.get("token") and cookie_name:
            parts = urllib.parse.urlsplit(url)
            jar.set_cookie(http.cookiejar.Cookie(
                0, cookie_name, solution["token"], None, False, parts.hostname or "",
                False, False, "/", True, False, None, False, None, None, {}))
            solution["token"] = ""  # carried by the jar, not the body
            retry["token"] = "(cookie)"
        if solution.get("token"):
            headers2, body2, url2, how = chal.inject(dict(headers), body, solution["token"],
                                                     row["challenge"], kwargs, url)
            retry["injected"] = how
            row = _send(ctx, method=str(kwargs.get("method") or "GET"), url=url2, headers=headers2,
                        body=body2, session=name, follow=bool(kwargs.get("follow")),
                        timeout=clamp_float(kwargs.get("timeout"), 1.0, 90.0, DEFAULT_HTTP_TIMEOUT),
                        max_bytes=clamp_int(kwargs.get("max_bytes"), 256, MAX_HTTP_BYTES, 131072),
                        jar=jar, client=str(kwargs.get("client") or ""),
                        curl_extra=str(kwargs.get("curl_extra") or ""))
            retry["cleared"] = not row.get("challenge")
    _save_jar(ctx, jar)

    # Persist any captured tokens as headers on the session so later calls carry them.
    captured: list[dict[str, Any]] = []
    for spec in (kwargs.get("capture") or []):
        if not isinstance(spec, dict):
            continue
        header_name = str(spec.get("as_header") or "Authorization")
        prefix = str(spec.get("prefix") or "")
        value = ""
        source = str(spec.get("from") or "body")
        if source == "body" and spec.get("regex"):
            match = re.search(str(spec["regex"]), row.get("body") or "")
            if match:
                value = match.group(1) if match.groups() else match.group(0)
        elif source == "header":
            value = (row.get("headers") or {}).get(str(spec.get("name") or ""), "")
        elif source == "json":
            try:
                node: Any = json.loads(row.get("body") or "{}")
                for part in str(spec.get("path") or "").split("."):
                    node = node[part]
                value = str(node)
            except (ValueError, KeyError, TypeError):
                value = ""
        if value:
            stored_headers[header_name] = prefix + value.strip().strip('"')
            captured.append({"as_header": header_name, "masked": _mask(stored_headers[header_name])})
    if captured:
        sessions.setdefault(name, {})["headers"] = stored_headers
    sessions.setdefault(name, {})["note"] = str(kwargs.get("note") or
                                                sessions.get(name, {}).get("note", ""))
    _write_sessions(ctx, sessions)

    evidence = _save_evidence(ctx, {"request": {"url": url, "method": row.get("method"),
                                                "headers": _headers(headers, keep_host=True),
                                                "body": truncate(redact(str(body or "")), 2000)},
                                   "response": _row_summary(row, 4000),
                                   "session": name, "captured": captured,
                                   "challenge_retry": retry}, prefix="auth")
    summary = _row_summary(row, 1200)
    payload_extra = {"challenge": summary.get("challenge"), "challenge_retry": retry or None}
    payload = {"session": name, "cookies": len(jar), "response": summary,
               "captured_headers": captured, **payload_extra}
    if evidence:
        payload["evidence_path"] = evidence
    text = (f"HTTP {row.get('status')} {row.get('method')} {url} ({row.get('length', 0)} bytes, "
            f"{row.get('ms', 0)} ms) session={name} cookies={len(jar)}"
            + (f" captured={[c['as_header'] for c in captured]}" if captured else "")
            + (f" WALL={retry.get('challenge')}" if retry.get("challenge") else "")
            + (f" retried via {retry.get('source')} cleared={retry.get('cleared')}"
               if retry.get("source") else "")
            + (f" error={row['error']}" if row.get("error") else "")
            + f"\n\n{summary.get('excerpt', '')}")
    return ToolResult.success(payload, text=truncate(text, 8000))


# ---------------------------------------------------------------------------
# tools: differential matrix
# ---------------------------------------------------------------------------


def _path_variants(path: str) -> dict[str, str]:
    base = path.rstrip("/") or "/"
    return {
        "trailing_slash": base + "/",
        "double_slash": base.replace("/", "//", 1) if base.count("/") >= 1 else "//" + base.lstrip("/"),
        "dot_segment": base + "/.",
        "encoded_dot": base + "/%2e",
        "semicolon": base + "/;/" if not base.endswith("/") else base + ";/",
        "extension_json": base + ".json",
        "extension_html": base + ".html",
        "case_upper": base.upper() if base.upper() != base else base.lower(),
        "encoded_slash_tail": base + "%2f",
    }


_PRESET_HEADERS: tuple[tuple[str, dict[str, str]], ...] = (
    ("xff_loopback", {"X-Forwarded-For": "127.0.0.1"}),
    ("xri_loopback", {"X-Real-IP": "127.0.0.1"}),
    ("xff_private", {"X-Forwarded-For": "10.0.0.1, 127.0.0.1"}),
    ("forwarded_proto", {"X-Forwarded-Proto": "https"}),
    ("original_url_root", {"X-Original-URL": "/"}),
    ("rewrite_url_admin", {"X-Rewrite-URL": "/admin"}),
    ("method_override_post", {"X-HTTP-Method-Override": "POST"}),
    ("user_header_admin", {"X-User": "admin", "X-Remote-User": "admin"}),
    ("role_header_admin", {"X-Role": "admin", "X-Forwarded-Role": "admin"}),
    ("trust_auth", {"X-Authenticated-User": "admin", "X-Trusted-Auth": "true"}),
    ("debug_header", {"X-Debug": "1", "X-Requested-With": "XMLHttpRequest"}),
)


def _matrix_variants(family: str, parts: urllib.parse.SplitResult) -> list[dict[str, Any]]:
    path = parts.path or "/"
    rows: list[dict[str, Any]] = []
    fam = family.lower()

    if fam in {"auth_presence", "all"}:
        for label, suffix in _path_variants(path).items():
            rows.append({"label": f"path_{label}", "path": suffix})
        for method in ("HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"):
            rows.append({"label": f"method_{method.lower()}", "method": method})
        for label, headers in _PRESET_HEADERS:
            rows.append({"label": label, "headers": headers})
        rows.append({"label": "method_override_get", "headers": {"X-HTTP-Method-Override": "GET"},
                     "method": "POST"})
        rows.append({"label": "form_method_override", "method": "POST",
                     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                     "body": "_method=GET"})
        rows.append({"label": "no_accept", "headers": {"Accept": ""}})
        rows.append({"label": "accept_text", "headers": {"Accept": "text/plain"}})
    elif fam == "host_header":
        port = f":{parts.port}" if parts.port else ""
        for candidate in ("127.0.0.1", "localhost", parts.hostname or "localhost",
                          "admin." + (parts.hostname or "localhost"),
                          f"{parts.hostname or 'localhost'}:1", f"127.0.0.1{port}"):
            rows.append({"label": f"host_{candidate}", "headers": {"Host": candidate}})
    elif fam == "method_override":
        for override in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            rows.append({"label": f"override_{override.lower()}",
                         "headers": {"X-HTTP-Method-Override": override}, "method": "POST"})
    elif fam == "path_tricks":
        for label, suffix in _path_variants(path).items():
            rows.append({"label": f"path_{label}", "path": suffix})
    elif fam == "header_trust":
        for label, headers in _PRESET_HEADERS:
            rows.append({"label": label, "headers": headers})
    else:
        return []
    return rows


def http_matrix(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    url = str(kwargs.get("url") or "").strip()
    if not url:
        return ToolResult.failure("url is required")
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme:
        return ToolResult.failure("url must be absolute (http:// or https://)")

    variants: list[dict[str, Any]] = []
    family = str(kwargs.get("family") or "").strip()
    if family:
        variants = _matrix_variants(family, parts)
        if not variants:
            return ToolResult.failure(f"unknown family '{family}'",
                                      data={"families": ["auth_presence", "host_header",
                                                         "method_override", "path_tricks",
                                                         "header_trust"]})
    for extra in (kwargs.get("variants") or []):
        if isinstance(extra, dict):
            variants.append(extra)
    if not variants:
        return ToolResult.failure("provide family or variants")
    if len(variants) > MAX_MATRIX_VARIANTS:
        variants = variants[:MAX_MATRIX_VARIANTS]

    session = str(kwargs.get("session") or "")
    jar, session_headers = _session_headers(ctx, session)
    base_headers = dict(session_headers)
    base_headers.update(_headers(kwargs.get("headers"), keep_host=True))
    method = str(kwargs.get("method") or "GET").upper()
    body = kwargs.get("body")
    follow = bool(kwargs.get("follow"))
    token = str(kwargs.get("token") or "{}")
    timeout = clamp_float(kwargs.get("timeout"), 1.0, 60.0, 12.0)
    deadline = time.monotonic() + clamp_float(kwargs.get("max_seconds"), 5.0, 300.0, 90.0)

    def target_url(row: dict[str, Any]) -> str:
        raw = row.get("path")
        if raw is None:
            return url
        text = str(raw)
        if "://" in text:
            return text
        if text.startswith("/"):
            return urllib.parse.urlunsplit((parts.scheme, parts.netloc, text, parts.query, ""))
        return urllib.parse.urljoin(url, text)

    def render(value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(value).replace("{}", token, 1)
        except (TypeError, ValueError):
            return str(value)

    # A wall makes every variant look identical. Resolve a token once, up front, and
    # plant it on every row; record the wall either way so the report cannot read
    # "no difference" where the truth is "blocked".
    wall: dict[str, Any] = {}
    token_note: dict[str, Any] = {}
    injected = ""
    if kwargs.get("token_from") or kwargs.get("challenge_token"):
        probe = _send(ctx, method=method, url=url, headers=base_headers, body=body, session=session,
                      follow=follow, timeout=timeout, max_bytes=4096, jar=jar,
                      client=str(kwargs.get("client") or ""))
        if probe.get("challenge"):
            wall = probe["challenge"]
            token_note = chal.resolve_token(ctx, kwargs, wall, url)
            injected = token_note.get("token") or ""

    matrix: list[dict[str, Any]] = []
    if not any(str(v.get("label") or "") == "baseline" for v in variants):
        base_row = {"label": "baseline", "method": method, "path": None}
        matrix.append({**_send(ctx, method=method, url=url, headers=base_headers, body=body,
                              session=session, follow=follow, timeout=timeout,
                              max_bytes=clamp_int(kwargs.get("max_bytes"), 256, MAX_HTTP_BYTES,
                                                  32768), jar=jar),
                       "label": "baseline"})
    for index, row in enumerate(variants):
        if time.monotonic() > deadline:
            matrix.append({"label": str(row.get("label") or f"v{index}"), "skipped": "deadline"})
            continue
        headers = dict(base_headers)
        headers.update(_headers(row.get("headers"), keep_host=True))
        row_body = render(row.get("body") if row.get("body") is not None else body)
        row_url = target_url(row)
        if injected:
            headers, row_body, row_url, _ = chal.inject(headers, row_body, injected, wall, kwargs,
                                                        row_url)
        attempt = _send(ctx, method=str(row.get("method") or method).upper(), url=row_url,
                        headers=headers, body=row_body,
                        session=session, follow=follow, timeout=timeout,
                        max_bytes=clamp_int(kwargs.get("max_bytes"), 256, MAX_HTTP_BYTES, 32768),
                        jar=jar)
        attempt["label"] = str(row.get("label") or f"v{index}")
        matrix.append(attempt)
    if jar is not None:
        _save_jar(ctx, jar)

    measured = [m for m in matrix if not m.get("skipped")]
    if not measured:
        return ToolResult.failure("no variant completed", data={"matrix": matrix})
    baseline = next((m for m in measured if m.get("label") == "baseline"), measured[0])
    baseline_len = baseline.get("length") or 0

    for row in measured:
        signals: list[str] = []
        if row is not baseline:
            if (row.get("status") or 0) != (baseline.get("status") or 0):
                signals.append(f"status {baseline.get('status')}->{row.get('status')}")
            if row.get("content_type") != baseline.get("content_type"):
                signals.append("content-type")
            if row.get("location") != baseline.get("location"):
                signals.append(f"location {row.get('location') or '—'}")
            if row.get("set_cookie") and not baseline.get("set_cookie"):
                signals.append("set-cookie")
            if row.get("www_authenticate") != baseline.get("www_authenticate"):
                signals.append("www-authenticate")
            delta = abs((row.get("length") or 0) - baseline_len)
            if baseline_len and delta > max(24, baseline_len * 0.05):
                signals.append(f"length±{delta}")
            if row.get("body_sha") != baseline.get("body_sha") and not signals:
                signals.append("body")
        row["verdict"] = "baseline" if row is baseline else ("DIFF" if signals else "same")
        row["signals"] = signals
        markers = sorted(set(m.group(1).lower() for m in _AUTH_MARKERS.finditer(row.get("body") or "")))
        if markers:
            row["auth_markers"] = markers[:6]

    challenged = [r for r in measured if r.get("challenge")]
    flagged = [r for r in measured if r.get("verdict") == "DIFF"]
    evidence = _save_evidence(ctx, {
        "request": {"url": url, "method": method, "headers": base_headers, "body": body,
                    "family": family, "session": session or None},
        "baseline_label": baseline.get("label"),
        "matrix": [_row_summary(r, 1200) | {"label": r.get("label"), "verdict": r.get("verdict"),
                                           "signals": r.get("signals")} for r in measured],
    }, prefix="matrix")

    lines = [f"{len(measured)} variants, baseline={baseline.get('label')} "
             f"({baseline.get('status')}, {baseline_len} bytes), {len(flagged)} differ"
             + (f", WALL {chal.describe(wall)} token={token_note.get('source')}"
                f" cleared={not challenged}" if wall else "")
             + (f", {len(challenged)} rows still walled" if challenged and not wall else "")]
    for row in measured:
        tag = row.get("verdict")
        detail = (";".join(row.get("signals") or []) or row.get("error") or "")
        lines.append(f"  {tag:<8} {row.get('label'):<24} {row.get('method')} {row.get('status'):>3} "
                     f"{row.get('length', 0):>7}B {detail}")
    payload: dict[str, Any] = {"baseline": _row_summary(baseline), "differing": len(flagged),
                               "wall": chal.describe(wall) if wall else "",
                               "wall_rows": len(challenged), "token": token_note or None,
                               "matrix": [_row_summary(r) | {"label": r.get("label"),
                                                             "verdict": r.get("verdict"),
                                                             "signals": r.get("signals"),
                                                             "auth_markers": r.get("auth_markers")}
                                          for r in measured]}
    if evidence:
        payload["evidence_path"] = evidence
    return ToolResult.success(payload, text="\n".join(lines))


# ---------------------------------------------------------------------------
# tools: JWT
# ---------------------------------------------------------------------------


def jwt_inspect(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    token = str(kwargs.get("token") or "").strip()
    if not token and not kwargs.get("forge"):
        return ToolResult.failure("token is required")
    segments = token.split(".") if token else []
    header: dict[str, Any] = {}
    claims: dict[str, Any] = {}
    flags: list[str] = []
    decoded_ok = False

    if len(segments) == 3:
        try:
            header = json.loads(_b64d(segments[0]))
            claims = json.loads(_b64d(segments[1]))
            decoded_ok = True
        except (ValueError, TypeError, base64.binascii.Error):
            flags.append("undecodable segments")
    elif token:
        flags.append("not a 3-segment JWT")

    if decoded_ok:
        alg = str(header.get("alg") or "").lower()
        if alg == "none":
            flags.append("alg=none (unsigned)")
        if "kid" in header:
            flags.append(f"kid present: {truncate(str(header['kid']), 80)}")
        if "jku" in header or "x5u" in header:
            flags.append("remote key reference (jku/x5u) — try pointing at your own host")
        if "jwk" in header:
            flags.append("embedded jwk")
        exp = claims.get("exp")
        if exp is None:
            flags.append("no exp claim (token never expires)")
        else:
            try:
                remaining = int(exp) - int(time.time())
                if remaining <= 0:
                    flags.append(f"expired {abs(remaining)}s ago")
                elif remaining < 3600:
                    flags.append(f"expires in {remaining}s")
            except (TypeError, ValueError):
                flags.append("non-numeric exp")
        for key in ("role", "roles", "admin", "is_admin", "scope", "scopes", "group", "groups",
                    "permissions", "tenant", "org", "sub"):
            if key in claims:
                flags.append(f"privilege-ish claim '{key}' = {truncate(json_dumps(claims[key]), 60)}")
        if isinstance(claims.get("admin"), str):
            flags.append("admin claim is a string (try \"true\"/true juggling)")

    # Secret check / crack (HMAC only).
    secret = kwargs.get("secret")
    verdict = ""
    if decoded_ok and secret:
        alg = str(header.get("alg") or "").upper()
        expected = hmac.new(str(secret).encode(), f"{segments[0]}.{segments[1]}".encode(),
                            {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                             "HS512": hashlib.sha512}.get(alg, hashlib.sha256)).digest()
        try:
            actual = _b64d(segments[2])
        except (ValueError, base64.binascii.Error):
            actual = b""
        verdict = "secret MATCHES" if hmac.compare_digest(expected, actual) else "secret does NOT match"
        flags.append(verdict)

    cracked = ""
    if decoded_ok and kwargs.get("crack") and str(header.get("alg") or "").upper().startswith("HS"):
        candidates = list(_JWT_WORDLIST)
        wordlist = kwargs.get("wordlist")
        if isinstance(wordlist, str) and wordlist:
            path = Path(wordlist) if Path(wordlist).is_absolute() else Path(ctx.workdir) / wordlist
            try:
                candidates += [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                               if line.strip()][:20000]
            except OSError:
                flags.append(f"wordlist not readable: {wordlist}")
        for candidate in candidates:
            expected = hmac.new(candidate.encode(), f"{segments[0]}.{segments[1]}".encode(),
                                {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                                 "HS512": hashlib.sha512}.get(str(header.get("alg") or "").upper(),
                                                              hashlib.sha256)).digest()
            try:
                okay = hmac.compare_digest(expected, _b64d(segments[2]))
            except (ValueError, base64.binascii.Error):
                okay = False
            if okay:
                cracked = candidate
                flags.append(f"CRACKED secret: {candidate}")
                break
        if not cracked:
            flags.append(f"no secret in {len(candidates)} candidates")

    forged = ""
    spec = kwargs.get("forge")
    if isinstance(spec, dict):
        new_header = dict(header) or {"alg": "HS256", "typ": "JWT"}
        new_header.update(spec.get("header") or {})
        new_claims = dict(claims)
        new_claims.update(spec.get("claims") or {})
        key = str(spec.get("secret") or secret or cracked or "")
        alg = str(new_header.get("alg") or "HS256").upper()
        signing_input = (f"{_b64e(json_dumps(new_header).encode())}."
                         f"{_b64e(json_dumps(new_claims).encode())}")
        if alg == "NONE":
            forged = signing_input + "."
        elif key:
            digest = hmac.new(key.encode(), signing_input.encode(),
                              {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                               "HS512": hashlib.sha512}.get(alg, hashlib.sha256)).digest()
            forged = f"{signing_input}.{_b64e(digest)}"
        else:
            flags.append("forge needs a secret for HMAC (or set header.alg=none)")
        if forged:
            flags.append(f"forged token produced (alg={alg})")

    evidence = _save_evidence(ctx, {"token_masked": _mask(token) if token else None,
                                    "header": header, "claims": claims, "flags": flags,
                                    "cracked_secret": cracked or None, "forged_masked":
                                    _mask(forged) if forged else None}, prefix="jwt")
    payload: dict[str, Any] = {"header": header, "claims": claims, "flags": flags,
                               "cracked_secret": cracked or None,
                               "forged": forged or None}
    if evidence:
        payload["evidence_path"] = evidence
    text_lines = [f"header: {json_dumps(header)}", f"claims: {truncate(json_dumps(claims), 1500)}",
                  "flags: " + ("; ".join(flags) if flags else "none")] 
    if forged:
        text_lines.append(f"forged: {forged}")
    return ToolResult.success(payload, text="\n".join(text_lines))


# ---------------------------------------------------------------------------
# tools: route / secret mining
# ---------------------------------------------------------------------------


def _extract(text: str, base: str = "") -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"paths": [], "urls": [], "secrets": [], "roles": [],
                                   "sourcemaps": [], "graphql": []}

    def add(bucket: str, value: str) -> None:
        value = value.strip()
        if value and value not in found[bucket] and len(found[bucket]) < 400:
            found[bucket].append(value)

    for pattern in _ROUTE_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1)
            (add("urls", value) if value.startswith(("http://", "https://", "ws://", "wss://"))
             else add("paths", value))
    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            add("secrets", f"{label}:{value}")
    for match in re.finditer(r"(?i)\b(?:is_?admin|isAdmin|admin|role|roles|scope|"
                             r"permissions?|feature_?flags?)\b\s*[:=]\s*[^,;}\n]{1,60}", text):
        add("roles", match.group(0).strip()[:100])
    for match in re.finditer(r"(?i)sourceMappingURL=([^\s*'\"]+)", text):
        raw = match.group(1)
        # resolve against the file it was found in, not the document
        add("sourcemaps", urllib.parse.urljoin(base or "http://x/", raw) if base else raw)
    for match in re.finditer(r"(?i)\b(query|mutation)\s+([A-Za-z0-9_]{2,60})\s*[({]", text):
        add("graphql", f"{match.group(1)} {match.group(2)}")
    return found


def route_mine(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    url = str(kwargs.get("url") or "").strip()
    if not url:
        return ToolResult.failure("url is required (the document to mine, not a directory)")
    max_scripts = clamp_int(kwargs.get("max_scripts"), 0, 20, 8)
    max_bytes = clamp_int(kwargs.get("max_bytes"), 1024, 500_000, 200_000)
    parts = urllib.parse.urlsplit(url)

    row = _send(ctx, url=url, max_bytes=max_bytes)
    if row.get("error") and not row.get("status"):
        return ToolResult.failure(f"fetch failed: {row['error']}", data={"url": url})
    document = row.get("body") or ""
    inventory = _extract(document, url)

    scripts: list[str] = []
    for match in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", document, re.I):
        absolute = urllib.parse.urljoin(url, match.group(1))
        if urllib.parse.urlsplit(absolute).netloc == parts.netloc and absolute not in scripts:
            scripts.append(absolute)
    for match in re.finditer(r"""["'`]([^"'`]+\.m?js(?:\?[^"'`]*)?)["'`]""", document):
        absolute = urllib.parse.urljoin(url, match.group(1))
        if urllib.parse.urlsplit(absolute).netloc == parts.netloc and absolute not in scripts:
            scripts.append(absolute)

    fetched: list[dict[str, Any]] = []
    for script in scripts[:max_scripts]:
        sub = _send(ctx, url=script, max_bytes=max_bytes)
        sub_extract = _extract(sub.get("body") or "", script)
        for bucket, values in sub_extract.items():
            for value in values:
                if value not in inventory[bucket] and len(inventory[bucket]) < 400:
                    inventory[bucket].append(value)
        fetched.append({"url": script, "status": sub.get("status"), "bytes": sub.get("length"),
                        "found": sum(len(v) for v in sub_extract.values())})

    # Source maps: fetch and mine sourcesContent which often carries the real source.
    maps: list[dict[str, Any]] = []
    for map_url in list(inventory["sourcemaps"])[:6]:
        absolute = urllib.parse.urljoin(url, map_url if map_url.startswith("http") else
                                        urllib.parse.urljoin(url, map_url))
        sub = _send(ctx, url=absolute, max_bytes=max_bytes)
        if sub.get("status") and 200 <= sub["status"] < 300:
            body = sub.get("body") or ""
            names = re.findall(r'"([^"]*\.(?:ts|tsx|js|jsx|vue|svelte))"', body)
            for name in names[:60]:
                if name not in inventory["paths"]:
                    inventory["paths"].append(name)
            # sourcesContent carries the original text: mine it like any source
            for bucket, values in _extract(body, absolute).items():
                for value in values:
                    if value not in inventory[bucket] and len(inventory[bucket]) < 400:
                        inventory[bucket].append(value)
            maps.append({"map": absolute, "status": sub["status"], "bytes": sub.get("length"),
                         "sources": len(set(names))})
    if not maps and inventory["sourcemaps"]:
        inventory["paths"].append("/** sourceMappingURL present but not fetched: see sourcemaps **")

    evidence = _save_evidence(ctx, {"url": url, "document": _row_summary(row, 2000),
                                    "scripts": fetched, "maps": maps, "inventory": inventory},
                              prefix="route_mine")
    payload: dict[str, Any] = {"document": {"status": row.get("status"),
                                            "bytes": row.get("length"),
                                            "content_type": row.get("content_type")},
                               "scripts_fetched": fetched, "sourcemaps": maps,
                               "inventory": inventory,
                               "counts": {k: len(v) for k, v in inventory.items()}}
    if evidence:
        payload["evidence_path"] = evidence
    text = (f"{row.get('status')} {url} ({row.get('length', 0)} bytes)\n"
            f"script refs: {len(scripts)} fetched {len(fetched)} | maps: {len(maps)}\n"
            f"paths {len(inventory['paths'])} · urls {len(inventory['urls'])} · "
            f"secrets {len(inventory['secrets'])} · graphql {len(inventory['graphql'])}\n\n"
            + "\n".join(f"  {p}" for p in inventory["paths"][:40])
            + ("\nsecrets:\n" + "\n".join(f"  {redact(s)}" for s in inventory["secrets"][:20])
               if inventory["secrets"] else ""))
    return ToolResult.success(payload, text=truncate(text, 9000))


# ---------------------------------------------------------------------------
# tools: artifact probe
# ---------------------------------------------------------------------------


def _sniff(body: str, content_type: str) -> str:
    head = (body or "")[:400]
    ctype = (content_type or "").lower()
    if head.startswith("PK\x03\x04"):
        return "zip"
    if head.startswith("<?php"):
        return "php-source"
    if re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=.{1,400}$", body or "") and \
            len(re.findall(r"(?m)^[A-Z][A-Z0-9_]{2,}=", body or "")) >= 2:
        return "env-file"
    if re.search(r"(?im)^-- (mysql|postgresql) dump|^INSERT INTO|^CREATE TABLE", body or ""):
        return "sql-dump"
    if re.search(r"(?m)^\[(?:core|remote|branch|user|http)\]", body or "") and \
            "repositoryformatversion" in (body or ""):
        return "git-config"
    if re.match(r"^(ref: |commit |tree |[0-9a-f]{40})", head) and ctype != "application/json":
        return "git-object"
    if head.startswith(("{", "[")) and "sourceRoot" in (body or "")[:4000] or '"mappings"' in (body or "")[:4000]:
        return "sourcemap"
    if head.startswith("BEGIN OPENSSH PRIVATE KEY") or "BEGIN RSA PRIVATE KEY" in body:
        return "private-key"
    if re.search(r"(?i)^\s*[\[;{]?\s*(DB_|DATABASE_|APP_KEY|SECRET|API_KEY|MAIL_)", head):
        return "env-file"
    if re.search(r"(?im)^\s*(?:name|description|version|installed)\s*[:=]", head) and "{" in head:
        return "package-manifest"
    if re.search(r"(?i)<(?:html|servlet)|Web-Application", head):
        return "xml-or-html"
    return ctype or "unknown"


def artifact_probe(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    base = str(kwargs.get("base_url") or "").strip()
    if not base:
        return ToolResult.failure("base_url is required")
    tier = str(kwargs.get("tier") or "s")
    paths: list[str] = []
    for name in re.split(r"[,\s]+", tier):
        paths += list(_ARTIFACT_PATHS.get(name, ()))
    for extra in (kwargs.get("paths") or []):
        if isinstance(extra, str):
            paths.append(extra)
    if not paths:
        return ToolResult.failure(f"no paths (tier must be one of {sorted(_ARTIFACT_PATHS)})")
    paths = list(dict.fromkeys(p.strip("/") for p in paths))
    max_paths = clamp_int(kwargs.get("max_paths"), 1, 200, 80)
    paths = paths[:max_paths]
    soft = bool(kwargs.get("soft_404", True))
    save = bool(kwargs.get("save", True))
    timeout = clamp_float(kwargs.get("timeout"), 1.0, 30.0, 8.0)
    deadline = time.monotonic() + clamp_float(kwargs.get("max_seconds"), 5.0, 300.0, 120.0)

    # Establish the soft-404 signature before probing anything real.
    soft_len = -1
    if soft:
        probe = _send(ctx, url=urllib.parse.urljoin(base + "/", "__ariax_probe_9f3__"), timeout=timeout,
                      max_bytes=4096)
        soft_len = probe.get("length") or -1

    rows: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    for path in paths:
        if time.monotonic() > deadline:
            rows.append({"path": path, "verdict": "skipped"})
            continue
        target = urllib.parse.urljoin(base.rstrip("/") + "/", path)
        row = _send(ctx, url=target, timeout=timeout, max_bytes=clamp_int(kwargs.get("max_bytes"),
                                                                          256, 400_000, 120_000))
        status = row.get("status") or 0
        length = row.get("length") or 0
        verdict = "MISS"
        if status == 0:
            verdict = "ERROR"
        elif status in (401, 403):
            verdict = "AUTHED" if status == 403 else "LOCKED"
        elif 200 <= status < 300:
            body = row.get("body") or ""
            if soft and soft_len >= 0 and abs(length - soft_len) <= max(48, soft_len * 0.25):
                verdict = "SOFT404"
            elif (row.get("content_type") or "").startswith("text/html") and \
                    re.search(r"(?i)<title>\s*(404|not found)", body[:2000]):
                verdict = "SOFT404"
            else:
                verdict = "HIT"
        else:
            verdict = f"HTTP{status}"
        info = {"path": path, "status": status, "length": length, "verdict": verdict,
                "content_type": row.get("content_type"), "body_sha": row.get("body_sha"),
                "elapsed_ms": row.get("ms")}
        if verdict == "HIT":
            info["sniff"] = _sniff(row.get("body") or "", row.get("content_type") or "")
            if save:
                data = (row.get("body") or "").encode("utf-8", "replace")
                evidence = _save_evidence(ctx, {
                    "url": target, "status": status, "content_type": row.get("content_type"),
                    "sha256_raw": hashlib.sha256(data).hexdigest(), "bytes": length,
                    "excerpt": truncate(redact(row.get("body") or ""), 6000)}, prefix="artifact")
                if evidence:
                    info["evidence_path"] = evidence
            hits.append(info)
        rows.append(info)

    evidence = _save_evidence(ctx, {"base": base, "tier": tier, "soft_404_length": soft_len,
                                    "rows": rows}, prefix="artifact_index")
    payload = {"base_url": base, "probed": len(rows), "hits": len(hits),
               "hit_rows": hits, "rows": rows, "soft_404_length": soft_len,
               "misses": [r["path"] for r in rows if r.get("verdict") in {"MISS", "SOFT404"}]}
    if evidence:
        payload["evidence_index"] = evidence
    text = [f"{len(rows)} probed · {len(hits)} HIT · soft-404 baseline {soft_len if soft_len >= 0 else 'off'}"]
    for row in rows:
        if row.get("verdict") not in {"MISS", "SOFT404", "skipped"}:
            text.append(f"  {row['verdict']:<8} {row.get('status'):>3} {row.get('length', 0):>8}B "
                        f"{row.get('sniff', row.get('content_type') or ''):<18} {row['path']}")
    return ToolResult.success(payload, text=truncate("\n".join(text), 9000))


# ---------------------------------------------------------------------------
# tools: code probe (one-time codes, tokens, limiters)
# ---------------------------------------------------------------------------


def code_probe(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    url = str(kwargs.get("url") or "").strip()
    if not url:
        return ToolResult.failure("url is required and must contain '{}' for the code")
    charset = str(kwargs.get("charset") or "0123456789")
    length = clamp_int(kwargs.get("length"), 1, 16, 4)
    start = clamp_int(kwargs.get("start"), 0, 10 ** length, 0)
    max_attempts = clamp_int(kwargs.get("max_attempts"), 1, MAX_ATTEMPTS, 40)
    method = str(kwargs.get("method") or "POST").upper()
    field = str(kwargs.get("field") or "code")
    body_template = kwargs.get("body")
    session = str(kwargs.get("session") or "")
    jar, session_headers = _session_headers(ctx, session)
    headers = dict(session_headers)
    headers.update(_headers(kwargs.get("headers")))
    timeout = clamp_float(kwargs.get("timeout"), 1.0, 30.0, 10.0)
    max_seconds = clamp_float(kwargs.get("max_seconds"), 5.0, 600.0, 120.0)
    deadline = time.monotonic() + max_seconds
    match_re = re.compile(str(kwargs["match"])) if kwargs.get("match") else None
    xff = bool(kwargs.get("xff_rotate"))
    counter_field = str(kwargs.get("counter_field") or "")
    counter_start = clamp_int(kwargs.get("counter_start"), 0, 10 ** 9, 1)

    def code_at(index: int) -> str:
        digits: list[str] = []
        value = start + index
        for _ in range(length):
            digits.append(charset[value % len(charset)])
            value //= len(charset)
        return "".join(reversed(digits))

    def request(code: str, index: int) -> dict[str, Any]:
        local = dict(headers)
        if xff:
            local["X-Forwarded-For"] = f"10.{index % 250}.{(index // 250) % 250}.{(index + 1) % 250}"
        if body_template is None:
            payload = urllib.parse.urlencode({field: code})
            local.setdefault("Content-Type", "application/x-www-form-urlencoded")
            target = url
        else:
            payload = str(body_template).replace("{}", code)
            if counter_field:
                payload = payload.replace("{{n}}", str(counter_start + index))
            target = url
        if "{}" in target:
            target = target.replace("{}", code)
        if injected_token:
            local, payload, target, _ = chal.inject(local, payload, injected_token,
                                                    token_wall or {}, kwargs, target)
        return _send(ctx, method=method, url=target, headers=local, body=payload,
                     timeout=timeout, max_bytes=clamp_int(kwargs.get("max_bytes"), 256, 200_000,
                                                          16384), jar=jar,
                     client=str(kwargs.get("client") or ""))

    injected_token = ""
    token_wall: dict[str, Any] = {}
    challenge_log: dict[str, Any] = {}

    space = len(charset) ** length
    max_attempts = min(max_attempts, max(1, space - start))
    baseline = request("_invalid_", 0)
    if baseline.get("error") and not baseline.get("status"):
        return ToolResult.failure(f"baseline request failed: {baseline['error']}")
    # A wall swallows every attempt identically. Deal with it before spending budget.
    if baseline.get("challenge"):
        token_wall = baseline["challenge"]
        solution = chal.resolve_token(ctx, kwargs, token_wall, url)
        challenge_log = {"wall": chal.describe(token_wall), **solution}
        if solution.get("token"):
            injected_token = solution["token"]
            baseline = request("_invalid_", 0)
            challenge_log["cleared"] = not baseline.get("challenge")
        if baseline.get("challenge"):
            blocked = {"blocked": True, "found": [], "candidates": [],
                       "wall": chal.describe(baseline["challenge"]),
                       "reaction": baseline["challenge"].get("reaction"),
                       "token": challenge_log, "attempts": 1,
                       "baseline": _row_summary(baseline)}
            evidence = _save_evidence(ctx, {"url": url, "blocked": blocked}, prefix="code_probe")
            if evidence:
                blocked["evidence_path"] = evidence
            return ToolResult.success(
                blocked, text=(f"BLOCKED by {blocked['wall']} before enumeration: "
                               f"{blocked['reaction']}\ntoken channel: "
                               f"{challenge_log.get('source') or 'none'} "
                               f"({challenge_log.get('detail')})"))
    base_status = baseline.get("status") or 0
    base_len = baseline.get("length") or 0
    base_sha = baseline.get("body_sha")

    attempts = 0
    consecutive = 0
    candidates: list[dict[str, Any]] = []
    found: list[dict[str, Any]] = []
    started = time.monotonic()
    for index in range(max_attempts):
        if time.monotonic() > deadline:
            break
        code = code_at(index)
        row = request(code, index + 1)
        attempts += 1
        if row.get("challenge"):
            challenge_log.setdefault("rows", []).append(code)
            consecutive += 1
            if consecutive >= 2 and not injected_token:
                break  # every remaining attempt would come back as the wall
        else:
            consecutive = 0
        status = row.get("status") or 0
        signals = []
        if status != base_status:
            signals.append(f"status {base_status}->{status}")
        if row.get("body_sha") != base_sha:
            delta = abs((row.get("length") or 0) - base_len)
            if delta > max(20, base_len * 0.05):
                signals.append(f"length±{delta}")
            elif row.get("body_sha") != base_sha:
                signals.append("body")
        matched = bool(match_re and match_re.search(row.get("body") or ""))
        if matched:
            signals.append("match")
        if signals:
            entry = {"code": code, "status": status, "length": row.get("length"),
                     "signals": signals, "matched": matched,
                     "excerpt": truncate(re.sub(r"\s+", " ", row.get("body") or ""), 220)}
            (found if matched else candidates).append(entry)
            if matched and kwargs.get("stop_on_match", True):
                break
    if jar is not None:
        _save_jar(ctx, jar)

    elapsed = max(0.001, time.monotonic() - started)
    rate = attempts / elapsed
    evidence = _save_evidence(ctx, {"url": url, "method": method, "field": field,
                                    "space": space, "attempts": attempts, "found": found,
                                    "candidates": candidates[:60],
                                    "baseline": _row_summary(baseline)}, prefix="code_probe")
    coverage = attempts / space if space else 0
    payload: dict[str, Any] = {
        "challenge": challenge_log or None, "blocked": bool(challenge_log and not injected_token),
        "space": space, "attempts": attempts, "rate_per_s": round(rate, 2),
        "coverage": round(coverage, 4),
        "eta_seconds_full_space": round(space / rate, 1) if rate else None,
        "found": found, "candidates": candidates[:20], "baseline": _row_summary(baseline)}
    if evidence:
        payload["evidence_path"] = evidence
    verdict = ("FOUND " + ", ".join(f["code"] for f in found[:5])) if found else \
              (f"{len(candidates)} candidate(s), unconfirmed" if candidates else "no candidate")
    text = (f"{attempts}/{space} tried ({coverage * 100:.2f}% of space) at {rate:.1f} req/s — {verdict}\n"
            f"baseline {base_status} / {base_len}B\n"
            + "\n".join(f"  {c['code']} {c['status']} {c['length']}B {','.join(c['signals'])}: "
                        f"{c['excerpt'][:140]}" for c in (found + candidates)[:12]))
    return ToolResult.success(payload, text=truncate(text, 8000))


# ---------------------------------------------------------------------------
# tools: object-reference walk
# ---------------------------------------------------------------------------


def id_walk(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    url = str(kwargs.get("url") or "").strip()
    if not url or "{}" not in url:
        return ToolResult.failure("url is required and must contain '{}' for the identifier")
    ids: list[str] = [str(i) for i in (kwargs.get("ids") or [])]
    start = clamp_int(kwargs.get("start"), -10 ** 12, 10 ** 12, 1)
    count = clamp_int(kwargs.get("count"), 1, 200, 12)
    if not ids:
        ids = [str(start + offset) for offset in range(count)]
    ids = ids[:200]
    session = str(kwargs.get("session") or "")
    jar, session_headers = _session_headers(ctx, session)
    headers = dict(session_headers)
    headers.update(_headers(kwargs.get("headers")))
    marker = re.compile(str(kwargs["marker"])) if kwargs.get("marker") else None
    timeout = clamp_float(kwargs.get("timeout"), 1.0, 30.0, 10.0)
    deadline = time.monotonic() + clamp_float(kwargs.get("max_seconds"), 5.0, 300.0, 90.0)

    rows: list[dict[str, Any]] = []
    for identifier in ids:
        if time.monotonic() > deadline:
            break
        row = _send(ctx, url=url.replace("{}", identifier), headers=headers, timeout=timeout,
                    max_bytes=clamp_int(kwargs.get("max_bytes"), 256, 200_000, 32768), jar=jar)
        rows.append({"id": identifier, "status": row.get("status"), "length": row.get("length"),
                     "body_sha": row.get("body_sha"), "ms": row.get("ms"),
                     "excerpt": truncate(re.sub(r"\s+", " ", row.get("body") or ""), 200),
                     "marker": bool(marker and marker.search(row.get("body") or ""))})
    if jar is not None:
        _save_jar(ctx, jar)

    lengths = sorted(r["length"] for r in rows if r.get("status") and 200 <= r["status"] < 300)
    if lengths:
        median = lengths[len(lengths) // 2]
        spread = sorted(abs(value - median) for value in lengths)
        mad = spread[len(spread) // 2] or 1
    else:
        median, mad = 0, 1
    for row in rows:
        deviation = abs((row.get("length") or 0) - median) / max(mad, 8)
        row["deviation"] = round(deviation, 1)
        row["flag"] = (row.get("status") in (401, 403, 500) or row.get("marker")
                       or (row.get("status") and 200 <= row["status"] < 300 and deviation >= 2.0))
    flagged = [r for r in rows if r.get("flag")]
    evidence = _save_evidence(ctx, {"url": url, "median_length": median, "rows": rows},
                              prefix="id_walk")
    payload: dict[str, Any] = {"probed": len(rows), "median_length": median,
                               "flagged": flagged, "rows": rows}
    if evidence:
        payload["evidence_path"] = evidence
    text = (f"{len(rows)} ids probed, median 200-length {median}B, {len(flagged)} flagged\n"
            + "\n".join(f"  {'FLAG' if r['flag'] else '    '} {r['id']:<14} {r.get('status')} "
                        f"{r.get('length')}B dev={r['deviation']} {r['excerpt'][:110]}"
                        for r in rows[:40]))
    return ToolResult.success(payload, text=truncate(text, 9000))




# ---------------------------------------------------------------------------
# tools: headless browser (JS walls, rendered DOM, cookie minting)
# ---------------------------------------------------------------------------


def browser_session(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    """Drive a real headless browser: the only lane that clears a JS challenge."""
    action = str(kwargs.get("action") or "open").lower()
    settle = clamp_int(kwargs.get("settle_ms"), 200, 30_000, 3500)
    state = br.read_state(Path(ctx.workdir))

    if action == "close":
        killed = br.shutdown(Path(ctx.workdir))
        return ToolResult.success({"closed": True, "killed": killed}, text="browser closed")

    if action in {"open", "read", "cookies", "eval", "shot"} and not state.get("browser_ws"):
        try:
            br.launch(Path(ctx.workdir), user_agent=str(kwargs.get("user_agent") or ""))
        except OSError as exc:
            return ToolResult.failure(f"browser launch failed: {exc}")

    try:
        ws = br.connect(Path(ctx.workdir))
    except OSError as exc:
        return ToolResult.failure(f"browser not reachable: {exc}")
    try:
        session_id = br._ensure_page(ws, Path(ctx.workdir))
        url = str(kwargs.get("url") or "").strip()

        if action == "eval":
            expression = str(kwargs.get("expression") or "1")
            if url:
                ctx.scope.require_url(url)
                br.navigate(ws, session_id, url, settle_ms=settle)
            value = br.evaluate(ws, session_id, expression)
            return ToolResult.success({"url": url or None, "value": value},
                                      text=truncate(json_dumps(value), 4000))

        if action == "cookies":
            host = str(kwargs.get("host") or "").strip()
            if not host and url:
                host = urllib.parse.urlsplit(url).hostname or ""
            if not host:
                return ToolResult.failure("host or url is required")
            harvest = [c for c in br.cookies(ws, session_id)
                       if br.domain_matches(str(c.get("domain", "")), host)]
            target = str(kwargs.get("import_to") or "")
            imported = 0
            if target and harvest:
                sessions = _sessions(ctx)
                jar, _ = _session_headers(ctx, target)
                if jar is None:
                    jar = http.cookiejar.MozillaCookieJar(str(_jar_path(ctx, target)))
                    sessions[target] = sessions.get(target) or {}
                for cookie in harvest:
                    _jar_put(jar, cookie)
                    imported += 1
                _save_jar(ctx, jar)
                _write_sessions(ctx, sessions)
            names = sorted({str(c.get("name")) for c in harvest})
            evidence = _save_evidence(ctx, {"host": host, "names": names,
                                            "count": len(harvest), "imported_to": target or None},
                                      prefix="cookie_harvest")
            payload = {"host": host, "count": len(harvest), "names": names,
                       "imported_to": target or None, "imported": imported}
            if evidence:
                payload["evidence_path"] = evidence
            return ToolResult.success(payload,
                                      text=f"{len(harvest)} cookies for {host}: {names}"
                                      + (f" (imported into '{target}')" if imported else ""))

        if action == "shot":
            target_path = Path(ctx.workdir) / "evidence" / f"shot_{int(time.time() * 1000)}.png"
            size = br.screenshot(ws, session_id, target_path)
            rel = str(target_path.relative_to(Path(ctx.workdir).resolve()))
            return ToolResult.success({"path": rel, "bytes": size},
                                      text=f"screenshot {rel} ({size} bytes)")

        if action not in {"open", "read"}:
            return ToolResult.failure(f"unknown action '{action}'",
                                      data={"actions": ["open", "read", "cookies", "eval",
                                                        "shot", "close"]})
        if not url:
            return ToolResult.failure("url is required for open/read")

        decision = ctx.scope.require_url(url)
        ctx.scope.acquire_slot(decision.host or "")

        # The browser IS the solver: give the challenge script room to finish and
        # re-read until it clears or the patience budget is gone. A captcha widget
        # never clears on its own, so stop early for that kind.
        # One navigation, then poll IN PLACE. Re-navigating restarts the challenge
        # from zero every time — a real browser load clears itself and moves on, so
        # the wall disappearing is a change in the DOM, not a new request.
        patience = clamp_float(kwargs.get("wait"), 0.0, 120.0, 20.0)
        deadline = time.monotonic() + patience
        wall: dict[str, Any] | None = None
        doc: dict[str, Any] = {}
        rounds = 0
        br.navigate(ws, session_id, url, settle_ms=settle)
        while True:
            doc = br.document(ws, session_id)
            wall = chal.detect(200, {}, doc.get("html") or "")
            rounds += 1
            if not wall or time.monotonic() > deadline:
                break
            if wall.get("kind") in {"captcha", "block"} and rounds >= 2:
                # a widget will not clear itself: keep a short look, then give up
                if rounds >= 4 or time.monotonic() > deadline - patience / 3:
                    break
            time.sleep(2.0 if wall.get("kind") == "js-challenge" else 3.0)

        html = doc.get("html") or ""
        host = decision.host or ""
        imported_cookies: list[str] = []
        target = str(kwargs.get("import_to") or "")
        if target and host:
            sessions = _sessions(ctx)
            jar, _ = _session_headers(ctx, target)
            if jar is None:
                jar = http.cookiejar.MozillaCookieJar(str(_jar_path(ctx, target)))
                sessions[target] = sessions.get(target) or {}
            _write_sessions(ctx, sessions)
            for cookie in br.cookies(ws, session_id):
                if not br.domain_matches(str(cookie.get("domain", "")), host):
                    continue
                _jar_put(jar, cookie)
                imported_cookies.append(str(cookie.get("name")))
            _save_jar(ctx, jar)
            if imported_cookies:
                # A clearance cookie is bound to the client's UA hash: replay it
                # with a different UA and Cloudflare issues a fresh challenge. Carry
                # the browser's own UA on the session so plain HTTP inherits it.
                try:
                    browser_ua = str(br.evaluate(ws, session_id, "navigator.userAgent") or "")
                except (OSError, ValueError):
                    browser_ua = ""
                if browser_ua:
                    sessions.setdefault(target, {})["headers"] = {
                        **(sessions.get(target, {}).get("headers") or {}),
                        "User-Agent": browser_ua}
                    sessions[target]["note"] = "seeded by browser_session (UA carried)"
                    _write_sessions(ctx, sessions)

        shot = ""
        if kwargs.get("screenshot"):
            path = Path(ctx.workdir) / "evidence" / f"shot_{int(time.time() * 1000)}.png"
            try:
                br.screenshot(ws, session_id, path)
                shot = str(path.relative_to(Path(ctx.workdir).resolve()))
            except OSError:
                shot = ""
        excerpt = truncate(re.sub(r"\s+", " ", html),
                           clamp_int(kwargs.get("max_chars"), 200, 20000, 3000))
        evidence = _save_evidence(ctx, {"url": url, "final_url": doc.get("url"),
                                        "title": doc.get("title"), "challenge": wall,
                                        "rounds": rounds, "imported_cookies": imported_cookies,
                                        "html_excerpt": excerpt, "screenshot": shot or None},
                                  prefix="browser")
        payload: dict[str, Any] = {
            "url": url, "final_url": doc.get("url"), "title": doc.get("title"),
            "html_bytes": len(html), "rounds": rounds,
            "challenge": chal.describe(wall) if wall else "",
            "cleared": bool(wall is None),
            "imported_cookies": imported_cookies, "screenshot": shot or None, "excerpt": excerpt}
        if evidence:
            payload["evidence_path"] = evidence
        text = (f"{doc.get('title') or '(no title)'} — {doc.get('url') or url}\n"
                f"{len(html)} bytes rendered, {rounds} round(s)"
                + (f", WALL {chal.describe(wall)}" if wall else ", no wall")
                + (f", imported {len(imported_cookies)} cookies into '{target}'"
                   if imported_cookies else "")
                + f"\n\n{excerpt}")
        return ToolResult.success(payload, text=truncate(text, 9000))
    except (OSError, ValueError) as exc:
        return ToolResult.failure(f"browser action failed: {exc}", data={"action": action})
    finally:
        ws.close()


def _jar_put(jar: http.cookiejar.MozillaCookieJar, cookie: dict[str, Any]) -> None:
    """A CDP cookie dict → an http.cookiejar.Cookie (argument order matters)."""
    domain = str(cookie.get("domain") or "")
    jar.set_cookie(http.cookiejar.Cookie(
        version=0, name=str(cookie.get("name")), value=str(cookie.get("value")),
        port=None, port_specified=False,
        # host-only cookie unless the server scoped it to a parent domain
        domain=domain.lstrip("."), domain_specified=domain.startswith("."),
        domain_initial_dot=domain.startswith("."),
        path=str(cookie.get("path") or "/"), path_specified=True,
        secure=bool(cookie.get("secure")),
        # CDP reports -1 for a session cookie; a literal -1 in cookiejar is never sent
        expires=None if (cookie.get("expires") or 0) <= 0 else cookie.get("expires"),
        discard=(cookie.get("expires") or 0) <= 0,
        comment=None, comment_url=None, rest={"HttpOnly": True} if cookie.get("httpOnly") else {},
        rfc2109=False))




# ---------------------------------------------------------------------------
# tools: JWT signing (RS*/ES*, alg=none, HS-confusion)
# ---------------------------------------------------------------------------


def jwt_sign(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    alg = str(kwargs.get("alg") or "").strip()
    claims = kwargs.get("claims")
    if not alg:
        return ToolResult.failure("alg is required",
                                  data={"alg": ["none", "HS256", "RS256", "RS384", "RS512", "ES256"]})
    if not isinstance(claims, dict) or not claims:
        return ToolResult.failure("claims must be a non-empty object")
    key_pem = str(kwargs.get("key_pem") or "")
    key_file = str(kwargs.get("key_file") or "")
    if key_file and not key_pem:
        path = Path(key_file) if Path(key_file).is_absolute() else Path(ctx.workdir) / key_file
        try:
            key_pem = path.read_text(encoding="utf-8")
        except OSError as exc:
            return ToolResult.failure(f"key_file unreadable: {exc}")
    try:
        signed = jwtkeys.sign(alg, claims, key_pem=key_pem,
                              header=kwargs.get("header"),
                              hmac_secret=str(kwargs.get("hmac_secret") or ""))
    except (ValueError, IndexError, KeyError) as exc:
        return ToolResult.failure(f"signing failed: {exc}")

    verdict = None
    if kwargs.get("verify"):
        try:
            verdict = jwtkeys.verify(signed["token"], key_pem=key_pem,
                                     hmac_secret=str(kwargs.get("hmac_secret") or ""))
        except ValueError as exc:
            verdict = {"valid": False, "detail": str(exc)}
    evidence = _save_evidence(ctx, {"alg": signed["alg"], "note": signed["note"],
                                    "claims": claims, "header": kwargs.get("header"),
                                    "token_masked": _mask(signed["token"]),
                                    "verdict": verdict}, prefix="jwt_sign")
    payload: dict[str, Any] = {"token": signed["token"], "alg": signed["alg"],
                               "note": signed["note"], "verdict": verdict}
    if evidence:
        payload["evidence_path"] = evidence
    text = f"{signed['alg']} token ({signed['note']}) — {len(signed['token'])} chars"
    if verdict is not None:
        text += f"\nself-verify: {'VALID' if verdict.get('valid') else 'INVALID'} ({verdict.get('detail')})"
    return ToolResult.success(payload, text=text)




# ---------------------------------------------------------------------------
# tools: stealth audit
# ---------------------------------------------------------------------------


def stealth_audit(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    """Report what the traffic actually looked like, and what could still betray it."""
    report = stealth.audit(Path(ctx.workdir))
    if kwargs.get("reset"):
        stealth.save(Path(ctx.workdir), {"persona": report.get("persona") or "chrome",
                                        "since": time.time(), "requests": 0, "bytes": 0,
                                        "by_class": {}, "challenges": 0, "rate_limited": 0,
                                        "hosts": {}})
    lines = [f"persona {report['persona'] or '(none)'} · transport {report['transport'] or '-'}"
             f" · fingerprint {report['fingerprint'] or '-'}",
             f"{report['requests']} requests / {report['bytes']} bytes "
             f"· challenges {report['challenges']} · 429s {report['rate_limited']}"]
    for kind, row in sorted((report.get("by_class") or {}).items()):
        lines.append(f"  {kind:<9} {row['requests']:>4} req {row['bytes']:>9} B")
    for host, row in sorted((report.get("hosts") or {}).items()):
        lines.append(f"  host {host}: {row['requests']} req, {row['challenges']} challenge, "
                     f"{row['rate_limited']} rate-limited")
    lines.append("capabilities: " + "; ".join(f"{k}={v}" for k, v in
                                              report["capabilities"].items() if k != "worker"))
    lines.append("residual risks:")
    lines += [f"  - {risk}" for risk in report["residual_risks"]]
    evidence = _save_evidence(ctx, report, prefix="stealth")
    payload = dict(report)
    if evidence:
        payload["evidence_path"] = evidence
    return ToolResult.success(payload, text="\n".join(lines))




# ---------------------------------------------------------------------------
# tools: escalating fetch (the ladder, as one call)
# ---------------------------------------------------------------------------


def http_fetch(ctx: ToolContext, kwargs: dict[str, Any]) -> ToolResult:
    """Fetch a URL, escalating only as far as the wall demands.

    fingerprint transport → headless browser → give up with a reason. Each rung is
    quieter than the next, so the default is the cheapest thing that works: an
    impersonated GET for a normal site, a browser only when the response is a
    challenge. That is the whole point — stealth is not one setting.
    """
    url = str(kwargs.get("url") or "").strip()
    if not url:
        return ToolResult.failure("url is required")
    method = str(kwargs.get("method") or "GET").upper()
    rungs: list[dict[str, Any]] = []

    first = _send(ctx, url=url, method=method, headers=_headers(kwargs.get("headers")),
                  body=kwargs.get("body"), timeout=clamp_float(kwargs.get("timeout"), 1, 90, 20),
                  max_bytes=clamp_int(kwargs.get("max_bytes"), 256, MAX_HTTP_BYTES, 131072))
    rungs.append({"rung": "http", "transport": first.get("transport") or "urllib",
                  "status": first.get("status"), "wall": chal.describe(first.get("challenge"))
                  if first.get("challenge") else ""})
    if first.get("status") and not first.get("challenge"):
        payload = row_payload(ctx, first, headers=kwargs.get("headers"), body=kwargs.get("body"))
        payload["rungs"] = rungs
        return ToolResult.success(payload, text=f"HTTP {first.get('status')} via "
                                                f"{first.get('transport') or 'urllib'}"
                                                f"\n\n{payload['body_excerpt'][:1500]}")
    if first.get("error") and not first.get("status"):
        return ToolResult.failure(f"fetch failed: {first['error']}", data={"rungs": rungs})

    if str(kwargs.get("escalate") or "browser") != "browser":
        payload = row_payload(ctx, first, headers=kwargs.get("headers"), body=kwargs.get("body"))
        payload["rungs"] = rungs
        return ToolResult.success(payload, text=f"HTTP {first.get('status')} walled, "
                                                f"escalation disabled\nrungs: {rungs}")

    session_name = f"fetch_{int(time.time() * 1000)}"
    browser = browser_session(ctx, {"action": "open", "url": url,
                                   "wait": clamp_float(kwargs.get("wait"), 0, 120, 25),
                                   "import_to": session_name,
                                   "max_chars": clamp_int(kwargs.get("max_chars"), 200, 20000, 4000)})
    rungs.append({"rung": "browser", "transport": "chrome",
                  "status": "ok" if browser.ok else "error",
                  "wall": (browser.data or {}).get("challenge", ""),
                  "cleared": (browser.data or {}).get("cleared")})
    if not browser.ok:
        return ToolResult.failure(f"escalation failed: {browser.error}", data={"rungs": rungs})
    payload = {"url": url, "title": (browser.data or {}).get("title"),
               "final_url": (browser.data or {}).get("final_url"),
               "html_bytes": (browser.data or {}).get("html_bytes"),
               "excerpt": (browser.data or {}).get("excerpt"),
               "cookies": (browser.data or {}).get("imported_cookies"),
               "session": session_name, "rungs": rungs,
               "evidence_path": (browser.data or {}).get("evidence_path")}
    return ToolResult.success(payload, text=truncate(
        f"walled for HTTP, cleared by the browser after {len(rungs)} rung(s); "
        f"cookies {payload['cookies']} in session '{session_name}'\n\n"
        f"{payload['excerpt']}", 9000))


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


def register(registry: ToolRegistry) -> None:
    registry.add(ToolSpec(
        name="http_session",
        description=(
            "Named, persistent cookie-jar HTTP session. action=open creates it (optionally logging in "
            "with url/method/body), action=send reuses the jar and any captured auth header. "
            "action=import seeds the jar from a browser: cookies/cookie_file/headers. "
            "capture=[{from:'json'|'header'|'body', path/regex/name, as_header, prefix}] lifts a token "
            "from the response into a header for all later calls. A detected wall is solved via "
            "token_from (vault:NAME|ask|solver|browser) and retried once. client=curl uses HTTP/2. "
            "Redirects are off unless follow=true."
        ),
        parameters={"type": "object", "properties": {
            "action": {"type": "string", "enum": ["open", "send", "import", "list", "close"]},
            "name": {"type": "string"},
            "cookies": {"type": "string", "description": "action=import: raw 'a=1; b=2' cookie string."},
            "reveal": {"type": "boolean", "description": "action=list: include the cookie header."},
            "cookie_file": {"type": "string", "description": "action=import: file of name=value pairs."},
            "url": {"type": "string"},
            "method": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            "capture": {"type": "array", "items": {"type": "object"}},
            "challenge_token": {"type": "string"},
            "token_from": {"type": "string", "enum": ["vault:NAME", "ask", "solver", "browser"]},
            "token_param": {"type": "string"}, "token_header": {"type": "string"},
            "token_in": {"type": "string", "enum": ["body", "json", "query"]},
            "token_cookie": {"type": "string"},
            "solver_service": {"type": "string", "enum": ["local", "2captcha", "capsolver"]},
            "solver_key": {"type": "string"}, "solver_timeout": {"type": "number"},
            "client": {"type": "string", "enum": ["", "curl"]},
            "curl_extra": {"type": "string"},
            "follow": {"type": "boolean"},
            "note": {"type": "string"},
            "timeout": {"type": "number"},
            "max_bytes": {"type": "integer"}},
            "required": ["action"]},
        risk="medium", tags=("network", "http", "auth"), requires_scope=True,
    ), http_session)

    registry.add(ToolSpec(
        name="http_matrix",
        description=(
            "Differential probe: send one URL as a baseline plus many controlled variants and return a "
            "verdict per row (same/DIFF + which signal changed). family presets: auth_presence, "
            "host_header, method_override, path_tricks, header_trust. Custom variants: "
            "[{label, method, path, headers, body}] where path may start with '/'. '{}' in a variant is "
            "replaced by token. This is the primary auth-presence and authz-differential tool."
        ),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"},
            "family": {"type": "string"},
            "variants": {"type": "array", "items": {"type": "object"}},
            "method": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            "session": {"type": "string"},
            "token": {"type": "string"},
            "challenge_token": {"type": "string"},
            "token_from": {"type": "string", "enum": ["vault:NAME", "ask", "solver"]},
            "token_param": {"type": "string"}, "token_header": {"type": "string"},
            "token_in": {"type": "string", "enum": ["body", "json", "query"]},
            "solver_service": {"type": "string"}, "solver_timeout": {"type": "number"},
            "client": {"type": "string", "enum": ["", "curl"]},
            "follow": {"type": "boolean"},
            "timeout": {"type": "number"},
            "max_seconds": {"type": "number"},
            "max_bytes": {"type": "integer"}},
            "required": ["url"]},
        risk="medium", tags=("network", "http", "auth", "differential"), requires_scope=True,
    ), http_matrix)

    registry.add(ToolSpec(
        name="jwt_inspect",
        description=(
            "Decode a JWT, flag weaknesses (alg=none, kid, jku/x5u, embedded jwk, missing exp, "
            "privilege claims), verify a supplied secret, crack an HMAC secret against a built-in list "
            "or a wordlist, and forge a token (forge={header:{},claims:{},secret})."
        ),
        parameters={"type": "object", "properties": {
            "token": {"type": "string"}, "secret": {"type": "string"},
            "crack": {"type": "boolean"}, "wordlist": {"type": "string"},
            "forge": {"type": "object"}}},
        risk="low", tags=("auth", "jwt"), read_only=True,
    ), jwt_inspect)

    registry.add(ToolSpec(
        name="route_mine",
        description=(
            "Mine an in-scope document (HTML/JS/manifest) for endpoints, URLs, source maps, GraphQL "
            "operations, role/flag strings and secret-shaped values; follows same-origin scripts and "
            "source maps. Use it to learn the app's real route surface before probing."
        ),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "max_scripts": {"type": "integer"},
            "max_bytes": {"type": "integer"}},
            "required": ["url"]},
        risk="low", tags=("network", "http", "discovery", "recon"), requires_scope=True, read_only=True,
    ), route_mine)

    registry.add(ToolSpec(
        name="artifact_probe",
        description=(
            "Probe paths that should not be served (.git, .env, dumps, backups, source maps, actuator, "
            "docs) against an in-scope base URL. tier: s|m|l (cumulative) plus explicit paths. "
            "Soft-404 aware; a HIT saves the body as hashed evidence and sniffs its type."
        ),
        parameters={"type": "object", "properties": {
            "base_url": {"type": "string"}, "tier": {"type": "string"},
            "paths": {"type": "array", "items": {"type": "string"}},
            "max_paths": {"type": "integer"}, "soft_404": {"type": "boolean"},
            "save": {"type": "boolean"}, "max_seconds": {"type": "number"},
            "timeout": {"type": "number"}, "max_bytes": {"type": "integer"}},
            "required": ["base_url"]},
        risk="medium", tags=("network", "http", "discovery", "artifact"), requires_scope=True,
    ), artifact_probe)

    registry.add(ToolSpec(
        name="code_probe",
        description=(
            "Enumerate a bounded code/token space against one in-scope URL containing '{}'. Detects a "
            "hit by response differential vs an invalid-code baseline and/or a match regex; reports "
            "attempts, rate, space coverage and ETA. xff_rotate cycles X-Forwarded-For to slip "
            "per-IP limiters; counter_field fills '{{n}}' for attempt counters."
        ),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "charset": {"type": "string"}, "length": {"type": "integer"},
            "start": {"type": "integer"}, "max_attempts": {"type": "integer"},
            "method": {"type": "string"}, "field": {"type": "string"}, "body": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "session": {"type": "string"}, "match": {"type": "string"}, "xff_rotate": {"type": "boolean"},
            "challenge_token": {"type": "string"},
            "token_from": {"type": "string", "enum": ["vault:NAME", "ask", "solver"]},
            "token_param": {"type": "string"}, "token_header": {"type": "string"},
            "token_in": {"type": "string", "enum": ["body", "json", "query"]},
            "solver_service": {"type": "string"}, "solver_timeout": {"type": "number"},
            "client": {"type": "string", "enum": ["", "curl"]},
            "counter_field": {"type": "string"}, "counter_start": {"type": "integer"},
            "stop_on_match": {"type": "boolean"}, "max_seconds": {"type": "number"},
            "timeout": {"type": "number"}, "max_bytes": {"type": "integer"}},
            "required": ["url"]},
        risk="medium", tags=("network", "http", "auth", "enumeration"), requires_scope=True,
    ), code_probe)

    registry.add(ToolSpec(
        name="id_walk",
        description=(
            "Walk a sequence of object references in an in-scope URL containing '{}' (numeric range via "
            "start/count, or explicit ids) and rank rows that deviate from the median response or hit a "
            "marker regex — the IDOR/side-channel surface. Use a session to walk as an authenticated user."
        ),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "ids": {"type": "array", "items": {"type": "string"}},
            "start": {"type": "integer"}, "count": {"type": "integer"}, "marker": {"type": "string"},
            "session": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "max_seconds": {"type": "number"}, "timeout": {"type": "number"},
            "max_bytes": {"type": "integer"}},
            "required": ["url"]},
        risk="medium", tags=("network", "http", "authz", "enumeration"), requires_scope=True,
    ), id_walk)

    registry.add(ToolSpec(
        name="vault",
        description=(
            "Run-scoped secret store so captured tokens survive evidence redaction. action=put/get/"
            "list/remove; get returns a masked value unless reveal=true."
        ),
        parameters={"type": "object", "properties": {
            "action": {"type": "string", "enum": ["put", "get", "list", "remove"]},
            "name": {"type": "string"}, "value": {"type": "string"}, "note": {"type": "string"},
            "reveal": {"type": "boolean"}},
            "required": ["action"]},
        risk="low", tags=("auth", "secret"), read_only=False,
    ), vault)

    registry.add(ToolSpec(
        name="browser_session",
        description=(
            "Headless Chrome/Edge over CDP. The ONLY lane that clears a js-challenge wall: it runs "
            "the page's own challenge script, waits (wait seconds, default 12) and re-reads until the "
            "wall clears or patience runs out. Returns the RENDERED DOM, title and final URL — content "
            "that never exists in the raw HTTP body. import_to=<session> harvests the minted cookies "
            "into a jar so the plain HTTP tools can take over afterwards. Also eval/shot/close. Target "
            "navigations are scope-checked; sub-resources are not."
        ),
        parameters={"type": "object", "properties": {
            "action": {"type": "string", "enum": ["open", "read", "cookies", "eval", "shot", "close"]},
            "url": {"type": "string"}, "wait": {"type": "number"},
            "settle_ms": {"type": "integer"}, "import_to": {"type": "string"},
            "host": {"type": "string"}, "expression": {"type": "string"},
            "max_chars": {"type": "integer"}, "screenshot": {"type": "boolean"},
            "user_agent": {"type": "string"}},
            "required": ["action"]},
        risk="high", tags=("network", "http", "browser", "challenge"), requires_scope=True,
    ), browser_session)

    registry.add(ToolSpec(
        name="jwt_sign",
        description=(
            "Sign a JWT the decoder cannot: alg none, HS256/384/512, RS256/384/512, ES256 "
            "(ECDSA P-256, raw r||s). key_pem/key_file takes a private key; pass the server's PUBLIC "
            "key as key_pem with alg=HS256 for algorithm confusion. verify=true self-checks the result."
        ),
        parameters={"type": "object", "properties": {
            "alg": {"type": "string", "enum": ["none", "HS256", "HS384", "HS512", "RS256",
                                               "RS384", "RS512", "ES256"]},
            "claims": {"type": "object"},
            "key_pem": {"type": "string"}, "key_file": {"type": "string"},
            "hmac_secret": {"type": "string"}, "header": {"type": "object"},
            "verify": {"type": "boolean"}},
            "required": ["alg", "claims"]},
        risk="low", tags=("auth", "jwt"), read_only=False,
    ), jwt_sign)

    registry.add(ToolSpec(
        name="stealth_audit",
        description=(
            "Report the stealth posture: persona, transport, fingerprint, requests and bytes per "
            "request class, challenges and 429s per host, available capabilities, and the residual "
            "risks that remain. Cite it in the report instead of asserting invisibility."
        ),
        parameters={"type": "object", "properties": {"reset": {"type": "boolean"}}},
        risk="low", tags=("stealth", "audit"), read_only=False,
    ), stealth_audit)

    registry.add(ToolSpec(
        name="http_fetch",
        description=(
            "Fetch one in-scope URL with escalation: impersonated Chrome fingerprint first, headless "
            "browser only if the response is a wall, then a reason if neither works. Returns the body "
            "and the rungs used. Prefer this over http_request when the host is known to be defended."
        ),
        parameters={"type": "object", "properties": {
            "url": {"type": "string"}, "method": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"}, "wait": {"type": "number"},
            "max_chars": {"type": "integer"}, "max_bytes": {"type": "integer"},
            "timeout": {"type": "number"},
            "escalate": {"type": "string", "enum": ["browser", "none"]}},
            "required": ["url"]},
        risk="medium", tags=("network", "http", "stealth", "escalation"), requires_scope=True,
    ), http_fetch)
