"""Bot-management detection and the challenge-token lane.

A challenge page is the one failure mode that lies: Cloudflare, Akamai, DataDome,
PerimeterX, Imperva, AWS WAF and the captcha widgets all answer **200** with a
widget where the data should be. A prober that only looks at status concludes
"nothing here" and the report confidently records a route as absent.

Two jobs, kept separate from the probing tools:

* :func:`detect` — decide from status, headers and body whether this response is
  a wall, and which wall. Cheap, pure, no network.
* :func:`resolve_token` — obtain a token for the wall: handed in, read from the
  vault, taken from a human over the approval gate, or bought from a solver
  service. Then :func:`inject` plants it where the vendor expects it.

Scope note: solver calls go to the *vendor* (2captcha/capsolver), not the target,
so they bypass :class:`~aria_x.tools.scope.Scope` on purpose. Everything a solver
call needs is public page data (URL + sitekey) plus the operator's own key.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..util import json_dumps, truncate

#: Vendor → header markers, body markers, and the widget kind.
#: Order matters: the most specific wall is tested first.
_SIGNATURES: tuple[tuple[str, str, tuple[re.Pattern[str], ...], tuple[re.Pattern[str], ...]], ...] = (
    ("cloudflare", "js-challenge",
     (re.compile(r"(?i)^challenge$"), re.compile(r"(?i)cf-mitigated|cf-ray")),
     (re.compile(r"(?i)_cf_chl_opt|cf-challenge|Just a moment\.\.\.|Checking your browser"),)),
    ("datadome", "js-challenge",
     (re.compile(r"(?i)datadome"), re.compile(r"(?i)x-dd-b")),
     (re.compile(r"(?i)captcha-delivery\.com|datadome/|dd_cookie_test"),)),
    ("perimeterx", "js-challenge",
     (re.compile(r"(?i)perimeterx"), re.compile(r"(?i)x-px")),
     (re.compile(r"(?i)px-captcha|_pxhd|px-captcha-container"),)),
    ("imperva", "block",
     (re.compile(r"(?i)incapsula|x-iinfo|visid_incap"),),
     (re.compile(r"(?i)Incapsula incident ID|Request unsuccessful\. Incapsula"),)),
    ("akamai", "block",
     (re.compile(r"(?i)akamai"), re.compile(r"(?i)_abck")),
     (re.compile(r"(?i)Access Denied.{0,80}Reference&#32;|ak_bmsc|bm-verify"),)),
    ("aws-waf", "js-challenge",
     (re.compile(r"(?i)awswaf|x-amzn-waf-action"),),
     (re.compile(r"(?i)aws-waf-token|gokuProps|challenge\.js"),)),
    ("sucuri", "block",
     (re.compile(r"(?i)x-sucuri"),),
     (re.compile(r"(?i)Sucuri WebSite Firewall|Access Denied - Sucuri"),)),
    ("f5", "block",
     (re.compile(r"(?i)bigip|f5"),),
     (re.compile(r"(?i)The requested URL was rejected"),)),
    ("wordfence", "block",
     (re.compile(r"(?i)wordfence"),),
     (re.compile(r"(?i)wordfence|Your access to this site has been limited"),)),
    # Captcha widgets last: a widget inside a 200 is unambiguous, a vendor string is not.
    ("recaptcha", "captcha", (), (re.compile(r'(?i)g-recaptcha|recaptcha/api\.js|grecaptcha'),)),
    ("hcaptcha", "captcha", (), (re.compile(r'(?i)h-captcha|hcaptcha\.com/1/api\.js'),)),
    ("turnstile", "captcha", (), (re.compile(r'(?i)cf-turnstile|challenges\.cloudflare\.com'),)),
    ("friendly-captcha", "captcha", (), (re.compile(r"(?i)frc-captcha|friendlycaptcha"),)),
    ("mcaptcha", "captcha", (), (re.compile(r"(?i)mcaptcha"),)),
)

_SITEKEY = re.compile(r"""(?i)data-sitekey=["']?([A-Za-z0-9_\-]{8,})""")
_SITEKEY_JSON = re.compile(r"""(?i)"sitekey"\s*:\s*"([A-Za-z0-9_\-]{8,})\"""")

#: Where each vendor expects the solved token, if it is a form field.
TOKEN_FIELDS: dict[str, str] = {
    "recaptcha": "g-recaptcha-response",
    "hcaptcha": "h-captcha-response",
    "turnstile": "cf-turnstile-response",
    "friendly-captcha": "frc-captcha-response",
    "mcaptcha": "mcaptcha__token",
}

#: Cookies whose absence proves you were never cleared by the wall.
CLEARANCE_COOKIES: dict[str, str] = {
    "cloudflare": "cf_clearance",
    "datadome": "datadome",
    "perimeterx": "_px3",
    "akamai": "_abck",
    "aws-waf": "aws-waf-token",
    "imperva": "visid_incap",
}


def detect(status: int, headers: dict[str, str], body: str) -> dict[str, Any] | None:
    """Return a challenge description, or ``None`` for a normal response.

    ``429`` alone is *not* a challenge (it is a rate limit) unless a vendor
    marker is present too — the two need different reactions.
    """
    head = truncate(body or "", 20000)
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    wall: dict[str, Any] | None = None
    widget: dict[str, Any] | None = None
    for vendor, kind, header_hits, body_hits in _SIGNATURES:
        marker = ""
        for pattern in header_hits:
            for name, value in lowered.items():
                if pattern.search(name) or pattern.search(value):
                    marker = f"header {name}"
                    break
            if marker:
                break
        if not marker:
            match = next((m for m in (p.search(head) for p in body_hits) if m), None)
            if match:
                marker = f"body '{truncate(match.group(0), 40)}'"
        if not marker:
            continue
        sitekey_match = _SITEKEY.search(head) or _SITEKEY_JSON.search(head)
        record = {
            "vendor": vendor, "kind": kind, "status": status, "marker": marker,
            "sitekey": sitekey_match.group(1) if sitekey_match else "",
            "token_field": TOKEN_FIELDS.get(vendor, ""),
            "clearance_cookie": CLEARANCE_COOKIES.get(vendor, ""),
            "reaction": ("solve or import a browser session" if kind == "captcha"
                         else "import a browser session (JS needed)" if kind == "js-challenge"
                         else "slow down, rotate persona, or resume later"),
        }
        if kind == "captcha":
            widget = record
            break
        wall = wall or record
    if widget or wall:
        chosen = widget or wall
        if widget and wall:
            chosen["wall_vendor"] = wall["vendor"]
            chosen["marker"] = f"{wall['marker']} + widget"
            chosen["reaction"] = "solve the widget or import a browser session"
        return chosen
    if status == 429:
        return {"vendor": "rate-limit", "kind": "rate-limit", "status": 429,
                "marker": f"retry-after={lowered.get('retry-after', '-')}",
                "sitekey": "", "token_field": "", "clearance_cookie": "",
                "reaction": "honour Retry-After, then back off"}
    return None


# ---------------------------------------------------------------------------
# token sources
# ---------------------------------------------------------------------------


def _state(ctx: Any, name: str) -> Path:
    path = Path(ctx.workdir) / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path / name


def _vault_get(ctx: Any, name: str) -> str:
    path = Path(ctx.workdir) / "state" / "vault.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    entry = data.get(name) or {}
    return str(entry.get("value") or "")


def solve(ctx: Any, challenge: dict[str, Any], page_url: str, *,
          service: str = "", key: str = "", timeout: float = 180.0) -> dict[str, Any]:
    """Obtain a token from a solver service. Returns ``{token, source, detail}``.

    ``service`` empty falls back to ``ARIAX_SOLVER_URL`` (a local solver, used by
    the lab and by tests) then to a keyed service if ``ARIAX_CAPTCHA_KEY`` is set.
    """
    import os

    vendor = challenge.get("vendor", "")
    sitekey = challenge.get("sitekey", "")
    if challenge.get("kind") != "captcha":
        return {"token": "", "source": "", "detail": f"{vendor} is a {challenge.get('kind')} wall, "
                                                     "not a captcha: import a browser session"}
    if not sitekey:
        return {"token": "", "source": "", "detail": "no data-sitekey in the page; cannot submit"}
    service = (service or "").lower()
    local_url = os.environ.get("ARIAX_SOLVER_URL", "")
    api_key = key or os.environ.get("ARIAX_CAPTCHA_KEY", "")
    if not service:
        service = "local" if local_url else ("capsolver" if api_key else "")

    if service == "local":
        if not local_url:
            return {"token": "", "source": "", "detail": "ARIAX_SOLVER_URL is not set"}
        body = json_dumps({"vendor": vendor, "sitekey": sitekey, "pageurl": page_url})
        try:
            request = urllib.request.Request(
                local_url, data=body.encode(), method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310
                payload = json.loads(resp.read().decode("utf-8", "replace") or "{}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"token": "", "source": "local", "detail": f"local solver failed: {exc}"}
        token = str(payload.get("token") or "")
        return {"token": token, "source": "local",
                "detail": payload.get("detail") or ("token from local solver" if token else "no token")}

    if not api_key:
        return {"token": "", "source": service,
                "detail": "set ARIAX_CAPTCHA_KEY (2captcha/capsolver) or ARIAX_SOLVER_URL (local)"}

    if service == "2captcha":
        try:
            submit = urllib.request.Request(
                "https://2captcha.com/in.php",
                data=urllib.parse.urlencode({
                    "key": api_key, "json": 1, "pageurl": page_url, "googlekey": sitekey,
                    "method": {"recaptcha": "userrecaptcha", "hcaptcha": "hcaptcha"}.get(vendor, ""),
                }).encode(), method="POST")
            with urllib.request.urlopen(submit, timeout=30) as resp:  # noqa: S310
                created = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"token": "", "source": "2captcha", "detail": f"submit failed: {exc}"}
        if str(created.get("status")) != "1":
            return {"token": "", "source": "2captcha",
                    "detail": f"rejected: {created.get('request') or created}"}
        task = created.get("request")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(5)
            query = f"https://2captcha.com/res.php?key={api_key}&action=get&id={task}&json=1"
            try:
                with urllib.request.urlopen(query, timeout=20) as resp:  # noqa: S310
                    polled = json.loads(resp.read().decode("utf-8", "replace"))
            except (urllib.error.URLError, OSError, ValueError):
                continue
            if str(polled.get("status")) == "1":
                return {"token": str(polled.get("request") or ""), "source": "2captcha",
                        "detail": "solved"}
        return {"token": "", "source": "2captcha", "detail": f"timeout after {timeout:.0f}s"}

    if service == "capsolver":
        task_type = {"recaptcha": "ReCaptchaV2TaskProxyLess",
                     "hcaptcha": "HCaptchaTaskProxyless",
                     "turnstile": "AntiTurnstileTaskProxyLess",
                     "friendly-captcha": "AntiTurnstileTaskProxyLess"}.get(vendor, "")
        if not task_type:
            return {"token": "", "source": "capsolver", "detail": f"no task type for {vendor}"}
        body = json_dumps({"clientKey": api_key, "task": {
            "type": task_type, "websiteURL": page_url, "websiteKey": sitekey}})
        try:
            submit = urllib.request.Request(
                "https://api.capsolver.com/createTask", data=body.encode(), method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(submit, timeout=30) as resp:  # noqa: S310
                created = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"token": "", "source": "capsolver", "detail": f"submit failed: {exc}"}
        if created.get("errorId"):
            return {"token": "", "source": "capsolver",
                    "detail": f"rejected: {created.get('errorDescription') or created}"}
        task = created.get("taskId")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(5)
            try:
                poll = urllib.request.Request(
                    "https://api.capsolver.com/getTaskResult",
                    data=json_dumps({"clientKey": api_key, "taskId": task}).encode(),
                    method="POST", headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(poll, timeout=20) as resp:  # noqa: S310
                    polled = json.loads(resp.read().decode("utf-8", "replace"))
            except (urllib.error.URLError, OSError, ValueError):
                continue
            solution = (polled.get("solution") or {})
            token = solution.get("gRecaptchaResponse") or solution.get("token") or ""
            if token:
                return {"token": token, "source": "capsolver", "detail": "solved"}
        return {"token": "", "source": "capsolver", "detail": f"timeout after {timeout:.0f}s"}

    return {"token": "", "source": service, "detail": f"unknown solver service '{service}'"}


def resolve_token(ctx: Any, args: dict[str, Any], challenge: dict[str, Any],
                  page_url: str) -> dict[str, Any]:
    """Get a token for this challenge from whichever channel the caller named.

    ``token_from``: ``vault:NAME`` | ``ask`` | ``solver`` | ``browser``. A literal
    ``challenge_token`` always wins. ``browser`` returns an empty token and means
    "you supplied cookies, not a token" — nothing to inject.
    """
    literal = str(args.get("challenge_token") or "")
    if literal:
        return {"token": literal, "source": "argument", "detail": "token from argument"}
    source = str(args.get("token_from") or "").lower()
    if not source:
        return {"token": "", "source": "", "detail": "no token_from set"}
    if source.startswith("vault:"):
        name = source.split(":", 1)[1]
        token = _vault_get(ctx, name)
        return {"token": token, "source": source,
                "detail": f"vault '{name}'" + ("" if token else " is empty")}
    if source == "browser":
        return {"token": "", "source": "browser",
                "detail": "cookies are expected to carry the clearance"}
    if source == "ask":
        pointer = _state(ctx, "challenge_token.txt")
        pointer.write_text("", encoding="utf-8")
        asker = getattr(ctx, "request_approval", None)
        if not callable(asker):
            return {"token": "", "source": "ask", "detail": "no approver attached"}
        prompt = (f"Solved challenge needed ({challenge.get('vendor')}, sitekey "
                  f"{challenge.get('sitekey') or 'n/a'}). Solve {page_url} in a browser, then "
                  f"write the token to {pointer} and approve.")
        approved = bool(asker("challenge_token", {"url": page_url, "pointer": str(pointer)},
                              "low", prompt))
        if not approved:
            return {"token": "", "source": "ask", "detail": "not approved"}
        token = pointer.read_text(encoding="utf-8").strip()
        return {"token": token, "source": "ask",
                "detail": "token from operator" if token else f"approved but {pointer.name} is empty"}
    if source == "solver":
        return solve(ctx, challenge, page_url,
                     service=str(args.get("solver_service") or ""),
                     key=str(args.get("solver_key") or ""),
                     timeout=float(args.get("solver_timeout") or 180))
    return {"token": "", "source": source, "detail": f"unknown token_from '{source}'"}


def inject(headers: dict[str, str], body: str | None, token: str, challenge: dict[str, Any],
           args: dict[str, Any], url: str = "") -> tuple[dict[str, str], str | None, str, dict[str, Any]]:
    """Plant a token where the vendor expects it. Returns (headers, body, url, how)."""
    if not token:
        return headers, body, url, {}
    field = str(args.get("token_param") or challenge.get("token_field") or "token")
    encoded = urllib.parse.quote(token)
    header_name = str(args.get("token_header") or "")
    pointer = str(args.get("token_in") or ("body" if body is not None else "query")).lower()
    how: dict[str, Any] = {"field": field, "in": pointer, "masked": f"{token[:6]}...{token[-4:]}"
                           if len(token) > 12 else "***"}
    if header_name:
        headers[header_name] = token
        how["in"] = f"header {header_name}"
        return headers, body, url, how
    if pointer == "query":
        if url:
            joiner = "&" if urllib.parse.urlsplit(url).query else "?"
            url = f"{url}{joiner}{field}={encoded}"
            how["in"] = "query"
        else:
            how["in"] = "query (no url given)"
        return headers, body, url, how
    if pointer == "json":
        try:
            payload = json.loads(body or "{}")
        except ValueError:
            payload = {}
        payload[field] = token
        how["in"] = "json"
        return headers, json_dumps(payload), url, how
    if body is None:
        return headers, body, url, how
    separator = "" if not body or body.endswith("&") else "&"
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    how["in"] = "form"
    return headers, f"{body}{separator}{field}={encoded}", url, how


def describe(challenge: dict[str, Any] | None) -> str:
    if not challenge:
        return ""
    return (f"{challenge.get('vendor')} {challenge.get('kind')} "
            f"(marker={challenge.get('marker')}, sitekey={challenge.get('sitekey') or '-'})")
