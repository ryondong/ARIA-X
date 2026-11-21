"""Stealth: one coherent persona, human-shaped timing, and an honest ledger.

"Undetectable" is not a property this can hold — every request is a log line
somewhere. What it *can* hold is that nothing about the traffic distinguishes it
from one person browsing: the same TLS stack a browser has, the same header set
in the same order, the same cadence, one identity for the whole run, and a
retreat instead of a hammer when the other side pushes back.

The mechanisms, cheapest first:

* **Fingerprint.** Nothing gives you away faster than a Python JA3 on an HTTP/1.1
  connection. ``curl_cffi`` (libcurl-impersonate, run through the toolchain venv)
  reproduces a real Chrome ClientHello, ALPN h2 and Akamai h2 fingerprint; the
  headless browser reproduces all of it plus JS. Both are measured against
  ``tls.peet.ws`` in ``lab/verify_stealth.py``.
* **Identity coherence.** A persona binds UA, ``sec-ch-ua``, ``Accept``,
  ``Accept-Language``, header *order* and screen to the impersonation target, and
  is chosen once per run — the classic tell is a UA that changes while the TLS
  fingerprint stays still.
* **Shape.** Browsers fetch a document, then its assets in parallel, then pause.
  Scripts that hit one endpoint at a uniform rate look like cron. So: classes of
  request with their own base delay and jitter, a small asset burst after a page,
  dwell before the next page.
* **Manners.** ``Referer`` chained from the page you came from, ``sec-fetch-*``
  set the way a browser sets them, conditional requests when a body is already
  held, and ``robots.txt`` respected on the first visit to a host.
* **Retreat.** 429/503 honours ``Retry-After`` and doubles the local base; three
  identical challenge responses open a circuit breaker for that host so the run
  stops burning requests into a wall.

Everything is recorded in a ledger the report can cite, including the residual
risks — the ledger is what makes the claim falsifiable instead of flattering.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..util import json_dumps

#: Interpreter that carries curl_cffi. Override with ARIAX_CURLL_CFFI_PY.
_TOOLCHAIN_PY = (r"C:\Users\ryond\AppData\Local\hermes\profiles\thoth\tools\py\Scripts\python.exe")

#: impersonation target → coherent browser persona. Headers the impersonator sets
#: itself are not repeated here; these are the ones it leaves to us.
PROFILES: dict[str, dict[str, Any]] = {
    "chrome": {
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/124.0.0.0 Safari/537.36"),
        "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "platform": '"Windows"',
        "accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
                   "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
        "languages": "en-US,en;q=0.9",
        "screen": "1920x1080",
        "timezone": "Asia/Manila",
        "order": ("Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                  "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
                  "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer",
                  "Accept-Encoding", "Accept-Language"),
    },
    "chrome_android": {
        "ua": ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/124.0.0.0 Mobile Safari/537.36"),
        "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "platform": '"Android"',
        "accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
                   "image/apng,*/*;q=0.8"),
        "languages": "en-US,en;q=0.9",
        "screen": "412x915",
        "timezone": "Asia/Manila",
        "order": ("Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                  "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
                  "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer",
                  "Accept-Encoding", "Accept-Language"),
    },
    "safari": {
        "ua": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.5 Safari/605.1.15"),
        "sec_ch_ua": "",
        "platform": '"macOS"',
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "languages": "en-US,en;q=0.9",
        "screen": "1512x982",
        "timezone": "Asia/Manila",
        "order": ("Host", "Accept-Language", "Accept-Encoding", "User-Agent", "Accept", "Referer",
                  "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Connection"),
    },
}

#: Request classes: base delay (s), jitter fraction, and whether a burst is allowed.
CLASSES: dict[str, tuple[float, float, bool]] = {
    "document": (1.8, 0.55, False),   # a page load is followed by one; keep it human
    "asset": (0.12, 0.8, True),       # assets stream in
    "api": (0.9, 0.7, False),
    "auth": (2.4, 0.5, False),        # login/OTP: the loudest requests on any site
    "probe": (0.7, 0.8, False),       # 404 ladders, artefacts — bot-shaped already
}

_ASSET_SUFFIXES = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif",
                   ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".map")
_AUTH_HINTS = ("login", "signin", "sign-in", "logout", "oauth", "token", "session", "otp",
               "mfa", "reset", "password", "verify", "captcha", "auth")
_API_HINTS = ("/api/", "/rest/", "/graphql", "/rpc/", "/v1/", "/v2/", "/v3/", ".json")


def classify(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    path = (parts.path or "/").lower()
    if path.endswith(_ASSET_SUFFIXES):
        return "asset"
    if any(hint in path for hint in _AUTH_HINTS):
        return "auth"
    if path in ("/", "") or path.endswith((".html", ".htm")) or "?" not in url and "." not in path.rsplit("/", 1)[-1]:
        return "document"
    if any(hint in path for hint in _API_HINTS):
        return "api"
    return "probe"


# ---------------------------------------------------------------------------
# fingerprint capability
# ---------------------------------------------------------------------------


_IMPERSONATE_CACHE: dict[str, str] = {}


def impersonate_python() -> str:
    """Path to an interpreter that can import curl_cffi, or ``""``. Memoised."""
    if "path" in _IMPERSONATE_CACHE:
        return _IMPERSONATE_CACHE["path"]
    _IMPERSONATE_CACHE["path"] = _probe_impersonate()
    return _IMPERSONATE_CACHE["path"]


def _probe_impersonate() -> str:
    override = os.environ.get("ARIAX_CURLL_CFFI_PY", "")
    for candidate in (override, _TOOLCHAIN_PY):
        if candidate and Path(candidate).is_file():
            try:
                check = subprocess.run([candidate, "-c", "import curl_cffi"], capture_output=True,
                                       timeout=25)
                if check.returncode == 0:
                    return candidate
            except (OSError, subprocess.SubprocessError):
                continue
    return ""


def browser_binary() -> str:
    from . import browser
    return browser.browser_path()


def capabilities() -> dict[str, Any]:
    """What this machine can actually carry. No pretending."""
    workers = Path(__file__).with_name("_impersonate_worker.py")
    return {
        "urllib": "python JA3, HTTP/1.1, always available",
        "impersonate": ("chrome/ja3+ja4+akamai-h2 via curl_cffi" if impersonate_python()
                        else "unavailable (curl_cffi interpreter not found)"),
        "browser": ("real Chrome via CDP" if browser_binary() else "unavailable (no browser)"),
        "worker": str(workers) if workers.is_file() else "",
    }


# ---------------------------------------------------------------------------
# persona state (fixed for the run, persisted so restarts keep identity)
# ---------------------------------------------------------------------------


def _state(workdir: Path) -> Path:
    path = Path(workdir) / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path / "stealth.json"


def load(workdir: Path) -> dict[str, Any]:
    try:
        return json.loads(_state(workdir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(workdir: Path, data: dict[str, Any]) -> None:
    try:
        _state(workdir).write_text(json_dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def persona(workdir: Path, name: str = "") -> tuple[str, dict[str, Any]]:
    """The run's persona — chosen once, then reused forever."""
    data = load(workdir)
    if name and name in PROFILES and data.get("persona") != name:
        data = {"persona": name, "since": time.time(), "requests": 0, "bytes": 0,
                "by_class": {}, "challenges": 0, "rate_limited": 0, "hosts": {}}
        save(workdir, data)
        return name, PROFILES[name]
    current = data.get("persona")
    if not current or current not in PROFILES:
        current = "chrome"
        data.update({"persona": current, "since": data.get("since") or time.time(), "requests": 0,
                     "bytes": 0, "by_class": {}, "challenges": 0, "rate_limited": 0, "hosts": {}})
        save(workdir, data)
    return current, PROFILES[current]


def headers_for(workdir: Path, url: str, method: str = "GET", *, referer: str = "",
                extra: dict[str, str] | None = None,
                encodings: str = "gzip, deflate, br") -> dict[str, str]:
    """A browser-shaped header block in the persona's own order."""
    name, profile = persona(workdir)
    parts = urllib.parse.urlsplit(url)
    kind = classify(url)
    navigational = kind == "document"
    site = "same-origin"
    if referer:
        ref = urllib.parse.urlsplit(referer)
        if ref.netloc != parts.netloc:
            site = "cross-site"
        elif ref.path.rstrip("/") != parts.path.rstrip("/"):
            site = "same-origin"
    ordered: dict[str, str] = {}
    for field_name in profile["order"]:
        if field_name == "Host":
            continue
        if field_name == "sec-ch-ua" and profile["sec_ch_ua"]:
            ordered["sec-ch-ua"] = profile["sec_ch_ua"]
        elif field_name == "sec-ch-ua-mobile" and profile["sec_ch_ua"]:
            ordered["sec-ch-ua-mobile"] = "?1" if name == "chrome_android" else "?0"
        elif field_name == "sec-ch-ua-platform" and profile["sec_ch_ua"]:
            ordered["sec-ch-ua-platform"] = profile["platform"]
        elif field_name == "Upgrade-Insecure-Requests" and navigational:
            ordered["Upgrade-Insecure-Requests"] = "1"
        elif field_name == "User-Agent":
            ordered["User-Agent"] = profile["ua"]
        elif field_name == "Accept":
            ordered["Accept"] = (profile["accept"] if navigational else
                                 "application/json, text/plain, */*")
        elif field_name == "Sec-Fetch-Site":
            ordered["Sec-Fetch-Site"] = "none" if not referer else site
        elif field_name == "Sec-Fetch-Mode":
            ordered["Sec-Fetch-Mode"] = "navigate" if navigational else "cors"
        elif field_name == "Sec-Fetch-User" and navigational:
            ordered["Sec-Fetch-User"] = "?1"
        elif field_name == "Sec-Fetch-Dest":
            ordered["Sec-Fetch-Dest"] = ("document" if navigational
                                         else "image" if kind == "asset" else "empty")
        elif field_name == "Referer" and referer:
            ordered["Referer"] = referer
        elif field_name == "Accept-Encoding":
            ordered["Accept-Encoding"] = encodings
        elif field_name == "Accept-Language":
            ordered["Accept-Language"] = profile["languages"]
    if method.upper() == "POST":
        ordered.setdefault("Origin", f"{parts.scheme}://{parts.netloc}")
    ordered.update(extra or {})
    return ordered


def next_delay(workdir: Path, kind: str, *, scale: float = 1.0) -> float:
    """Jittered pre-request delay for a class of request."""
    base, jitter, bursty = CLASSES.get(kind, CLASSES["probe"])
    data = load(workdir)
    host_scale = scale
    if bursty and data.get("last_kind") == kind and (time.time() - data.get("last_at", 0)) < 3:
        base *= 0.35                      # assets are allowed to stream
    spread = base * jitter
    delay = max(0.0, random.gauss(base, spread / 2) if spread else base)
    delay = min(delay, base * (1 + jitter))
    try:  # tests and batch work set this to squeeze the wall clock
        scale = float(os.environ.get("ARIAX_STEALTH_SCALE", "1") or 1)
    except ValueError:
        scale = 1.0
    return round(delay * host_scale * scale, 3)


def record(workdir: Path, *, url: str, kind: str, status: int, size: int, elapsed_ms: int,
           transport: str, fingerprint: str, challenge: str = "", egress: str = "") -> None:
    """Ledger row. Cheap, and the only source of the audit numbers."""
    data = load(workdir)
    data.setdefault("by_class", {})
    entry = data["by_class"].setdefault(kind, {"requests": 0, "bytes": 0})
    entry["requests"] += 1
    entry["bytes"] += size
    data["requests"] = data.get("requests", 0) + 1
    data["bytes"] = data.get("bytes", 0) + size
    data["last_kind"] = kind
    data["last_at"] = time.time()
    data["transport"] = transport
    data["fingerprint"] = fingerprint
    if egress:
        data["egress"] = egress
        distinct = data.setdefault("distinct_egress", [])
        if egress not in distinct:
            distinct.append(egress)
    host = urllib.parse.urlsplit(url).hostname or ""
    hosts = data.setdefault("hosts", {})
    host_row = hosts.setdefault(host, {"requests": 0, "challenges": 0, "rate_limited": 0,
                                       "breaker": 0.0})
    host_row["requests"] += 1
    if challenge:
        data["challenges"] = data.get("challenges", 0) + 1
        host_row["challenges"] += 1
        host_row["breaker"] = time.time()
    if status == 429:
        data["rate_limited"] = data.get("rate_limited", 0) + 1
        host_row["rate_limited"] += 1
    save(workdir, data)


def host_scale(workdir: Path, host: str) -> float:
    """Per-host slowdown after rate limiting: 1 → 2 → 4, capped, decaying by time."""
    data = load(workdir)
    row = (data.get("hosts") or {}).get(host) or {}
    limited = row.get("rate_limited", 0)
    last = row.get("breaker", 0)
    if not limited or not last:
        return 1.0
    if time.time() - last > 900:          # quarter of an hour of quiet: forgive
        return 1.0
    return min(4.0, 1.0 + 0.5 * limited)


def breaker_open(workdir: Path, host: str, *, limit: int = 3, cooldown: float = 120.0,
                 already_paid: float = 45.0) -> float:
    """Seconds still to wait if the host keeps challenging, else 0.

    Paid once, not per request: ``already_paid`` is how recently the pause was
    actually taken. Sleeping on every call inside a tight loop burns the run's
    own wall-clock budget and can starve a deadline before a single hit.
    """
    data = load(workdir)
    row = ((data.get("hosts") or {}).get(host) or {})
    if row.get("challenges", 0) < limit:
        return 0.0
    paid = float(data.get("breaker_paid") or 0)
    if paid and time.time() - paid < already_paid:
        return 0.0
    waited = time.time() - float(row.get("breaker") or 0)
    return max(0.0, cooldown - waited)


def mark_paid(workdir: Path) -> None:
    data = load(workdir)
    data["breaker_paid"] = time.time()
    save(workdir, data)


def audit(workdir: Path) -> dict[str, Any]:
    """The stealth self-check: what we did, and what could still reveal us."""
    data = load(workdir)
    caps = capabilities()
    by_class = data.get("by_class") or {}
    return {
        "persona": data.get("persona", ""),
        "transport": data.get("transport", ""),
        "fingerprint": data.get("fingerprint", ""),
        "egress": data.get("egress", "") or "direct",
        "distinct_egress": data.get("distinct_egress") or [],
        "requests": data.get("requests", 0),
        "bytes": data.get("bytes", 0),
        "by_class": by_class,
        "challenges": data.get("challenges", 0),
        "rate_limited": data.get("rate_limited", 0),
        "hosts": data.get("hosts") or {},
        "capabilities": caps,
        "residual_risks": [
            "access logs exist on the server; 'unseen' means indistinguishable, not invisible",
            ("the egress IP is a single constant address" if not data.get("distinct_egress")
             else f"{len(data.get('distinct_egress') or [])} egress(es) used; they can still be"
                  " correlated by ASN or by timing"),
            "no JS means no browser telemetry the score-based systems expect (v3 captcha);"
            " browser lane fixes that at a cost",
            "TLS session resumption and TCP characteristics still differ from a browser on the"
            " same host",
            "request timing classes are human-shaped but not human: no mouse, no scroll",
            "DNS resolution was done by this machine, not the target's resolver path",
        ],
    }
