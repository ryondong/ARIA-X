#!/usr/bin/env python3
"""Measure the stealth ladder against a public TLS/h2 echo — no model, no guessing.

Prints, per transport, what the *other end* sees: HTTP version, JA3, JA4, the
Akamai HTTP/2 fingerprint and the UA. Then states which rungs are actually
browser-shaped.

    PYTHONPATH=src python lab/verify_stealth.py                 # default echo
    PYTHONPATH=src python lab/verify_stealth.py https://...     # your own echo

Exit 1 when impersonation does not beat Python's own TLS stack. A 10/10 stealth
claim that cannot show this table is a mood, not a property.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from aria_x.tools import stealth  # noqa: E402

ECHO = "https://tls.peet.ws/api/all"


def _row(name: str, data: dict | None, note: str = "") -> dict[str, str]:
    if not data:
        return {"transport": name, "http": "-", "ja3": "-", "ja4": "-", "akamai": "-",
                "ua": note or "-"}
    tls = data.get("tls") or data
    return {
        "transport": name,
        "http": str(data.get("http_version") or "-"),
        "ja3": str(tls.get("ja3_hash") or "-")[:16],
        "ja4": str(tls.get("ja4") or "-")[:20],
        "akamai": str((data.get("http2") or {}).get("akamai_fingerprint_hash") or "-")[:16],
        "ua": str(data.get("user_agent") or note or "-")[:44],
    }


def via_urllib(url: str) -> dict | None:
    request = urllib.request.Request(url, headers={"User-Agent": "ARIA-X/0.1 research",
                                                   "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=25) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace"))


def via_impersonate(url: str) -> dict | None:
    python = stealth.impersonate_python()
    if not python:
        return None
    worker = REPO / "src" / "aria_x" / "tools" / "_impersonate_worker.py"
    spec = json.dumps({"url": url, "method": "GET",
                       "headers": list(stealth.headers_for(Path(tempfile.mkdtemp()), url).items()),
                       "body_b64": "", "timeout": 25, "max_bytes": 40000, "follow": False,
                       "impersonate": "chrome"})
    run = subprocess.run([python, str(worker)], input=spec, capture_output=True, text=True,
                         timeout=60)
    import base64
    payload = json.loads(run.stdout or "{}")
    if payload.get("error"):
        return {"_error": payload["error"]}
    return json.loads(base64.b64decode(payload["body_b64"]).decode("utf-8", "replace"))


def via_browser(url: str) -> dict | None:
    from aria_x.tools import browser
    if not browser.browser_path():
        return None
    workdir = Path(tempfile.mkdtemp())
    browser.launch(workdir)
    ws = browser.connect(workdir)
    try:
        session = browser._ensure_page(ws, workdir)
        browser.navigate(ws, session, url, settle_ms=2500)
        text = browser.evaluate(ws, session,
                                "(document.body && document.body.innerText) || ''")
        return json.loads(text) if text else None
    finally:
        ws.close()
        browser.shutdown(workdir)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    url = argv[0] if argv and not argv[0].startswith("-") else ECHO
    print(f"echo: {url}\n")
    rows: list[dict[str, str]] = []

    started = time.monotonic()
    try:
        rows.append(_row("urllib (python ssl)", via_urllib(url)))
    except Exception as exc:  # noqa: BLE001
        rows.append(_row("urllib (python ssl)", None, f"failed: {exc}"))
    try:
        data = via_impersonate(url)
        rows.append(_row("impersonate (chrome)", data,
                         (data or {}).get("_error", "-") if data else "unavailable"))
    except Exception as exc:  # noqa: BLE001
        rows.append(_row("impersonate (chrome)", None, f"failed: {exc}"))
    try:
        rows.append(_row("browser (real chrome)", via_browser(url)))
    except Exception as exc:  # noqa: BLE001
        rows.append(_row("browser (real chrome)", None, f"failed: {exc}"))

    widths = {"transport": 24, "http": 5, "ja3": 17, "ja4": 21, "akamai": 17, "ua": 46}
    header = " | ".join(key.ljust(widths[key]) for key in widths)
    print(header)
    print("-" * len(header))
    for row in rows:
        print(" | ".join(row[key].ljust(widths[key]) for key in widths))

    python_ja3 = rows[0]["ja3"]
    chrome_ja3 = rows[1]["ja3"]
    print(f"\nelapsed {time.monotonic() - started:.1f}s")
    verdict = []
    verdict.append("urllib is a Python JA3 on " + ("HTTP/1.1" if rows[0]["http"] != "2" else "h2")
                   + " — usable, never browser-like")
    if chrome_ja3 in {"-", python_ja3}:
        verdict.append("impersonation did NOT change the fingerprint — not 10/10")
    else:
        verdict.append(f"impersonation changes JA3 ({python_ja3} -> {chrome_ja3}) and "
                       f"negotiates {'h2' if 'h2' in rows[1]['ja4'] else 'h1'}"
                       + (", Akamai h2 fingerprint present" if rows[1]["akamai"] != "-" else ""))
    if rows[1]["ja4"] != "-" and rows[1]["ja4"] == rows[2]["ja4"]:
        verdict.append("impersonation and the real browser share a JA4 — indistinguishable on the"
                       " layer bot management actually scores")
    else:
        verdict.append(f"JA4 differs from a real browser ({rows[1]['ja4']} vs {rows[2]['ja4']})")
    if rows[1]["akamai"] != "-" and rows[1]["akamai"] == rows[2]["akamai"]:
        verdict.append("and they agree on the Akamai h2 fingerprint too")
    for line in verdict:
        print(" - " + line)
    print("\nResidual, even at the top rung: the server's own access log; egress IP (fixed unless ARIAX_PROXIES is set, one ASN shared by a datacentre pool); "
          "local DNS on direct rungs; no dwell on a real element.")
    return 0 if chrome_ja3 not in {"-", python_ja3} else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
