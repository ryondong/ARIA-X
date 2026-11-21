#!/usr/bin/env python
"""One impersonated request, executed under an interpreter that has curl_cffi.

Not imported by the engine: the engine runs on system Python, curl_cffi lives in
the toolchain venv, so this is invoked as a subprocess with a JSON request on
stdin and a JSON response on stdout. Keeping it out of process also means a
libcurl crash cannot take the engine with it.

Request:  {url, method, headers: [[k, v], ...], body_b64, timeout, max_bytes,
           follow, impersonate, http_version}
Response: {status, headers: {k: v}, body_b64, elapsed_ms, transport, error}
"""

import base64
import json
import sys
import time

from curl_cffi import requests
from curl_cffi.const import CurlHttpVersion


def main() -> int:
    try:
        spec = json.load(sys.stdin)
    except ValueError as exc:
        print(json.dumps({"error": f"bad request json: {exc}"}))
        return 2

    url = spec["url"]
    headers = {str(k): str(v) for k, v in (spec.get("headers") or [])}
    body = base64.b64decode(spec["body_b64"]) if spec.get("body_b64") else None
    limit = int(spec.get("max_bytes") or 65536)
    started = time.monotonic()
    try:
        response = requests.request(
            str(spec.get("method") or "GET").upper(), url,
            headers=headers, data=body,
            impersonate=spec.get("impersonate") or "chrome",
            timeout=float(spec.get("timeout") or 20),
            allow_redirects=bool(spec.get("follow")),
            max_redirects=5,
            http_version=(CurlHttpVersion.V2_0 if spec.get("http_version") != "1.1"
                          else CurlHttpVersion.V1_1),
            verify=True,
        )
    except Exception as exc:  # noqa: BLE001 - libcurl raises its own hierarchy
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1

    raw = response.content[:limit]
    payload = {
        "status": response.status_code,
        "headers": dict(response.headers),
        "body_b64": base64.b64encode(raw).decode(),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "transport": "impersonate",
        "http_version": str(getattr(response, "http_version", "")),
    }
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
