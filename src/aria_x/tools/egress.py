"""Egress selection: a proxy pool with sticky per-host assignment.

The single biggest remaining tell after the fingerprint work is the IP. One
constant address across a run, and the same address again next week, is the thing
that correlates everything you did — including across different hosts.

So: a pool, one egress **stuck to a host for the life of the session**, and a
deliberate `rotate` when a host pushes back. Sticky matters more than random: a
session that hops mid-flow looks worse than one that never moved, because no
browser changes IP between a page and its assets.

Configuration is environment-only, so it never lands in a committed config:

* ``ARIAX_PROXIES`` — comma-separated, ``scheme://user:pass@host:port`` or
  ``host:port`` (defaults to http). Supports ``socks5://`` where the client does.
* ``ARIAX_PROXY_FILE`` — one proxy per line instead.
* ``ARIAX_EGRESS`` — ``sticky`` (default), ``rotate`` (new egress per request) or
  ``off``.

Dead egresses are cooled off, not retried: one failure parks a proxy for five
minutes so a broken line cannot stall a whole run. Nothing here is required — an
empty pool is the old single-IP behaviour and the ledger says so.
"""

from __future__ import annotations

import os
import random
import re
import time
from pathlib import Path
from typing import Any

from ..util import json_dumps

_MASK = re.compile(r"//([^:@/]+):([^@/]+)@")


def _state(workdir: Path) -> Path:
    path = Path(workdir) / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path / "egress.json"


def load(workdir: Path) -> dict[str, Any]:
    import json
    try:
        return json.loads(_state(workdir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(workdir: Path, data: dict[str, Any]) -> None:
    try:
        _state(workdir).write_text(json_dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def mask(proxy: str) -> str:
    """``http://user:pass@h:port`` → ``http://user:***@h:port`` (logs are printed)."""
    return _MASK.sub(r"//\1:***@", proxy) if "@" in proxy else proxy


def pool() -> list[str]:
    """Configured proxies, normalised. Empty list means 'direct'."""
    raw: list[str] = []
    env = os.environ.get("ARIAX_PROXIES", "")
    raw += [piece for piece in env.split(",") if piece.strip()]
    path = os.environ.get("ARIAX_PROXY_FILE", "")
    if path:
        try:
            raw += [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.strip().startswith("#")]
        except OSError:
            pass
    out: list[str] = []
    for entry in raw:
        entry = entry.strip()
        if not entry:
            continue
        if "://" not in entry:
            entry = "http://" + entry
        if entry not in out:
            out.append(entry)
    return out


def strategy() -> str:
    value = (os.environ.get("ARIAX_EGRESS") or "sticky").lower()
    return value if value in {"sticky", "rotate", "off"} else "sticky"


def _alive(data: dict[str, Any], proxy: str) -> bool:
    row = (data.get("proxies") or {}).get(proxy) or {}
    return (time.time() - float(row.get("failed_at") or 0)) > 300 or not row.get("failed")


def choose(workdir: Path, host: str) -> str:
    """The egress for this host: sticky if possible, rotated only on demand."""
    proxies = pool()
    if not proxies or strategy() == "off":
        return ""
    data = load(workdir)
    stuck = (data.get("hosts") or {}).get(host)
    if strategy() == "sticky" and stuck and stuck in proxies and _alive(data, stuck):
        return stuck
    alive = [p for p in proxies if _alive(data, p)] or proxies
    picked = alive[random.randrange(len(alive))] if strategy() == "rotate" else alive[0]
    data.setdefault("hosts", {})[host] = picked
    data.setdefault("proxies", {}).setdefault(picked, {"uses": 0, "failures": 0})
    save(workdir, data)
    return picked


def used(workdir: Path, proxy: str, host: str) -> None:
    if not proxy:
        return
    data = load(workdir)
    row = data.setdefault("proxies", {}).setdefault(proxy, {"uses": 0, "failures": 0})
    row["uses"] = int(row.get("uses") or 0) + 1
    row["failed"] = False
    data.setdefault("last", {})["host"] = host
    data["last"]["proxy"] = proxy
    data["last_at"] = time.time()
    save(workdir, data)


def failed(workdir: Path, proxy: str, host: str = "") -> None:
    if not proxy:
        return
    data = load(workdir)
    row = data.setdefault("proxies", {}).setdefault(proxy, {"uses": 0, "failures": 0})
    row["failures"] = int(row.get("failures") or 0) + 1
    row["failed"] = True
    row["failed_at"] = time.time()
    if host and (data.get("hosts") or {}).get(host) == proxy:
        data["hosts"].pop(host, None)          # next call re-picks instead of retrying a corpse
    save(workdir, data)


def rotate(workdir: Path, host: str) -> str:
    """Force a different egress for one host. Returns the new proxy (``""`` if direct)."""
    data = load(workdir)
    current = (data.get("hosts") or {}).get(host)
    candidates = [p for p in pool() if p != current and _alive(data, p)] or \
                 [p for p in pool() if p != current]
    if not candidates:
        return current or ""
    data.setdefault("hosts", {})[host] = candidates[0]
    save(workdir, data)
    return candidates[0]


def status(workdir: Path) -> dict[str, Any]:
    data = load(workdir)
    proxies = pool()
    return {
        "strategy": strategy(),
        "configured": len(proxies),
        "proxies": [{"proxy": mask(p),
                     "uses": int(((data.get("proxies") or {}).get(p) or {}).get("uses") or 0),
                     "failures": int(((data.get("proxies") or {}).get(p) or {}).get("failures") or 0),
                     "alive": _alive(data, p)} for p in proxies],
        "hosts": {host: mask(p) for host, p in (data.get("hosts") or {}).items()},
        "note": ("no pool: direct egress, constant IP" if not proxies
                 else "sticky per host; rotate explicitly when a host pushes back"),
    }


def urllib_handler(proxy: str) -> Any:
    """A ProxyHandler for one egress — or one that ignores the environment."""
    import urllib.request
    if not proxy:
        return urllib.request.ProxyHandler({})
    parts = proxy.split("://", 1)
    scheme = parts[0] if len(parts) == 2 else "http"
    mapping = {scheme: proxy}
    return urllib.request.ProxyHandler(mapping)


def curl_flags(proxy: str) -> list[str]:
    return ["--proxy", proxy] if proxy else []
