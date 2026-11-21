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
* ``ARIAX_EGRESS`` — ``sticky`` (default), ``distinct`` (a different egress per
  host: the mode for a multi-host run), ``rotate`` (new egress per request) or
  ``off``.

Residential/mobile providers are built from credentials instead of a pasted list,
because that is the only way to get a different *ASN* rather than a different
address on the same datacentre. ``ARIAX_PROXY_PROVIDER`` names the gateway and the
pool becomes ``ARIAX_PROXY_SESSIONS`` sticky slots; ``distinct`` then hands each
host its own slot so no two hosts ever see the same IP. Unknown providers use
``ARIAX_PROXY_USER_TEMPLATE`` with ``{session}`` in it.

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

#: Greedy up to the LAST '@': provider passwords legitimately contain '@' and ':',
#: and a lazy match leaks half of one into every log line.
_MASK = re.compile(r"^(?P<scheme>[A-Za-z0-9+.-]+://)(?P<user>[^:/@]+):(?P<secret>.+)@"
                   r"(?P<host>[^@/]+)$")


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
    match = _MASK.match(proxy)
    if not match:
        return proxy
    return f"{match.group(1)}{match.group(2)}:***@{match.group(4)}"


#: Provider → gateway host:port, and the sticky-session username template.
#: Session tokens are what the vendor ties an IP to; the *timeout* is the vendor's,
#: so a clearance cookie can outlive a stuck session — keep lifetimes long.
PROVIDERS: dict[str, dict[str, str]] = {
    "brightdata": {"gateway": "brd.superproxy.io:33335",
                   "user": "brd-customer-{user}-zone-{zone}-session-{session}{country}",
                   "pass": "{password}", "zone_env": "ARIAX_PROXY_ZONE"},
    "oxylabs": {"gateway": "pr.oxylabs.io:7777",
                "user": "user-{user}-sess-{session}{country}",
                "pass": "{password}", "country": ""},
    "decodo": {"gateway": "gate.decodo.com:7000",
               "user": "user-{user}_session-{session}_lifetime-30{country}",
               "pass": "{password}", "country": "_country-{cc}"},
    "iproyal": {"gateway": "geo.iproyal.com:12321",
                "user": "user-{user}_session-{session}{country}",
                "pass": "{password}", "country": "_country-{cc}"},
    "soax": {"gateway": "proxy.soax.com:5000",
             "user": "package-{user}-sessionid-{session}{country}",
             "pass": "{password}", "country": "-country-{cc}"},
}

#: Where the vendor expects country selection, per provider above.
_COUNTRY = {"brightdata": "-country-{cc}", "oxylabs": "-cc-{cc}", "decodo": "_country-{cc}",
            "iproyal": "_country-{cc}", "soax": "-country-{cc}"}


def provider() -> str:
    return (os.environ.get("ARIAX_PROXY_PROVIDER") or "").strip().lower()


def _provider_pool() -> list[str]:
    """Build one proxy URL per sticky session slot from provider credentials."""
    name = provider()
    if not name:
        return []
    user = os.environ.get("ARIAX_PROXY_USER", "")
    password = os.environ.get("ARIAX_PROXY_PASS", "")
    gateway = os.environ.get("ARIAX_PROXY_GATEWAY", "")
    country = (os.environ.get("ARIAX_PROXY_COUNTRY") or "").lower()
    try:
        slots = max(1, min(32, int(os.environ.get("ARIAX_PROXY_SESSIONS") or 4)))
    except ValueError:
        slots = 4

    if name == "custom":
        template = os.environ.get("ARIAX_PROXY_USER_TEMPLATE", "")
        if not template or not gateway:
            return []
        return [f"http://{template.format(session=f's{index:02d}', user=user)}:{password}@{gateway}"
                .replace(":@", "@") for index in range(slots)]

    spec = PROVIDERS.get(name)
    if not spec:
        return []
    gateway = gateway or spec["gateway"]
    zone = os.environ.get(spec.get("zone_env", ""), "") if spec.get("zone_env") else ""
    suffix = _COUNTRY.get(name, "")
    cc = country if suffix and country else ""
    built: list[str] = []
    for index in range(slots):
        username = spec["user"].format(user=user, zone=zone, password=password,
                                       session=f"ariax{index:02d}",
                                       country=suffix.format(cc=cc) if cc else "")
        secret = spec["pass"].format(password=password)
        credential = f"{username}:{secret}@" if secret else f"{username}@"
        built.append(f"http://{credential}{gateway}")
    return built


def pool() -> list[str]:
    """Configured proxies, normalised. Empty list means 'direct'."""
    from_provider = _provider_pool()
    if from_provider:
        return from_provider
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
    return value if value in {"sticky", "distinct", "rotate", "off"} else "sticky"


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
    if strategy() in {"sticky", "distinct"} and stuck and stuck in proxies and _alive(data, stuck):
        return stuck
    alive = [p for p in proxies if _alive(data, p)] or proxies
    if strategy() == "rotate":
        picked = alive[random.randrange(len(alive))]
    elif strategy() == "distinct":
        # a host gets an egress no other host currently holds; collisions only when
        # the pool is smaller than the host set, and the ledger records them
        held = set((data.get("hosts") or {}).values()) - {stuck}
        free = [p for p in alive if p not in held]
        picked = free[0] if free else alive[0]
        if not free:
            data.setdefault("collisions", []).append(host)
    else:
        picked = alive[0]
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
    held = [value for value in (data.get("hosts") or {}).values()]
    collisions = sorted({p for p in held if held.count(p) > 1})
    return {
        "strategy": strategy(),
        "configured": len(proxies),
        "proxies": [{"proxy": mask(p),
                     "uses": int(((data.get("proxies") or {}).get(p) or {}).get("uses") or 0),
                     "failures": int(((data.get("proxies") or {}).get(p) or {}).get("failures") or 0),
                     "alive": _alive(data, p)} for p in proxies],
        "hosts": {host: mask(p) for host, p in (data.get("hosts") or {}).items()},
        "provider": provider() or "generic",
        "distinct": strategy() == "distinct",
        "collisions": [mask(p) for p in collisions],
        "note": ("no pool: direct egress, constant IP" if not proxies
                 else "sticky per host (same ASN unless a residential provider is set)"
                 if strategy() != "distinct" else
                 f"{len(proxies)} egresses for {len(data.get('hosts') or {})} hosts; "
                 "a host keeps its own while slots last"),
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
