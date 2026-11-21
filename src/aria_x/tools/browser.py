"""Headless-browser lane over the Chrome DevTools Protocol (stdlib only).

The HTTP stack cannot execute JavaScript, so a ``js-challenge`` wall (Cloudflare's
interstitial, DataDome, PerimeterX) has no solver: the page verifies itself and
hands out a cookie. That is a *browser* job, and pretending otherwise is how a run
ends up reporting "blocked" on a target it could have entered.

This module drives a real Chrome/Edge in ``--headless=new`` with a throwaway
profile and speaks CDP over a minimal WebSocket client (no third-party packages):

* open a URL, let it settle, and keep the tab;
* return the **rendered** DOM (what urllib can never see);
* harvest cookies the JS challenge minted, straight into a session jar;
* evaluate an expression (typing, clicking) for form flows that need it;
* screenshot, because a wall you cannot see is a wall you guess about.

Boundaries that matter: the profile is per-run and deleted on close (no shared
state, no logged-in leakage from the operator's own Chrome); target navigations
are scope-checked before the tab moves; sub-resources (CDN, captcha vendor) are
*not* scope-checked — a page's own asset hosts are out of the engagement scope by
definition. Chrome is launched directly, not through the sandbox, because the
sandbox's job is commands and files, not long-lived processes; the profile lives
inside the workdir either way.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..util import json_dumps, truncate

_CHROME_CANDIDATES = (
    os.environ.get("ARIAX_BROWSER", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def browser_path() -> str:
    for candidate in _CHROME_CANDIDATES:
        if candidate and Path(candidate).is_file():
            return candidate
    found = shutil.which("chrome") or shutil.which("chromium") or shutil.which("msedge")
    return found or ""


# ---------------------------------------------------------------------------
# minimal websocket (text frames, masking, fragmentation)
# ---------------------------------------------------------------------------


class _WS:
    def __init__(self, host: str, port: int, path: str, timeout: float = 30.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
                   f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                   f"Sec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(request.encode())
        self.buffer = b""
        head = self._read_until(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise OSError(f"websocket handshake refused: {head[:120]!r}")
        self.next_id = 0
        self.pending: dict[int, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("socket closed during handshake")
            self.buffer += chunk
        head, _, self.buffer = self.buffer.partition(marker)
        return head

    def _recv_exact(self, count: int) -> bytes:
        while len(self.buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("socket closed")
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def send(self, payload: dict[str, Any]) -> int:
        self.next_id += 1
        message_id = self.next_id
        payload["id"] = message_id
        raw = json.dumps(payload).encode()
        header = bytearray([0x81])
        length = len(raw)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", length)
        mask = secrets.token_bytes(4)
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(raw)))
        return message_id

    def _frame(self) -> tuple[bool, int, bytes]:
        first, second = self._recv_exact(2)
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b""
        data = self._recv_exact(length)
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return fin, opcode, data

    def recv(self) -> dict[str, Any] | None:
        """Next JSON message, or None for a control frame."""
        chunks: list[bytes] = []
        while True:
            fin, opcode, data = self._frame()
            if opcode == 0x8:
                raise OSError("websocket closed by peer")
            if opcode in (0x9, 0xA):
                continue
            chunks.append(data)
            if fin:
                break
        try:
            return json.loads(b"".join(chunks))
        except ValueError:
            return None

    def call(self, method: str, params: dict[str, Any] | None = None,
             session_id: str | None = None, timeout: float = 30.0) -> dict[str, Any]:
        payload: dict[str, Any] = {"method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        message_id = self.send(payload)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            message = self.recv()
            if message is None:
                continue
            if message.get("id") == message_id:
                if "error" in message:
                    raise OSError(f"{method}: {message['error'].get('message')}")
                return message.get("result") or {}
            if "method" in message:
                self.events.append(message)
                if len(self.events) > 400:
                    self.events = self.events[-200:]
        raise OSError(f"{method}: timed out")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# browser lifecycle
# ---------------------------------------------------------------------------


def _state_file(workdir: Path) -> Path:
    path = workdir / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path / "browser.json"


def read_state(workdir: Path) -> dict[str, Any]:
    try:
        return json.loads(_state_file(workdir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_state(workdir: Path, data: dict[str, Any]) -> None:
    try:
        _state_file(workdir).write_text(json_dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


#: Without a non-headless UA, Chrome sends "...HeadlessChrome/..." and Cloudflare
#: refuses before the challenge is even attempted.
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/157.0.0.0 Safari/537.36")

#: Injected before any page script: the automation tells bot management checks.
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
window.chrome = window.chrome || {runtime: {}};
"""


def launch(workdir: Path, *, width: int = 1280, height: int = 900,
           user_agent: str = "") -> dict[str, Any]:
    """Start headless Chrome with a throwaway profile. Returns connection info."""
    binary = browser_path()
    if not binary:
        raise OSError("no chrome/chromium/msedge found; set ARIAX_BROWSER to the binary")
    profile = Path(workdir) / "state" / f"profile_{secrets.token_hex(4)}"
    profile.mkdir(parents=True, exist_ok=True)
    argv = [binary, "--headless=new", "--remote-debugging-port=0",
            f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
            "--disable-gpu", "--disable-extensions", "--disable-background-networking",
            "--disable-blink-features=AutomationControlled", "--lang=en-US",
            "--disable-features=Translate,BackForwardCache", "--enable-features=NetworkService",
            f"--window-size={width},{height}", "--hide-scrollbars", "about:blank"]
    argv.insert(1, f"--user-agent={user_agent or DEFAULT_UA}")
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=flags)
    port_file = profile / "DevToolsActivePort"
    port = 0
    for _ in range(200):
        if port_file.exists():
            text = port_file.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                port = int(text.splitlines()[0])
                break
        if process.poll() is not None:
            break
        time.sleep(0.1)
    if not port:
        raise OSError("chrome did not open a devtools port")
    # DevToolsActivePort is two lines: the port, then the browser websocket path.
    ws_path = ""
    for _ in range(100):
        try:
            lines = port_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        if len(lines) > 1 and lines[1].startswith("/devtools/"):
            ws_path = lines[1].strip()
            break
        time.sleep(0.1)
    if not ws_path:
        _kill(process.pid)
        shutil.rmtree(profile, ignore_errors=True)
        raise OSError("devtools browser endpoint not published")
    ws = _WS("127.0.0.1", port, ws_path)
    state = {"pid": process.pid, "port": port, "profile": str(profile),
             "browser_ws": ws_path, "opened_at": time.time()}
    write_state(workdir, state)
    return state


def connect(workdir: Path) -> _WS:
    state = read_state(workdir)
    if not state.get("browser_ws"):
        raise OSError("no browser running; action=open first")
    return _WS("127.0.0.1", int(state["port"]), state["browser_ws"])


def _kill(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=20)
        else:
            os.kill(int(pid), 15)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def shutdown(workdir: Path) -> bool:
    state = read_state(workdir)
    pid = state.get("pid")
    profile = state.get("profile")
    killed = False
    killed = _kill(int(pid) if pid else None)
    _state_file(workdir).unlink(missing_ok=True)
    time.sleep(0.6)  # let Windows release the profile handles before rmtree
    if profile:
        shutil.rmtree(profile, ignore_errors=True)
    return killed


# ---------------------------------------------------------------------------
# page operations
# ---------------------------------------------------------------------------


def _ensure_page(ws: _WS, workdir: Path) -> str:
    """A target + attached session for the current tab, reused when possible."""
    state = read_state(workdir)
    session_id = state.get("session_id")
    if session_id:
        return session_id
    created = ws.call("Target.createTarget", {"url": "about:blank"})
    attached = ws.call("Target.attachToTarget", {"targetId": created["targetId"],
                                                 "flatten": True})
    session_id = attached["sessionId"]
    state.update({"session_id": session_id, "target_id": created["targetId"]})
    write_state(workdir, state)
    ws.call("Page.enable", session_id=session_id)
    ws.call("Page.addScriptToEvaluateOnNewDocument", {"source": _STEALTH_JS},
            session_id=session_id)
    ws.call("Network.enable", session_id=session_id)
    ws.call("Runtime.enable", session_id=session_id)
    return session_id


def navigate(ws: _WS, session_id: str, url: str, *, settle_ms: int = 2500) -> dict[str, Any]:
    result = ws.call("Page.navigate", {"url": url}, session_id=session_id, timeout=45)
    time.sleep(max(0, settle_ms) / 1000)
    # let pending loads finish, then report what the DOM actually became
    for _ in range(20):
        state = ws.call("Runtime.evaluate",
                        {"expression": "document.readyState", "returnByValue": True},
                        session_id=session_id, timeout=10)
        if ((state.get("result") or {}).get("value")) == "complete":
            break
        time.sleep(0.15)
    return result


def document(ws: _WS, session_id: str) -> dict[str, Any]:
    """Rendered DOM, title and URL — the evidence a wall needs."""
    out = ws.call("Runtime.evaluate", {
        "expression": "JSON.stringify({title: document.title, url: location.href,"
                      " html: (document.documentElement ? document.documentElement.outerHTML : '')})",
        "returnByValue": True}, session_id=session_id, timeout=20)
    try:
        data = json.loads((out.get("result") or {}).get("value") or "{}")
    except ValueError:
        data = {}
    return {"title": data.get("title", ""), "url": data.get("url", ""),
            "html": data.get("html", "")}


def cookies(ws: _WS, session_id: str) -> list[dict[str, Any]]:
    result = ws.call("Network.getAllCookies", session_id=session_id, timeout=20)
    return list(result.get("cookies") or [])


def evaluate(ws: _WS, session_id: str, expression: str) -> Any:
    out = ws.call("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                       "awaitPromise": True}, session_id=session_id, timeout=30)
    return (out.get("result") or {}).get("value")


def screenshot(ws: _WS, session_id: str, path: Path) -> int:
    shot = ws.call("Page.captureScreenshot", {"format": "png"}, session_id=session_id, timeout=30)
    raw = base64.b64decode(shot.get("data") or "")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return len(raw)


def fetch_via_browser(ws: _WS, session_id: str, url: str, *, settle_ms: int = 2000,
                      headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Navigate, then read the DOM — the browser equivalent of one GET."""
    navigate(ws, session_id, url, settle_ms=settle_ms)
    if headers:
        evaluate(ws, session_id, "0")
    return document(ws, session_id)


def http_json(port: int, path: str) -> Any:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=15) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace"))


def domain_matches(cookie_domain: str, host: str) -> bool:
    """True for exact host and for either direction of parent/child.

    Cloudflare sets ``cf_clearance`` on ``.zoominfo.com`` while the target is
    ``www.zoominfo.com``: a plain ``endswith`` test drops the only cookie that
    matters, in the direction that ends in a false "handoff failed".
    """
    domain = cookie_domain.lstrip(".").lower()
    host = host.lstrip(".").lower()
    if not domain or not host:
        return False
    return domain == host or host.endswith("." + domain) or domain.endswith("." + host)


def clamp_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme:
        return "https://" + url
    return url
