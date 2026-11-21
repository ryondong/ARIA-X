#!/usr/bin/env python3
"""A tiny forwarding proxy for the lab, so egress can be tested without a VPN.

Plain HTTP is forwarded with an absolute-URI request line; HTTPS is tunnelled with
CONNECT. Every forwarded request carries ``X-Egress: <id>`` so the *target* can
prove which proxy a request came through — that is the whole assertion in the
egress tests.

    python lab/proxy.py --port 8901 --id p1
"""

from __future__ import annotations

import argparse
import selectors
import socket
import threading
import urllib.parse


def pipe(left: socket.socket, right: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    try:
        while True:
            for key, _events in selector.select(timeout=30):
                data = key.fileobj.recv(65536)
                if not data:
                    return
                key.data.sendall(data)
    except OSError:
        return
    finally:
        selector.close()


def handle(client: socket.socket, egress_id: str) -> None:
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client.recv(65536)
            if not chunk:
                return
            head += chunk
        request_line, _, rest = head.partition(b"\r\n")
        method, target, version = request_line.decode("latin-1").split(" ", 2)

        if method.upper() == "CONNECT":
            host, _, port = target.partition(":")
            upstream = socket.create_connection((host, int(port or 443)), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            pipe(client, upstream)
            return

        parts = urllib.parse.urlsplit(target)
        upstream = socket.create_connection((parts.hostname, parts.port or 80), timeout=20)
        path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
        headers = rest.replace(b"\r\n\r\n", b"\r\n")
        forwarded = (f"{method} {path} {version}\r\n".encode()
                     + f"X-Egress: {egress_id}\r\n".encode()
                     + headers + b"\r\n")
        upstream.sendall(forwarded)
        pipe(client, upstream)
    except (OSError, ValueError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8901)
    parser.add_argument("--id", default="p1")
    args = parser.parse_args()
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(64)
    print(f"proxy {args.id} on 127.0.0.1:{args.port}")
    while True:
        client, _addr = server.accept()
        threading.Thread(target=handle, args=(client, args.id), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
