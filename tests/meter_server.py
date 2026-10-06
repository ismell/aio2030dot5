"""A fake IEEE 2030.5 HAN meter for tests.

Serves responses captured from a real Itron Gen5 Riva (agent 3.2.50) over
TLS 1.2 / ECDHE-ECDSA-AES128-CCM8 with client-certificate auth, and models
the behaviours the client must cope with:

* keep-alive with an idle timeout (the real meter: 30 s)
* list paging (``s``/``l``) re-sliced from the captured pages
* TLS session resumption (the server's built-in session cache)
* an optional cap on requests per connection
* "blackhole" mode: accept TCP, never complete the handshake

It records every connection so tests can assert the one-connection rule.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIXTURES = Path(__file__).parent / "fixtures" / "itron_riva_3_2_50.json"
NS = "urn:ieee:std:2030.5:ns"
ET.register_namespace("", NS)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class FixtureTree:
    """Captured responses, with lists reassembled so any page can be served."""

    def __init__(self, path: Path = FIXTURES) -> None:
        data = json.loads(path.read_text())
        self.meta = data["_meta"]
        self.exact: dict[str, tuple[int, str]] = {}
        pages: dict[str, list[tuple[int, ET.Element]]] = {}
        for key, r in data["responses"].items():
            parts = urlsplit(key)
            if parts.query and r["status"] == 200:
                start = int(parse_qs(parts.query).get("s", ["0"])[0])
                pages.setdefault(parts.path, []).append((start, ET.fromstring(r["body"])))
            else:
                self.exact[parts.path] = (r["status"], r["body"])
        self.lists: dict[str, tuple[ET.Element, list[ET.Element]]] = {}
        for base, got in pages.items():
            got.sort(key=lambda p: p[0])
            root = got[0][1]
            items: list[ET.Element] = []
            for _, page in got:
                items.extend(c for c in page if not _local(c.tag).endswith("Link"))
            self.lists[base] = (root, items)

    def respond(self, target: str) -> tuple[int, str]:
        parts = urlsplit(target)
        if parts.path in self.lists:
            q = parse_qs(parts.query)
            s = int(q.get("s", ["0"])[0])
            n = int(q.get("l", ["255"])[0])
            proto, items = self.lists[parts.path]
            chosen = items[s : s + n]
            root = ET.Element(proto.tag, dict(proto.attrib))
            root.set("all", str(len(items)))
            root.set("results", str(len(chosen)))
            root.extend(chosen)
            return 200, ET.tostring(root, encoding="unicode")
        if parts.path in self.exact:
            return self.exact[parts.path]
        return 404, ""


@dataclass
class ServerLog:
    connections: int = 0
    resumed: int = 0
    max_concurrent: int = 0
    requests: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class FakeMeter:
    def __init__(
        self,
        server_cert: Path,
        server_key: Path,
        client_ca: Path,
        *,
        idle_timeout: float = 30.0,
        max_requests_per_connection: int | None = None,
        blackhole: bool = False,
        honour_keep_alive: bool = True,
        clean_close: bool = True,
        port: int = 0,
        tree: FixtureTree | None = None,
    ) -> None:
        self.tree = tree or FixtureTree()
        self.idle_timeout = idle_timeout
        self.max_requests = max_requests_per_connection
        self.blackhole = blackhole
        self.honour_keep_alive = honour_keep_alive
        # The real meter sends close_notify when it closes; without it OpenSSL
        # evicts the session from the server cache and nothing can resume.
        self.clean_close = clean_close
        self.log = ServerLog()
        self._active = 0
        self._lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0")
        ctx.load_cert_chain(server_cert, server_key)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(client_ca)
        self.ctx = ctx
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeMeter:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        with self._lock:
            self._active += 1
            self.log.connections += 1
            self.log.max_concurrent = max(self.log.max_concurrent, self._active)
        try:
            if self.blackhole:
                time.sleep(5)
                return
            try:
                tls = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as err:
                self.log.errors.append(f"handshake: {err}")
                return
            if tls.session_reused:
                self.log.resumed += 1
            served = 0
            while True:
                tls.settimeout(self.idle_timeout)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            return
                        data += chunk
                except (TimeoutError, OSError):
                    return  # idle timeout: drop the connection, like the meter
                line = data.split(b"\r\n", 1)[0].decode()
                method, target, _ = line.split(" ", 2)
                if method != "GET":
                    self.log.errors.append(f"non-GET request: {line}")
                    return
                self.log.requests.append(target)
                status, body = self.tree.respond(target)
                served += 1
                close = (not self.honour_keep_alive) or (self.max_requests is not None and served >= self.max_requests)
                reason = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "Status")
                payload = body.encode()
                head = f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(payload)}\r\n"
                if payload:
                    head += "Content-Type: application/sep+xml\r\n"
                tls.sendall(head.encode() + b"\r\n" + payload)
                if close:
                    if self.clean_close:
                        try:
                            tls.unwrap()
                        except (ssl.SSLError, OSError):
                            pass
                    tls.close()
                    return
        finally:
            with self._lock:
                self._active -= 1
            try:
                raw.close()
            except OSError:
                pass
