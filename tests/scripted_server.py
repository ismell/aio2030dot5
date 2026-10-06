"""A tiny threaded TLS server whose per-connection behaviour a test scripts (resets, odd framing)."""

from __future__ import annotations

import socket
import ssl
import struct
import threading


def server_ctx(pki, client_ca=None, verify=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0")
    ctx.load_cert_chain(pki.server_cert, pki.server_key)
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(client_ca or pki.client_cert)
    return ctx


def rst(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


class Server:
    def __init__(self, handler):
        self.handler = handler
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()
        self.errors = []

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.sock.close()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(raw,), daemon=True).start()

    def _one(self, raw):
        with self.lock:
            self.connections += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            self.handler(raw)
        except Exception as e:
            self.errors.append(repr(e))
        finally:
            with self.lock:
                self.active -= 1
            try:
                raw.close()
            except OSError:
                pass


def read_request(tls):
    data = b""
    while b"\r\n\r\n" not in data:
        c = tls.recv(4096)
        if not c:
            return None
        data += c
    return data.split(b"\r\n", 1)[0].decode()
