"""Connection handling for a fragile, single-connection HAN meter.

Why this exists instead of ``asyncio.open_connection(ssl=...)``:

* asyncio's SSL transport cannot offer a saved ``SSLSession``, so every
  connection would be a full ECDHE+ECDSA handshake. On an Itron Gen5 Riva a
  full handshake costs ~330 ms of meter CPU (up to 11 s observed); a resumed
  one ~60-160 ms. TLS here is driven through ``ssl.MemoryBIO`` and
  ``SSLContext.wrap_bio(session=...)`` over a plain asyncio TCP stream.
* The meter serves ONE connection at a time and degrades when over-polled,
  so all access goes through a single lock, connections are spaced, and
  requests are batched on one keep-alive connection.

Measured on agent 3.2.50: keep-alive honoured, idle connections closed after
30 s, Content-Length on every response, ~1 in 190 handshakes failing with
``BAD_SIGNATURE`` (a meter-side signing glitch; one retry succeeds).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import ssl
import tempfile
import time
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

from .exceptions import (
    AuthReason,
    InvalidIdentity,
    MeterAuthError,
    MeterBusy,
    MeterConnectionError,
    MeterHttpError,
    MeterIdentityMismatch,
    MeterNotFound,
    MeterProtocolError,
    MeterTimeout,
)
from .identity import Identity, lfdi_from_der, sfdi_from_lfdi, short_lfdi
from .models import short

_LOGGER = logging.getLogger(__name__)

IEEE_2030_5_CIPHERS = "ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0"
CONTENT_TYPE = "application/sep+xml"
_READ_SIZE = 16384
_MAX_HEADER_BYTES = 16384
_MAX_BODY_BYTES = 4 * 1024 * 1024


def build_ssl_context(cert_path: str | os.PathLike[str], key_path: str | os.PathLike[str]) -> ssl.SSLContext:
    """TLS client context for an IEEE 2030.5 HAN meter, from PEM files.

    Blocking (reads the cert and key files): call it from an executor in an
    event loop. The meter's certificate chains to its manufacturer's 2030.5
    root (on an Itron, "IEEE 2030.5 Root, O=Itron"), which is in no trust
    store, so CA verification is disabled -- on this context only. The meter
    is authenticated by pinning its LFDI instead (``Meter(expected_lfdi=)``,
    set by ``discover()``); it admits us because our certificate's LFDI is
    registered with the utility.
    """
    ctx = _client_context()
    try:
        ctx.load_cert_chain(cert_path, key_path, password=_no_password)
    except ssl.SSLError as err:
        raise InvalidIdentity(f"cannot use the client certificate/key: {err.reason or err}") from None
    return ctx


def _no_password() -> str:
    # Without a password callback OpenSSL prompts on the terminal for an
    # encrypted key -- hanging an executor thread forever.
    raise InvalidIdentity("the private key is encrypted", ("private key is encrypted",))


def build_ssl_context_from_pem(cert_pem: str | bytes, key_pem: str | bytes) -> ssl.SSLContext:
    """:func:`build_ssl_context` from PEM text, e.g. an identity kept in a
    config entry. Blocking: call it from an executor.

    Why temporary files: ``ssl.SSLContext.load_cert_chain`` only reads from
    paths -- the ssl module has no way to load a private key from memory, and
    there is no cross-platform anonymous file it can open. The PEMs go into a
    fresh private directory (mode 0700, files 0600) that is removed before
    this returns, so the key is on disk only for the duration of the call.
    """
    blobs = []
    for p in (cert_pem, key_pem):
        # Checked rather than caught: a UnicodeEncodeError would carry the key
        # text along in its context.
        if isinstance(p, str) and p.isascii():
            blobs.append(p.encode("ascii"))
        elif isinstance(p, bytes | bytearray | memoryview):
            blobs.append(bytes(p))
        else:
            raise InvalidIdentity("PEM text must be ASCII str or bytes", ("PEM text must be ASCII",))
    with tempfile.TemporaryDirectory(prefix="aio2030dot5-") as tmp:
        paths = []
        for name, blob in zip(("cert.pem", "key.pem"), blobs, strict=True):
            path = os.path.join(tmp, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            paths.append(path)
        return build_ssl_context(paths[0], paths[1])


async def async_build_ssl_context(identity: Identity) -> ssl.SSLContext:
    """:func:`build_ssl_context_from_pem` for an :class:`Identity`, off the event loop."""
    return await asyncio.to_thread(build_ssl_context_from_pem, identity.cert_pem, identity.key_pem)


def _client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    ctx.set_ciphers(IEEE_2030_5_CIPHERS)
    return ctx


@dataclass(frozen=True, slots=True)
class Timeouts:
    """Per-phase timeouts, and an optional deadline for a whole batch (one
    library call). The batch deadline starts once the meter's lock is held,
    so time spent queued behind another reader -- a history backfill, say --
    never counts against it. Raises :class:`MeterTimeout`."""

    connect: float = 10.0
    handshake: float = 20.0  # full handshakes have taken 11 s on a busy meter
    response: float = 20.0
    batch: float | None = None


@dataclass(slots=True)
class TransportStats:
    """Counters for diagnostics. Monotonic for the life of the transport."""

    requests: int = 0
    connections: int = 0
    resumed_connections: int = 0
    bad_signature_retries: int = 0
    reconnects_mid_batch: int = 0
    failures: int = 0
    last_handshake_ms: int | None = None

    def to_dict(self) -> dict[str, int | None]:
        """The counters, e.g. for diagnostics (output only: there is no from_dict)."""
        return {
            "requests": self.requests,
            "connections": self.connections,
            "resumed_connections": self.resumed_connections,
            "bad_signature_retries": self.bad_signature_retries,
            "reconnects_mid_batch": self.reconnects_mid_batch,
            "failures": self.failures,
            "last_handshake_ms": self.last_handshake_ms,
        }


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    keep_alive: bool


@dataclass(frozen=True, slots=True)
class PeerCertificate:
    """The certificate a meter presented, and the identity it implies.

    In IEEE 2030.5 a device's LFDI *is* the leftmost 160 bits of the SHA-256
    of its device certificate, so this identifies the meter whatever its
    address: on an Itron Gen5 Riva it equals the ``/sdev`` lFDI, and the SFDI
    is the one in its mDNS instance name. It is not verified against a CA -- pin it (trust on first use).
    """

    # Left out of repr(): the DER is kilobytes, and a meter's certificate can
    # carry a hardware serial number that does not belong in logs.
    der: bytes = field(repr=False)  # the leaf (device) certificate
    chain: tuple[bytes, ...] = field(repr=False)  # as sent, leaf first; just the leaf on a resumed session
    lfdi: str
    sfdi: str

    @classmethod
    def from_chain(cls, chain: tuple[bytes, ...]) -> PeerCertificate:
        """The identity a certificate chain (leaf first) implies."""
        lfdi = lfdi_from_der(chain[0])
        return cls(der=chain[0], chain=chain, lfdi=lfdi, sfdi=sfdi_from_lfdi(lfdi))


class _CertificateTap:
    """Picks the server's Certificate message out of the raw TLS 1.2 stream.

    The meter sends its certificate in the clear before it judges ours, and
    rejects an unregistered client with an alert that makes OpenSSL discard
    everything it learned. Reading the handshake bytes ourselves is the only
    way to learn who refused us -- which is what a setup flow needs before the
    client certificate is registered, and what tells "wrong device at this
    address" apart from "not registered". Best effort: anything unexpected
    just stops the tap.
    """

    _LIMIT = 65536

    def __init__(self) -> None:
        self._records = b""
        self._handshake = b""
        self._seen = 0
        self.chain: tuple[bytes, ...] | None = None
        # True once ServerHelloDone followed the Certificate. By then OpenSSL
        # has checked the ServerKeyExchange signature (mandatory with the
        # only cipher suite offered) against the certificate's key, so the
        # peer holds that key. A refusal before that point could come from
        # anything replaying the meter's (public) certificate.
        self.proven = False
        self.done = False

    def feed(self, data: bytes) -> None:
        if self.done:
            return
        self._seen += len(data)
        if self._seen > self._LIMIT:
            self.done = True
            return
        self._records += data
        while len(self._records) >= 5 and not self.done:
            content_type, length = self._records[0], int.from_bytes(self._records[3:5], "big")
            if len(self._records) < 5 + length:
                return
            body, self._records = self._records[5 : 5 + length], self._records[5 + length :]
            if content_type == 22:  # handshake
                self._handshake += body
                self._messages()
            elif content_type != 21:  # anything but an alert: ChangeCipherSpec onwards is encrypted
                self.done = True

    def _messages(self) -> None:
        while len(self._handshake) >= 4 and not self.done:
            kind, length = self._handshake[0], int.from_bytes(self._handshake[1:4], "big")
            if len(self._handshake) < 4 + length:
                return
            body, self._handshake = self._handshake[4 : 4 + length], self._handshake[4 + length :]
            if kind == 11:  # Certificate
                self.chain = _certificate_list(body)
                if self.chain is None:
                    self.done = True
            elif kind == 14:  # ServerHelloDone: the server's flight is complete
                self.proven = self.chain is not None
                self.done = True


def _certificate_list(body: bytes) -> tuple[bytes, ...] | None:
    if len(body) < 3 or int.from_bytes(body[:3], "big") != len(body) - 3:
        return None
    certs, i = [], 3
    while i + 3 <= len(body):
        n = int.from_bytes(body[i : i + 3], "big")
        if n == 0 or i + 3 + n > len(body):
            return None
        certs.append(body[i + 3 : i + 3 + n])
        i += 3 + n
    return tuple(certs) if certs and i == len(body) else None


# -- TLS over MemoryBIO -------------------------------------------------------


class _TlsConnection:
    """One TCP connection with TLS driven through MemoryBIO."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        sslobj: ssl.SSLObject,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
        tap: _CertificateTap | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._ssl = sslobj
        self._in = incoming
        self._out = outgoing
        self._tap = tap  # fed raw bytes until the handshake ends
        self._buffer = b""
        self.eof = False
        self.requests = 0
        self.last_used = time.monotonic()

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
        ctx: ssl.SSLContext,
        session: ssl.SSLSession | None,
        timeouts: Timeouts,
        tap: _CertificateTap | None = None,
    ) -> _TlsConnection:
        try:
            async with asyncio.timeout(timeouts.connect):
                reader, writer = await asyncio.open_connection(host, port)
        except TimeoutError as err:
            raise MeterTimeout(f"connect to {host}:{port} timed out") from err
        except OSError as err:
            raise MeterConnectionError(f"connect to {host}:{port} failed: {err}") from err

        try:
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            sslobj = ctx.wrap_bio(incoming, outgoing, server_side=False, session=session)
            conn = cls(reader, writer, sslobj, incoming, outgoing, tap)
        except BaseException:
            writer.transport.abort()
            raise
        try:
            async with asyncio.timeout(timeouts.handshake):
                await conn._handshake()
        except BaseException:
            conn.abort()
            raise
        return conn

    @property
    def session(self) -> ssl.SSLSession | None:
        return self._ssl.session

    @property
    def session_reused(self) -> bool:
        return self._ssl.session_reused

    def peer_chain(self) -> tuple[bytes, ...] | None:
        """The meter's certificate chain, leaf first, after a completed
        handshake. OpenSSL's leaf is authoritative (a resumed session has no
        Certificate message; it keeps the leaf in the session); the tapped
        chain only adds the intermediates when its leaf agrees."""
        der = self._ssl.getpeercert(binary_form=True)
        if not der:
            return None
        if self._tap is not None and self._tap.chain and self._tap.chain[0] == der:
            return self._tap.chain
        return (der,)

    # _flush and _feed are the only places that touch the socket, so every
    # OSError (a reset from a meter that is clamping down, a broken pipe) is
    # turned into a MeterConnectionError here and nowhere else.

    async def _flush(self) -> None:
        data = self._out.read()
        if data:
            try:
                self._writer.write(data)
                await self._writer.drain()
            except OSError as err:
                raise MeterConnectionError(f"send to meter failed: {err}") from err

    async def _feed(self) -> bool:
        """Move bytes from the socket into the TLS engine. False on EOF."""
        try:
            data = await self._reader.read(_READ_SIZE)
        except OSError as err:
            raise MeterConnectionError(f"receive from meter failed: {err}") from err
        if not data:
            self._in.write_eof()
            return False
        if self._tap is not None and not self._tap.done:
            self._tap.feed(data)
        self._in.write(data)
        return True

    def looks_dead(self) -> bool:
        """True if the meter has visibly reset or closed this connection.

        Catches resets; a clean close_notify+FIN usually still sits unread in
        the buffer, and is handled by the retry in Batch._request instead."""
        return self._reader.at_eof() or self._reader.exception() is not None or self._writer.is_closing()

    async def _handshake(self) -> None:
        while True:
            try:
                self._ssl.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._flush()
                if not await self._feed():
                    raise MeterConnectionError("meter closed the connection during the TLS handshake") from None
            except ssl.SSLError as err:
                # Best effort: let the meter see our alert before the close.
                with suppress(Exception):
                    await asyncio.wait_for(self._flush(), 0.5)
                raise _classify_ssl_error(err) from err
        await self._flush()

    async def send(self, data: bytes) -> None:
        self.last_used = time.monotonic()
        try:
            self._ssl.write(data)
        except ssl.SSLError as err:
            raise _classify_ssl_error(err, handshake=False) from err
        await self._flush()

    async def _recv_some(self) -> bytes:
        """Decrypted bytes, or b"" once the meter has closed the connection."""
        while True:
            try:
                data = self._ssl.read(_READ_SIZE)
                if not data:
                    # A clean close_notify: SSLObject.read() returns b"".
                    self.eof = True
                self.last_used = time.monotonic()
                return data
            except ssl.SSLWantReadError:
                await self._flush()
                # On EOF, loop once more so the engine can report close_notify
                # (b"" above) or a truncated stream (SSLEOFError below).
                await self._feed()
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                self.eof = True
                return b""
            except ssl.SSLError as err:
                # Agents that let an unregistered client finish the handshake
                # send their auth alert later, so it can arrive here.
                raise _classify_ssl_error(err, handshake=False) from err

    @property
    def leftover(self) -> bool:
        """True if bytes arrived after the last complete response (none expected)."""
        return bool(self._buffer)

    async def read_response(self) -> Response:
        """Read exactly one HTTP/1.1 response, framed by its own headers."""
        buf = self._buffer
        while b"\r\n\r\n" not in buf:
            if len(buf) > _MAX_HEADER_BYTES:
                raise MeterProtocolError("HTTP response headers too large")
            try:
                chunk = await self._recv_some()
            except MeterConnectionError as err:
                if buf:
                    raise
                # Reset before the first response byte: on a reused
                # connection this is the meter's idle close racing us.
                raise _EmptyResponse(str(err)) from err
            if not chunk:
                raise _EmptyResponse() if not buf else MeterConnectionError("meter closed the connection mid-headers")
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1").split("\r\n")
        try:
            version, status_text, *reason = lines[0].split(" ", 2)
            status = int(status_text)
        except ValueError as err:
            raise MeterProtocolError(f"bad HTTP status line: {short(lines[0])}") from err
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()

        connection = {t.strip() for t in headers.get("connection", "").lower().split(",")}
        keep_alive = version == "HTTP/1.1" and "close" not in connection

        if 100 <= status < 200:
            # A 2030.5 meter never sends interim responses; half-supporting
            # them could hand one GET's body to the next. Refuse.
            raise MeterProtocolError(f"unexpected interim response {status}")
        if status in (204, 304):
            # No body by definition (RFC 9112 section 6.3).
            body, self._buffer = b"", rest
        elif "chunked" in headers.get("transfer-encoding", "").lower():
            # Chunked framing wins over Content-Length (RFC 9112 section 6.3).
            body, self._buffer = await self._read_chunked(rest)
        elif "content-length" in headers:
            try:
                length = int(headers["content-length"])
            except ValueError as err:
                raise MeterProtocolError(f"bad Content-Length {short(headers['content-length'])}") from err
            if length < 0 or length > _MAX_BODY_BYTES:
                raise MeterProtocolError(f"bad Content-Length {length}")
            body_buf = bytearray(rest)
            while len(body_buf) < length:
                chunk = await self._recv_some()
                if not chunk:
                    raise MeterConnectionError("meter closed the connection mid-body")
                body_buf += chunk
            body, self._buffer = bytes(body_buf[:length]), bytes(body_buf[length:])
        else:
            # No framing: the body runs to EOF and the connection is spent.
            body_buf = bytearray(rest)
            while True:
                chunk = await self._recv_some()
                if not chunk:
                    break
                body_buf += chunk
                if len(body_buf) > _MAX_BODY_BYTES:
                    raise MeterProtocolError("HTTP body too large")
            rest = bytes(body_buf)
            body, self._buffer, keep_alive = rest, b"", False

        return Response(status, reason[0] if reason else "", headers, body, keep_alive and not self.eof)

    async def _read_chunked(self, rest: bytes) -> tuple[bytes, bytes]:
        body = b""
        while True:
            while b"\r\n" not in rest:
                chunk = await self._recv_some()
                if not chunk:
                    raise MeterConnectionError("meter closed the connection mid-chunk")
                rest += chunk
            size_line, rest = rest.split(b"\r\n", 1)
            try:
                size = int(size_line.split(b";")[0], 16)
            except ValueError as err:
                raise MeterProtocolError(f"bad chunk size {short(size_line)}") from err
            if size < 0:
                raise MeterProtocolError("negative chunk size")
            while len(rest) < size + 2:
                chunk = await self._recv_some()
                if not chunk:
                    raise MeterConnectionError("meter closed the connection mid-chunk")
                rest += chunk
            if size == 0:
                # Skip optional trailers up to the terminating blank line.
                while not rest.startswith(b"\r\n") and b"\r\n\r\n" not in rest:
                    chunk = await self._recv_some()
                    if not chunk:
                        raise MeterConnectionError("meter closed the connection mid-trailer")
                    rest += chunk
                end = 2 if rest.startswith(b"\r\n") else rest.index(b"\r\n\r\n") + 4
                return body, rest[end:]
            body += rest[:size]
            if len(body) > _MAX_BODY_BYTES:
                raise MeterProtocolError("HTTP body too large")
            rest = rest[size + 2 :]

    async def close(self) -> None:
        """Send close_notify and close. Never raises; even if cancelled
        midway, the socket is released (it holds the meter's only slot)."""
        try:
            with suppress(Exception):
                self._ssl.unwrap()
            with suppress(Exception):
                await asyncio.wait_for(self._flush(), 1.0)
        finally:
            self.abort()
        with suppress(Exception):
            await asyncio.wait_for(self._writer.wait_closed(), 1.0)

    def abort(self) -> None:
        """Drop the TCP connection now, synchronously (safe in any state)."""
        with suppress(Exception):
            self._writer.transport.abort()


class _EmptyResponse(MeterConnectionError):
    """The meter closed or reset the connection before any response byte.

    On a reused keep-alive connection that is the meter's idle close racing
    our request, and the (idempotent) GET is safe to retry once.
    """

    def __init__(self, detail: str = "") -> None:
        msg = "meter closed the connection before responding"
        super().__init__(f"{msg} ({detail})" if detail else msg)


# TLS alert (as OpenSSL names it in the reason) -> MeterAuthError.reason
_AUTH_ALERTS: dict[str, AuthReason] = {
    "BAD_CERTIFICATE": "certificate_rejected",
    "CERTIFICATE_UNKNOWN": "certificate_rejected",
    "UNKNOWN_CA": "certificate_rejected",
    "UNSUPPORTED_CERTIFICATE": "certificate_rejected",
    "CERTIFICATE_EXPIRED": "certificate_expired",
    "CERTIFICATE_REVOKED": "certificate_revoked",
    "ACCESS_DENIED": "access_denied",
}


def _classify_ssl_error(err: ssl.SSLError, *, handshake: bool = True) -> Exception:
    reason = (getattr(err, "reason", None) or str(err)).upper()
    if handshake and "BAD_SIGNATURE" in reason:
        return _BadSignature(str(err))
    for alert, auth_reason in _AUTH_ALERTS.items():
        if alert in reason:
            return MeterAuthError(
                f"meter rejected the client certificate ({err}); check that its LFDI is "
                "registered with the utility and that it has not expired",
                reason=auth_reason,
            )
    return MeterConnectionError(f"TLS {'handshake' if handshake else 'connection'} failed: {err}")


class _BadSignature(MeterConnectionError):
    pass


async def _pace(seconds: float, deadline: asyncio.Timeout | None) -> None:
    """Sleep for connection pacing without spending the caller's deadline:
    the deadline is moved out by the same amount first."""
    if seconds <= 0:
        return
    if deadline is not None:
        when = deadline.when()
        if when is not None:
            deadline.reschedule(when + seconds)
    await asyncio.sleep(seconds)


# -- the public transport -----------------------------------------------------


@dataclass(slots=True)
class _Shared:
    """State shared by every transport to one (host, port) on one event loop.

    The meter has one connection slot, so the one-connection rule must hold
    across Meter objects too -- e.g. a Home Assistant re-auth probe built with
    a new certificate while the entry's coordinator is polling, or the CLI.
    """

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_connect: float = -1e9
    last_close: float = -1e9
    owner: asyncio.Task[Any] | None = None  # the task holding the lock


_SHARED: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[tuple[str, int], _Shared]] = (
    weakref.WeakKeyDictionary()
)
_SHARED_STRONG: dict[int, tuple[asyncio.AbstractEventLoop, dict[tuple[str, int], _Shared]]] = {}


def _shared(address: str, port: int) -> _Shared:
    """The state for one meter, keyed by its (resolved) address and port."""
    loop = asyncio.get_running_loop()
    try:
        per_loop = _SHARED.setdefault(loop, {})
    except TypeError:
        # A loop that refuses weak references is kept by id, together with the
        # loop itself so the id cannot be reused by another loop while stored.
        for stale in [k for k, (lp, _) in _SHARED_STRONG.items() if lp.is_closed()]:
            del _SHARED_STRONG[stale]
        per_loop = _SHARED_STRONG.setdefault(id(loop), (loop, {}))[1]
    return per_loop.setdefault((address.lower(), port), _Shared())


# How long a resolved host name is trusted for keying the shared state.
_RESOLVE_TTL = 300.0


async def _canonical_address(host: str, port: int, resolve_within: float) -> str:
    """One meter, one key: the same meter reached as "meter.local",
    "192.0.2.19" or "[fe80::1%eth0]" must share one lock and one pacing
    clock, or two connections could open at once. IP literals are
    normalised; names are resolved (IPv4 preferred). If resolution fails the
    name itself is the key -- connecting would fail the same way."""
    bare = host.strip("[]").split("%", 1)[0]
    with suppress(ValueError):
        return ipaddress.ip_address(bare).compressed
    try:
        async with asyncio.timeout(resolve_within):
            infos = await asyncio.get_running_loop().getaddrinfo(bare, port, type=socket.SOCK_STREAM)
        infos.sort(key=lambda info: info[0] != socket.AF_INET)
        return ipaddress.ip_address(str(infos[0][4][0]).split("%", 1)[0]).compressed
    except (OSError, TimeoutError, ValueError, IndexError):
        return bare.lower()


class MeterTransport:
    """Serialised, paced, session-resuming GET transport to one meter.

    ``async with transport.batch() as b: await b.get(path)`` runs several GETs
    on one keep-alive connection, holding the transport lock for the whole
    batch. The connection is closed when the batch ends: the meter only has
    one connection slot and closes idle ones after 30 s anyway.
    """

    def __init__(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext,
        *,
        timeouts: Timeouts | None = None,
        min_connect_interval: float = 2.0,
        request_spacing: float = 0.25,
        expected_lfdi: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._ctx = ssl_context
        self.expected_lfdi = expected_lfdi
        # The certificate from the latest handshake -- also a refused one.
        self.peer: PeerCertificate | None = None
        self._address: tuple[str, str, float] | None = None  # (host, resolved, when)
        self.timeouts = timeouts or Timeouts()
        self.min_connect_interval = min_connect_interval
        self.request_spacing = request_spacing
        self._session: ssl.SSLSession | None = None
        self.stats = TransportStats()

    @property
    def _lock(self) -> asyncio.Lock:
        return self._state().lock

    def _state(self) -> _Shared:
        """The shared state of this meter (by the last resolved address)."""
        address = self._address[1] if self._address and self._address[0] == self.host else self.host
        return _shared(address, self.port)

    async def _resolve(self) -> _Shared:
        now = time.monotonic()
        if self._address is None or self._address[0] != self.host or now - self._address[2] > _RESOLVE_TTL:
            resolved = await _canonical_address(self.host, self.port, self.timeouts.connect)
            self._address = (self.host, resolved, now)
        return self._state()

    @property
    def expected_lfdi(self) -> str | None:
        """The meter's LFDI, checked on every connection before any request
        is sent; a different device raises :class:`MeterIdentityMismatch`.
        ``None`` checks nothing."""
        return self._expected_lfdi

    @expected_lfdi.setter
    def expected_lfdi(self, lfdi: str | None) -> None:
        if lfdi is not None and not re.fullmatch(r"[0-9A-Fa-f]{40}", lfdi):
            raise ValueError(f"an LFDI is 40 hex digits, got {lfdi!r}")
        self._expected_lfdi = lfdi.upper() if lfdi else None

    def forget_session(self) -> None:
        self._session = None

    async def _connect(
        self, *, verify: bool = True, deadline: asyncio.Timeout | None = None, shared: _Shared | None = None
    ) -> _TlsConnection:
        # A batch passes the state it locked: re-resolving the host name meanwhile
        # (another task, after the TTL) must not switch pacing to another meter's.
        shared = shared or self._state()
        task = asyncio.current_task()
        if shared.owner is not None and task is not None and shared.owner is not task:
            raise RuntimeError("a Batch must be used from the task that opened it")
        # Spaced from the last connect AND the last close: a long batch must
        # not be followed by a connect the instant it ends.
        wait = max(shared.last_connect, shared.last_close) + self.min_connect_interval - time.monotonic()
        await _pace(wait, deadline)
        shared.last_connect = time.monotonic()
        t0 = time.monotonic()
        try:
            try:
                conn = await self._open_once(verify)
            except _BadSignature:
                # Meter-side signing glitch; observed ~1 in 190 handshakes, and
                # an immediate second attempt has always succeeded.
                self.stats.bad_signature_retries += 1
                _LOGGER.debug("BAD_SIGNATURE from %s; retrying handshake once", self.host)
                shared.last_close = time.monotonic()
                await _pace(self.min_connect_interval, deadline)
                shared.last_connect = time.monotonic()
                t0 = time.monotonic()
                conn = await self._open_once(verify)
            if verify:
                try:
                    self._check_identity()
                except BaseException:
                    conn.abort()
                    raise
        except BaseException:
            # A failed attempt counts as a close for pacing: a slow handshake
            # that ends in a reset must not be followed by another at once.
            shared.last_close = time.monotonic()
            raise
        self.stats.last_handshake_ms = round((time.monotonic() - t0) * 1000)
        self.stats.connections += 1
        if conn.session_reused:
            self.stats.resumed_connections += 1
        _LOGGER.debug(
            "%s:%d: connected in %d ms (%s), meter LFDI %s",
            self.host,
            self.port,
            self.stats.last_handshake_ms,
            "resumed" if conn.session_reused else "full handshake",
            short_lfdi(self.peer.lfdi) if self.peer else "unknown",
        )
        self._session = conn.session
        return conn

    async def _open_once(self, verify: bool) -> _TlsConnection:
        tap = _CertificateTap()
        self.peer = None
        try:
            conn = await _TlsConnection.open(self.host, self.port, self._ctx, self._session, self.timeouts, tap)
        except TimeoutError as err:
            raise MeterTimeout(f"TLS handshake with {self.host}:{self.port} timed out") from err
        except MeterAuthError:
            self.forget_session()
            # Only a certificate the peer proved it holds the key for.
            self._record_peer(tap.chain if tap.proven else None)
            if verify:
                # A device that is not our meter would refuse our certificate
                # too: report the real problem, the address.
                self._check_identity()
            raise
        except MeterConnectionError as err:
            # Keep the session across plain network failures (refused, reset,
            # timeout): the first connect after an outage should be the cheap
            # resumed handshake. Drop it only if TLS itself failed, in case the
            # resumption attempt is what the meter objected to.
            if isinstance(err.__cause__, ssl.SSLError):
                self.forget_session()
            raise
        self._record_peer(conn.peer_chain())
        return conn

    def _record_peer(self, chain: tuple[bytes, ...] | None) -> None:
        self.peer = PeerCertificate.from_chain(chain) if chain else None

    def _check_identity(self) -> None:
        expected = self.expected_lfdi
        if expected is None:
            return
        actual = self.peer.lfdi if self.peer else None
        if actual != expected:
            self.forget_session()
            raise MeterIdentityMismatch(self.host, expected, actual)

    @asynccontextmanager
    async def batch(self, *, verify_identity: bool = True) -> AsyncIterator[Batch]:
        """One connection's worth of requests, holding the meter's lock.

        ``verify_identity=False`` skips the :attr:`expected_lfdi` check (for
        probing an address: read :attr:`peer` afterwards).

        Not re-entrant: starting a batch for the same meter (via this or any
        other Meter object) from inside one raises RuntimeError instead of
        waiting forever on the lock.
        """
        shared = await self._resolve()
        task = asyncio.current_task()
        if task is not None and shared.owner is task:
            raise RuntimeError(f"nested batch on {self.host}:{self.port} would deadlock")
        async with shared.lock:
            shared.owner = task
            deadline = asyncio.timeout(self.timeouts.batch)
            b = Batch(self, verify_identity, deadline, shared)
            try:
                try:
                    async with deadline:
                        yield b
                except TimeoutError as err:
                    if deadline.expired():
                        raise MeterTimeout(
                            f"{self.host}:{self.port}: call exceeded its {self.timeouts.batch:g} s deadline"
                        ) from err
                    raise
            except Exception:
                self.stats.failures += 1
                raise
            finally:
                b._closed = True
                shared.owner = None
                try:
                    await b.close()
                finally:
                    b._kill()

    async def get(self, path: str) -> bytes:
        async with self.batch() as b:
            return await b.get(path)


class Batch:
    """GETs on one connection. Created only by :meth:`MeterTransport.batch`."""

    def __init__(
        self,
        transport: MeterTransport,
        verify_identity: bool = True,
        deadline: asyncio.Timeout | None = None,
        shared: _Shared | None = None,
    ) -> None:
        self._t = transport
        self._shared = shared  # the meter state whose lock this batch holds
        self._verify = verify_identity
        self._deadline = deadline
        self._conn: _TlsConnection | None = None
        self._peer: PeerCertificate | None = None
        self._last_request = -1e9
        self._busy = False
        self._closed = False

    async def get(self, path: str) -> bytes:
        """GET ``path``; return the body of a 2xx response."""
        resp = await self.request(path)
        if resp.status in (404, 410):
            raise MeterNotFound(path, resp.status, resp.reason)
        if resp.status in (401, 403):
            raise MeterAuthError(
                f"GET {path} -> HTTP {resp.status} {resp.reason}".rstrip(),
                reason="http_401" if resp.status == 401 else "http_403",
            )
        if resp.status in (429, 503):
            raise MeterBusy(f"GET {path} -> HTTP {resp.status} {resp.reason}".rstrip())
        if not 200 <= resp.status < 300:
            raise MeterHttpError(path, resp.status, resp.reason)
        return resp.body

    async def connect(self) -> PeerCertificate | None:
        """Open the batch's connection now (a no-op if one is open) and return
        the meter's certificate. A handshake alone sends no request."""
        if self._closed:
            raise RuntimeError("Batch used after its batch() block exited")
        if self._busy:
            raise RuntimeError("Batch is not safe for concurrent use; await one request at a time")
        self._busy = True
        try:
            if self._conn is not None and self._conn.looks_dead():
                await self.close()
            if self._conn is None:
                if self._closed:  # the batch ended while close() ran
                    raise RuntimeError("Batch used after its batch() block exited")
                self._conn = await self._t._connect(verify=self._verify, deadline=self._deadline, shared=self._shared)
                self._peer = self._t.peer
        finally:
            self._busy = False
        return self._peer

    @property
    def peer(self) -> PeerCertificate | None:
        """The meter's certificate on this batch's connection (None until it connects)."""
        return self._peer

    async def request(self, path: str) -> Response:
        # A Batch owns one connection and must stay on one task: two requests
        # interleaving on it would corrupt the stream or open a second
        # connection, and one used after batch() exits would hold no lock.
        if self._closed:
            raise RuntimeError("Batch used after its batch() block exited")
        if self._busy:
            raise RuntimeError("Batch is not safe for concurrent use; await one request at a time")
        self._busy = True
        try:
            return await self._request(path)
        finally:
            self._busy = False

    async def _request(self, path: str) -> Response:
        t = self._t
        target = _request_target(path)
        wait = self._last_request + t.request_spacing - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        if self._conn is not None and (
            self._conn.looks_dead() or time.monotonic() - self._conn.last_used > REUSE_IDLE_LIMIT
        ):
            # Closed by the meter, or close to its 30 s idle timeout: start
            # a fresh (resumed) connection rather than race the close.
            await self.close()
        reused = self._conn is not None
        try:
            return await self._request_once(target)
        except _EmptyResponse:
            if not reused:
                raise
            # The meter dropped a kept-alive connection before answering.
            # GET is idempotent: reconnect once.
            t.stats.reconnects_mid_batch += 1
            await self.close()
            return await self._request_once(target)
        finally:
            self._last_request = time.monotonic()

    async def _request_once(self, path: str) -> Response:
        t = self._t
        if self._conn is None:
            if self._closed:
                # The batch ended while this request was waiting (e.g. a task
                # left running by gather()): connecting now would be outside
                # the lock, beside whatever holds it.
                raise RuntimeError("Batch used after its batch() block exited")
            self._conn = await t._connect(verify=self._verify, deadline=self._deadline, shared=self._shared)
            self._peer = t.peer
        conn = self._conn
        host = _host_header(t.host, t.port)
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: {CONTENT_TYPE}\r\n\r\n".encode("ascii")
        t.stats.requests += 1
        conn.requests += 1
        t0 = time.monotonic()
        try:
            async with asyncio.timeout(t.timeouts.response):
                try:
                    await conn.send(request)
                except MeterConnectionError as err:
                    raise _EmptyResponse(str(err)) from err
                resp = await conn.read_response()
        except BaseException as err:
            # Whatever went wrong -- our timeout, the caller's cancellation, a
            # reset -- the connection may hold half a response. Drop it now,
            # synchronously, so it is never reused.
            self._kill()
            if isinstance(err, MeterAuthError):
                t.forget_session()  # never resume a session the meter rejected
            if isinstance(err, TimeoutError):
                raise MeterTimeout(f"GET {path} timed out after {t.timeouts.response:.0f} s") from err
            raise
        _LOGGER.debug(
            "GET %s -> %d, %d bytes in %d ms", path, resp.status, len(resp.body), (time.monotonic() - t0) * 1000
        )
        if conn.leftover:
            # We never pipeline, so bytes after a complete response mean the
            # stream is out of step: never serve them as the next response.
            _LOGGER.debug("GET %s: unexpected bytes after the response; reconnecting", path)
            self._kill()
        elif not resp.keep_alive:
            await self.close()
        return resp

    async def close(self) -> None:
        if self._conn is not None:
            conn, self._conn = self._conn, None
            try:
                await conn.close()
            finally:
                (self._shared or self._t._state()).last_close = time.monotonic()

    def _kill(self) -> None:
        if self._conn is not None:
            conn, self._conn = self._conn, None
            conn.abort()
            (self._shared or self._t._state()).last_close = time.monotonic()


# Reconnect instead of reusing a connection idle this long (the meter closes
# idle connections at 30 s).
REUSE_IDLE_LIMIT = 25.0


def _request_target(path: str) -> str:
    """Validate a request target taken from meter XML: an origin-form path of
    printable ASCII. Anything else is a protocol error, never a header
    injection or a request to another host."""
    if not path.startswith("/") or not path.isascii() or not path.isprintable() or " " in path:
        raise MeterProtocolError(f"unusable href from meter: {short(path)}")
    return path


def _host_header(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


# The public names; everything else here is internal.
__all__ = [
    "PeerCertificate",
    "Timeouts",
    "TransportStats",
    "async_build_ssl_context",
    "build_ssl_context",
    "build_ssl_context_from_pem",
]
