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
import logging
import ssl
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field

from .exceptions import (
    MeterAuthError,
    MeterConnectionError,
    MeterHttpError,
    MeterNotFound,
    MeterProtocolError,
    MeterTimeout,
)

_LOGGER = logging.getLogger(__name__)

IEEE_2030_5_CIPHERS = "ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0"
CONTENT_TYPE = "application/sep+xml"
_READ_SIZE = 16384
_MAX_HEADER_BYTES = 16384
_MAX_BODY_BYTES = 4 * 1024 * 1024


def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """TLS client context for an IEEE 2030.5 HAN meter.

    Blocking (reads the cert and key files): call it from an executor in an
    event loop. The meter's server certificate is self-signed by the meter and
    cannot be verified, so verification is disabled -- on this context only.
    Trust runs the other way: the meter admits us because our certificate's
    LFDI is registered with the utility.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    ctx.set_ciphers(IEEE_2030_5_CIPHERS)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


@dataclass(frozen=True, slots=True)
class Timeouts:
    connect: float = 10.0
    handshake: float = 20.0  # full handshakes have taken 11 s on a busy meter
    response: float = 20.0


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

    def as_dict(self) -> dict[str, int | None]:
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
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._ssl = sslobj
        self._in = incoming
        self._out = outgoing
        self._buffer = b""
        self.eof = False
        self.requests = 0

    @classmethod
    async def open(
        cls,
        host: str,
        port: int,
        ctx: ssl.SSLContext,
        session: ssl.SSLSession | None,
        timeouts: Timeouts,
    ) -> _TlsConnection:
        try:
            async with asyncio.timeout(timeouts.connect):
                reader, writer = await asyncio.open_connection(host, port)
        except TimeoutError as err:
            raise MeterTimeout(f"connect to {host}:{port} timed out") from err
        except OSError as err:
            raise MeterConnectionError(f"connect to {host}:{port} failed: {err}") from err

        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        sslobj = ctx.wrap_bio(incoming, outgoing, server_side=False, session=session)
        conn = cls(reader, writer, sslobj, incoming, outgoing)
        try:
            async with asyncio.timeout(timeouts.handshake):
                await conn._handshake()
        except BaseException:
            conn._abort()
            raise
        return conn

    @property
    def session(self) -> ssl.SSLSession | None:
        return self._ssl.session

    @property
    def session_reused(self) -> bool:
        return self._ssl.session_reused

    async def _flush(self) -> None:
        data = self._out.read()
        if data:
            self._writer.write(data)
            await self._writer.drain()

    async def _feed(self) -> bool:
        """Move bytes from the socket into the TLS engine. False on EOF."""
        data = await self._reader.read(_READ_SIZE)
        if not data:
            self._in.write_eof()
            return False
        self._in.write(data)
        return True

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
                raise _classify_ssl_error(err) from err
        await self._flush()

    async def send(self, data: bytes) -> None:
        try:
            self._ssl.write(data)
        except ssl.SSLError as err:
            raise MeterConnectionError(f"TLS write failed: {err}") from err
        try:
            await self._flush()
        except OSError as err:
            raise MeterConnectionError(f"send failed: {err}") from err

    async def _recv_some(self) -> bytes:
        """Decrypted bytes, or b"" once the meter has closed the connection."""
        while True:
            try:
                return self._ssl.read(_READ_SIZE)
            except ssl.SSLWantReadError:
                await self._flush()
                try:
                    more = await self._feed()
                except OSError as err:
                    raise MeterConnectionError(f"receive failed: {err}") from err
                if not more:
                    # Loop once more so the engine can surface close_notify
                    # (SSLZeroReturnError) or a truncation (SSLEOFError).
                    continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                self.eof = True
                return b""
            except ssl.SSLError as err:
                raise MeterConnectionError(f"TLS read failed: {err}") from err

    async def read_response(self) -> Response:
        """Read exactly one HTTP/1.1 response, framed by its own headers."""
        buf = self._buffer
        while b"\r\n\r\n" not in buf:
            if len(buf) > _MAX_HEADER_BYTES:
                raise MeterProtocolError("HTTP response headers too large")
            chunk = await self._recv_some()
            if not chunk:
                raise _EmptyResponse() if not buf else MeterConnectionError("meter closed the connection mid-headers")
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1").split("\r\n")
        try:
            version, status_text, *reason = lines[0].split(" ", 2)
            status = int(status_text)
        except ValueError as err:
            raise MeterProtocolError(f"bad HTTP status line: {lines[0]!r}") from err
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()

        connection = headers.get("connection", "").lower()
        keep_alive = version == "HTTP/1.1" and connection != "close"

        if "content-length" in headers:
            try:
                length = int(headers["content-length"])
            except ValueError as err:
                raise MeterProtocolError("bad Content-Length") from err
            if length > _MAX_BODY_BYTES:
                raise MeterProtocolError("HTTP body too large")
            while len(rest) < length:
                chunk = await self._recv_some()
                if not chunk:
                    raise MeterConnectionError("meter closed the connection mid-body")
                rest += chunk
            body, self._buffer = rest[:length], rest[length:]
        elif "chunked" in headers.get("transfer-encoding", "").lower():
            body, self._buffer = await self._read_chunked(rest)
        else:
            # No framing: the body runs to EOF and the connection is spent.
            while True:
                chunk = await self._recv_some()
                if not chunk:
                    break
                rest += chunk
                if len(rest) > _MAX_BODY_BYTES:
                    raise MeterProtocolError("HTTP body too large")
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
                raise MeterProtocolError("bad chunk size") from err
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
                        break
                    rest += chunk
                end = 2 if rest.startswith(b"\r\n") else rest.index(b"\r\n\r\n") + 4
                return body, rest[end:]
            body += rest[:size]
            if len(body) > _MAX_BODY_BYTES:
                raise MeterProtocolError("HTTP body too large")
            rest = rest[size + 2 :]

    async def close(self) -> None:
        """Send close_notify and close. Never raises."""
        with suppress(Exception):
            self._ssl.unwrap()
        with suppress(Exception):
            await asyncio.wait_for(self._flush(), 1.0)
        self._abort()
        with suppress(Exception):
            await asyncio.wait_for(self._writer.wait_closed(), 1.0)

    def _abort(self) -> None:
        with suppress(Exception):
            self._writer.close()


class _EmptyResponse(MeterConnectionError):
    """The meter closed a kept-alive connection before answering: safe to retry."""

    def __init__(self) -> None:
        super().__init__("meter closed the connection before responding")


def _classify_ssl_error(err: ssl.SSLError) -> Exception:
    reason = (getattr(err, "reason", None) or str(err)).upper()
    if "BAD_SIGNATURE" in reason:
        return _BadSignature(str(err))
    if any(
        k in reason
        for k in (
            "BAD_CERTIFICATE",
            "CERTIFICATE_UNKNOWN",
            "CERTIFICATE_EXPIRED",
            "UNKNOWN_CA",
            "ACCESS_DENIED",
            "CERTIFICATE_REVOKED",
        )
    ):
        return MeterAuthError(
            f"meter rejected the client certificate ({err}); check that its LFDI is "
            "registered with the utility and that it has not expired"
        )
    return MeterConnectionError(f"TLS handshake failed: {err}")


class _BadSignature(MeterConnectionError):
    pass


# -- the public transport -----------------------------------------------------


@dataclass(slots=True)
class _Pacing:
    last_connect: float = field(default=-1e9)


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
    ) -> None:
        self.host = host
        self.port = port
        self._ctx = ssl_context
        self.timeouts = timeouts or Timeouts()
        self.min_connect_interval = min_connect_interval
        self.request_spacing = request_spacing
        self._lock = asyncio.Lock()
        self._session: ssl.SSLSession | None = None
        self._pacing = _Pacing()
        self.stats = TransportStats()

    def forget_session(self) -> None:
        self._session = None

    async def _connect(self) -> _TlsConnection:
        wait = self._pacing.last_connect + self.min_connect_interval - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self._pacing.last_connect = time.monotonic()
        t0 = time.monotonic()
        try:
            conn = await self._open_once()
        except _BadSignature:
            # Meter-side signing glitch; observed ~1 in 190 handshakes, and an
            # immediate second attempt has always succeeded.
            self.stats.bad_signature_retries += 1
            _LOGGER.debug("BAD_SIGNATURE from %s; retrying handshake once", self.host)
            await asyncio.sleep(self.min_connect_interval)
            self._pacing.last_connect = time.monotonic()
            t0 = time.monotonic()
            conn = await self._open_once()
        self.stats.last_handshake_ms = round((time.monotonic() - t0) * 1000)
        self.stats.connections += 1
        if conn.session_reused:
            self.stats.resumed_connections += 1
        self._session = conn.session
        return conn

    async def _open_once(self) -> _TlsConnection:
        try:
            return await _TlsConnection.open(self.host, self.port, self._ctx, self._session, self.timeouts)
        except TimeoutError as err:
            self.forget_session()
            raise MeterTimeout(f"TLS handshake with {self.host}:{self.port} timed out") from err
        except MeterConnectionError:
            # A failed resumption attempt must not poison the next connect.
            self.forget_session()
            raise

    @asynccontextmanager
    async def batch(self) -> AsyncIterator[Batch]:
        async with self._lock:
            b = Batch(self)
            try:
                yield b
            except Exception:
                self.stats.failures += 1
                raise
            finally:
                await b.close()

    async def get(self, path: str) -> bytes:
        async with self.batch() as b:
            return await b.get(path)


class Batch:
    """GETs on one connection. Created only by :meth:`MeterTransport.batch`."""

    def __init__(self, transport: MeterTransport) -> None:
        self._t = transport
        self._conn: _TlsConnection | None = None
        self._last_request = -1e9

    async def get(self, path: str) -> bytes:
        """GET ``path``; return the body of a 2xx response."""
        resp = await self.request(path)
        if resp.status in (404, 410):
            raise MeterNotFound(path, resp.status, resp.reason)
        if not 200 <= resp.status < 300:
            raise MeterHttpError(path, resp.status, resp.reason)
        return resp.body

    async def request(self, path: str) -> Response:
        t = self._t
        wait = self._last_request + t.request_spacing - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        reused = self._conn is not None
        try:
            return await self._request_once(path)
        except _EmptyResponse:
            if not reused:
                raise
            # The meter dropped a kept-alive connection before answering (e.g.
            # its 30 s idle timer raced us). GET is idempotent: reconnect once.
            t.stats.reconnects_mid_batch += 1
            await self.close()
            return await self._request_once(path)
        finally:
            self._last_request = time.monotonic()

    async def _request_once(self, path: str) -> Response:
        t = self._t
        if self._conn is None:
            self._conn = await t._connect()
        conn = self._conn
        request = (f"GET {path} HTTP/1.1\r\nHost: {t.host}:{t.port}\r\nAccept: {CONTENT_TYPE}\r\n\r\n").encode("ascii")
        t.stats.requests += 1
        conn.requests += 1
        try:
            async with asyncio.timeout(t.timeouts.response):
                await conn.send(request)
                resp = await conn.read_response()
        except TimeoutError as err:
            await self.close()
            raise MeterTimeout(f"GET {path} timed out after {t.timeouts.response:.0f} s") from err
        except MeterConnectionError:
            await self.close()
            raise
        if not resp.keep_alive:
            await self.close()
        return resp

    async def close(self) -> None:
        if self._conn is not None:
            conn, self._conn = self._conn, None
            await conn.close()
