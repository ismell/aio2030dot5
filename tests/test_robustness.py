"""Regression tests from the 2026-10-06 review: cancellation, misuse, resets,
odd framing and malformed input must never desync a connection, open a
second one, or escape as anything but a MeterError."""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
import time
from pathlib import Path

import pytest

from aio2030dot5 import MeterAuthError, MeterConnectionError, MeterProtocolError, Timeouts
from aio2030dot5 import transport as T
from aio2030dot5.models import ListPage, Reading, parse_xml

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree
from .scripted_server import Server, read_request, rst, server_ctx


class SlowTree(FixtureTree):
    """Answers requests whose target contains "slow" after 0.5 s."""

    def respond(self, target: str) -> tuple[int, str]:
        if "slow" in target:
            time.sleep(0.5)
        return super().respond(target)


async def test_cancelled_get_never_desyncs_the_batch(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[T._TlsConnection] = []
    real_open = T._TlsConnection.open

    async def spy(*a, **k):  # type: ignore[no-untyped-def]
        if opened:
            # The abandoned connection must already be dropped (client side)
            # before a new one is opened. (The fake meter's handler thread may
            # still be busy with it; production spaces connects by 2 s.)
            assert opened[-1]._writer.is_closing()
        c = await real_open(*a, **k)
        opened.append(c)
        return c

    monkeypatch.setattr(T._TlsConnection, "open", spy)
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        meter = make_meter(pki, fm.port)
        async with meter.transport.batch() as b:
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.2):  # the caller's own deadline
                    await b.get("/dcap?slow=1")
            body = await b.get("/tm")
        assert body.lstrip().startswith(b"<Time")
        assert len(opened) == 2  # the half-read connection was dropped, not reused


async def test_concurrent_use_of_one_batch_is_refused(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        meter = make_meter(pki, fm.port)
        async with meter.transport.batch() as b:
            results = await asyncio.gather(b.get("/dcap?slow=1"), b.get("/tm"), return_exceptions=True)
        assert isinstance(results[1], RuntimeError)
        assert fm.log.max_concurrent == 1 and fm.log.connections == 1


async def test_batch_is_dead_after_its_block(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as fm:
        meter = make_meter(pki, fm.port)
        async with meter.transport.batch() as b:
            pass
        with pytest.raises(RuntimeError):
            await b.get("/dcap")
        assert fm.log.connections == 0


async def test_reset_during_handshake_is_a_connection_error(pki: Pki) -> None:
    def handler(raw):  # type: ignore[no-untyped-def]
        raw.recv(4096)  # ClientHello
        rst(raw)

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        with pytest.raises(MeterConnectionError):
            await meter.transport.get("/dcap")


@pytest.mark.parametrize("case", ["unregistered", "expired"])
async def test_rejected_certificate_is_an_auth_error(pki: Pki, tmp_path: Path, case: str) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    ca, cert, key = pki.other_client_cert, str(pki.client_cert), str(pki.client_key)
    if case == "expired":
        k = ec.generate_private_key(ec.SECP256R1())
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
        now = dt.datetime.now(dt.UTC)
        c = (
            x509.CertificateBuilder()
            .subject_name(n)
            .issuer_name(n)
            .public_key(k.public_key())
            .serial_number(1)
            .not_valid_before(now - dt.timedelta(days=10))
            .not_valid_after(now - dt.timedelta(days=1))
            .sign(k, hashes.SHA256())
        )
        (tmp_path / "c.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
        (tmp_path / "k.pem").write_bytes(
            k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        )
        cert, key, ca = str(tmp_path / "c.pem"), str(tmp_path / "k.pem"), tmp_path / "c.pem"
    sctx = server_ctx(pki, client_ca=ca)

    def handler(raw):  # type: ignore[no-untyped-def]
        try:
            sctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError:
            pass

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        meter.transport._ctx = T.build_ssl_context(cert, key)
        with pytest.raises(MeterAuthError):
            await meter.transport.get("/dcap")


async def test_reset_of_a_reused_connection_reconnects(pki: Pki) -> None:
    sctx = server_ctx(pki)
    state = {"n": 0}

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        state["n"] += 1
        read_request(tls)
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        if state["n"] == 1:
            time.sleep(0.1)
            rst(tls)  # the meter's idle close arriving as a reset
        else:
            read_request(tls)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            read_request(tls)

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        async with meter.transport.batch() as b:
            assert await b.get("/a") == b"ok"
            await asyncio.sleep(0.3)
            assert await b.get("/b") == b"ok"
        assert srv.connections == 2 and srv.max_active == 1


async def test_idle_connection_is_replaced_before_the_meter_drops_it(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(T, "REUSE_IDLE_LIMIT", 0.2)
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as fm:
        meter = make_meter(pki, fm.port)
        async with meter.transport.batch() as b:
            await b.get("/dcap")
            await asyncio.sleep(0.3)
            await b.get("/tm")
        assert fm.log.connections == 2 and meter.stats.reconnects_mid_batch == 0
        assert fm.log.resumed == 1


async def test_bodyless_status_does_not_wait_for_eof(pki: Pki) -> None:
    sctx = server_ctx(pki)

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
        time.sleep(3)

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port, timeouts=Timeouts(1, 1, 1))
        async with meter.transport.batch() as b:
            async with asyncio.timeout(0.8):
                resp = await b.request("/x")
        assert resp.status == 204 and resp.body == b""


async def test_truncated_chunked_trailer_is_a_connection_error(pki: Pki) -> None:
    sctx = server_ctx(pki)

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n")
        tls.unwrap()
        tls.close()

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        with pytest.raises(MeterConnectionError):
            await meter.transport.get("/x")


@pytest.mark.parametrize("href", ["/upt/é", "upt/1", "http://evil.example/x", "/a\r\nX-Injected: 1", "/a b"])
async def test_bad_hrefs_are_refused_before_any_connection(pki: Pki, href: str) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as fm:
        meter = make_meter(pki, fm.port)
        with pytest.raises(MeterProtocolError):
            await meter.transport.get(href)
        assert fm.log.connections == 0


async def test_cancel_during_close_still_releases_the_socket(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as fm:
        meter = make_meter(pki, fm.port)
        conns: list[T._TlsConnection] = []
        real_open = T._TlsConnection.open

        async def spy(*a, **k):  # type: ignore[no-untyped-def]
            c = await real_open(*a, **k)
            conns.append(c)
            return c

        monkeypatch.setattr(T._TlsConnection, "open", spy)

        async def slow_flush(self):  # type: ignore[no-untyped-def]
            self._out.read()
            await asyncio.sleep(0.5)  # a meter that stopped reading

        async def work() -> None:
            async with meter.transport.batch() as b:
                await b.get("/dcap")
                monkeypatch.setattr(T._TlsConnection, "_flush", slow_flush)

        task = asyncio.create_task(work())
        await asyncio.sleep(0.3)  # inside close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert conns[0]._writer.is_closing()
        assert not meter.transport._lock.locked()


async def test_close_notify_marks_eof(pki: Pki) -> None:
    sctx = server_ctx(pki)

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(b"HTTP/1.1 200 OK\r\n\r\nbody-to-eof")
        tls.unwrap()
        tls.close()

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        async with meter.transport.batch() as b:
            resp = await b.request("/x")
        assert resp.body == b"body-to-eof" and not resp.keep_alive


@pytest.mark.parametrize(
    "xml",
    [
        '<Reading xmlns="urn:ieee:std:2030.5:ns"><localID>zz</localID></Reading>',
        '<Reading xmlns="urn:ieee:std:2030.5:ns"><timePeriod><start>99999999999999999</start></timePeriod></Reading>',
    ],
)
def test_malformed_reading_is_a_protocol_error(xml: str) -> None:
    with pytest.raises(MeterProtocolError):
        Reading.from_xml(parse_xml(xml))


def test_malformed_list_attributes_are_a_protocol_error() -> None:
    with pytest.raises(MeterProtocolError):
        ListPage.of(parse_xml('<ReadingList xmlns="urn:ieee:std:2030.5:ns" all="many" results="1"/>'))
