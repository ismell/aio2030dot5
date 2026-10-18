"""Privacy (no key text, certificate or whole meter ID in messages and logs) and
HTTP framing a 2030.5 server may legitimately use."""

from __future__ import annotations

import socket
import time

import pytest

from aio2030dot5 import MeterProtocolError, sfdi_from_lfdi
from aio2030dot5.models import parse_xml

from .conftest import Pki, make_meter
from .meter_server import FakeMeter
from .scripted_server import Server, read_request, server_ctx

NS = 'xmlns="urn:ieee:std:2030.5:ns"'


async def _get(pki: Pki, response: bytes, *, close_notify: bool = True) -> bytes:
    sctx = server_ctx(pki)

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(response)
        if close_notify:
            time.sleep(0.3)
        else:
            raw.shutdown(socket.SHUT_RDWR)  # FIN without close_notify

    with Server(handler) as srv:
        return await make_meter(pki, srv.port)._transport.get("/x")


OK = b"HTTP/1.1 200 OK\r\n"


async def test_chunked_body_with_trailers_still_works(pki: Pki) -> None:
    body = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
    assert await _get(pki, OK + b"Transfer-Encoding: chunked\r\n\r\n" + body) == b"hello world"


def test_a_peer_certificate_repr_leaves_out_the_der() -> None:
    from aio2030dot5.transport import PeerCertificate

    cert = PeerCertificate(lfdi="A" * 40, sfdi="1", der=b"SERIAL-1234" * 200, chain=(b"SERIAL-1234",))
    assert "SERIAL" not in repr(cert)


def test_non_ascii_pem_raises_without_carrying_the_key_along() -> None:
    from aio2030dot5 import InvalidIdentity, load_identity
    from aio2030dot5.transport import build_ssl_context_from_pem

    key = "-----BEGIN PRIVATE KEY-----\nSECRETé\n-----END PRIVATE KEY-----\n"
    for call in (lambda: load_identity("cert", key), lambda: build_ssl_context_from_pem("cert", key)):
        with pytest.raises(InvalidIdentity) as exc:
            call()
        assert exc.value.__context__ is None and exc.value.__cause__ is None


def test_pem_must_be_text_or_bytes() -> None:
    from aio2030dot5 import InvalidIdentity
    from aio2030dot5.transport import build_ssl_context_from_pem

    with pytest.raises(InvalidIdentity):
        build_ssl_context_from_pem(10**9, b"")  # type: ignore[arg-type]  # not a gigabyte of zeros


@pytest.mark.parametrize("encoding", ["utf-32", "shift_jis", "nosuch"])
def test_an_unreadable_declared_encoding_is_a_protocol_error(encoding: str) -> None:
    with pytest.raises(MeterProtocolError):
        parse_xml(f'<?xml version="1.0" encoding="{encoding}"?><Time {NS}/>'.encode())


async def test_bytes_after_a_response_are_never_served_as_the_next_one(pki: Pki) -> None:
    """We never pipeline: leftover bytes mean the stream is out of step, so the
    connection is dropped and the next GET gets a fresh answer on a new one."""
    sctx = server_ctx(pki)
    connections = 0

    def response(body: bytes) -> bytes:
        return OK + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

    def handler(raw):  # type: ignore[no-untyped-def]
        nonlocal connections
        connections += 1
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        if connections == 1:
            tls.sendall(response(b"first") + response(b"stale"))  # one response too many
        else:
            tls.sendall(response(b"fresh"))
        time.sleep(0.3)

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        async with meter._transport.batch() as b:
            assert await b.get("/a") == b"first"
            assert await b.get("/b") == b"fresh"
        assert connections == 2


def test_messages_never_carry_a_whole_lfdi_or_its_sfdi() -> None:
    from aio2030dot5 import MeterIdentityMismatch, sfdi_from_lfdi

    expected, actual = "0123456789ABCDEF0123456789ABCDEF01234567", "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
    text = str(MeterIdentityMismatch("192.0.2.19", expected, actual))
    for lfdi in (expected, actual):
        assert lfdi not in text and sfdi_from_lfdi(lfdi) not in text and lfdi[-6:] in text


def test_a_wrong_call_to_from_dict_is_not_bad_data() -> None:
    from aio2030dot5 import Measurement

    with pytest.raises(TypeError):
        Measurement.from_dict()  # type: ignore[call-arg]


async def test_debug_logs_never_carry_a_whole_lfdi_or_sfdi(
    pki: Pki, fake_meter: FakeMeter, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.DEBUG, logger="aio2030dot5")
    meter = make_meter(pki, fake_meter.port)
    await meter.discover()
    lfdi = meter.expected_lfdi
    assert lfdi is not None
    assert lfdi not in caplog.text and sfdi_from_lfdi(lfdi) not in caplog.text
    assert lfdi[-6:] in caplog.text  # the short form is there


def test_an_sfdi_in_an_mdns_name_is_logged_by_its_last_three_digits() -> None:
    from aio2030dot5.locate import _masked

    assert _masked("651057190448._smartenergy._tcp.local.") == "...448._smartenergy._tcp.local."
    assert _masked("meter-12._smartenergy._tcp.local.") == "meter-12._smartenergy._tcp.local."  # not an SFDI
