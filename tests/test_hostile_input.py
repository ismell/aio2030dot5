"""Input a healthy meter never sends -- framing, XML and numbers -- fails as a
typed MeterError, quickly, and without unbounded memory."""

from __future__ import annotations

import socket
import time
from datetime import UTC, datetime

import pytest

from aio2030dot5 import MeterProtocolError, ProfileError, ReadingType
from aio2030dot5.models import MAX_TEXT, Reading, ReadingSetInfo, add_seconds, interval_values, parse_xml, text
from aio2030dot5.profile import MAX_LIST_ITEMS

from .conftest import Pki, make_meter
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


# -- HTTP framing -------------------------------------------------------------------

OK = b"HTTP/1.1 200 OK\r\n"


async def test_chunked_body_with_trailers_still_works(pki: Pki) -> None:
    body = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
    assert await _get(pki, OK + b"Transfer-Encoding: chunked\r\n\r\n" + body) == b"hello world"


@pytest.mark.parametrize(
    "chunks",
    [
        pytest.param(b"FFFFFFF\r\n", id="declared-size-beyond-the-body-cap"),
        pytest.param(b"1" * 2000, id="size-line-without-end"),
        pytest.param(b"0x10\r\n", id="prefixed-size"),
        pytest.param(b"+10\r\n", id="signed-size"),
        pytest.param(b"1_0\r\n", id="underscored-size"),
        pytest.param(b"2\r\nokXX", id="chunk-not-ended-by-crlf"),
        pytest.param(b"0\r\n" + b"X-T: " + b"a" * 20000, id="endless-trailers"),
    ],
)
async def test_bad_chunked_framing_is_refused_early(pki: Pki, chunks: bytes) -> None:
    started = time.monotonic()
    with pytest.raises(MeterProtocolError):
        await _get(pki, OK + b"Transfer-Encoding: chunked\r\n\r\n" + chunks)
    assert time.monotonic() - started < 1.5  # not after the response timeout


@pytest.mark.parametrize("length", [b"+5", b"1_0", b" 5x", b"99999999999"])
async def test_content_length_must_be_plain_digits(pki: Pki, length: bytes) -> None:
    with pytest.raises(MeterProtocolError):
        await _get(pki, OK + b"Content-Length: " + length + b"\r\n\r\nhello")


async def test_an_unframed_body_cut_without_close_notify_is_not_trusted(pki: Pki) -> None:
    with pytest.raises(MeterProtocolError):  # unusable, not an outage: no back-off loop
        await _get(pki, OK + b"Connection: close\r\n\r\npartial", close_notify=False)


# -- XML ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "doc",
    [
        f'<!DOCTYPE t [<!ENTITY e "{"x" * 100}">]><Time {NS}><currentTime>&e;</currentTime></Time>',
        f"<!DOCTYPE Time><Time {NS}/>",
    ],
)
def test_a_document_type_declaration_is_refused(doc: str) -> None:
    for body in (doc, doc.encode(), doc.encode("utf-16")):
        with pytest.raises(MeterProtocolError):
            parse_xml(body)


def test_element_text_is_clamped() -> None:
    root = parse_xml(f"<R {NS}><description>{'d' * 100_000}</description></R>")
    assert len(text(root, "description") or "") == MAX_TEXT


# -- numbers ----------------------------------------------------------------------------


def _reading(local_id: str = "1", duration: str | None = None) -> Reading:
    period = f"<timePeriod><duration>{duration}</duration><start>0</start></timePeriod>" if duration else ""
    return Reading.from_xml(parse_xml(f"<Reading {NS}><localID>{local_id}</localID>{period}<value>1</value></Reading>"))


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: _reading(local_id="FFFFFFFF"), id="localID-wider-than-HexBinary16"),
        pytest.param(lambda: _reading(duration="99999999999999"), id="duration-beyond-UInt32"),
        pytest.param(
            lambda: ReadingType.from_xml(
                parse_xml(f"<ReadingType {NS}><intervalLength>-1</intervalLength></ReadingType>")
            ),
            id="negative-intervalLength",
        ),
    ],
)
def test_out_of_range_numbers_are_protocol_errors(build) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(MeterProtocolError):
        build()


def test_date_arithmetic_past_the_calendar_is_a_protocol_error() -> None:
    late = datetime(9999, 12, 31, tzinfo=UTC)
    with pytest.raises(MeterProtocolError):
        add_seconds(late, 2**31)
    rs = ReadingSetInfo("/rs/1", None, late, 2**31, "/rs/1/r", None)
    rt = ReadingType.from_dict({"uom": 72, "accumulationBehaviour": 4, "intervalLength": 900})
    with pytest.raises(MeterProtocolError):
        interval_values(rs, [_reading(local_id="FFFF")], rt)


@pytest.mark.parametrize(
    "cached",
    [
        {"powerOfTenMultiplier": 10**9},
        {"intervalLength": "900"},
        {"uom": True},
        {"kind": -1},
    ],
)
def test_a_tampered_cached_reading_type_is_a_profile_error(cached: dict) -> None:  # type: ignore[type-arg]
    with pytest.raises(ProfileError):
        ReadingType.from_dict(cached)


# -- lists ---------------------------------------------------------------------------------


async def test_a_list_claiming_millions_of_items_is_refused(pki: Pki) -> None:
    sctx = server_ctx(pki)
    served = 0

    def handler(raw):  # type: ignore[no-untyped-def]
        nonlocal served
        tls = sctx.wrap_socket(raw, server_side=True)
        while read_request(tls):
            served += 1
            items = "".join(f'<ReadingSet href="/rs/{served}_{i}"/>' for i in range(255))
            body = f'<ReadingSetList {NS} all="4294967295" results="255">{items}</ReadingSetList>'.encode()
            tls.sendall(OK + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    from aio2030dot5.profile import get_list

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        with pytest.raises(MeterProtocolError):
            async with meter._transport.batch() as b:
                await get_list(b, "/rs", "ReadingSet")
    assert served * 255 <= MAX_LIST_ITEMS + 255


# -- secrets and identifying data stay out of reprs and exceptions -----------------------


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


def test_an_absurdly_long_href_is_refused() -> None:
    from aio2030dot5.models import MAX_HREF, link
    from aio2030dot5.profile import resolve_href

    root = parse_xml(f'<R {NS}><TimeLink href="/{"t" * MAX_HREF}"/></R>')
    with pytest.raises(MeterProtocolError) as exc:
        link(root, "TimeLink")
    assert len(str(exc.value)) < 200  # and the message stays short
    with pytest.raises(MeterProtocolError):
        resolve_href("/dcap", "/" + "x" * (MAX_HREF + 1), "192.0.2.19", 8081)


async def test_one_page_claiming_too_many_items_is_refused(pki: Pki) -> None:
    from aio2030dot5.profile import get_list

    sctx = server_ctx(pki)
    items = "".join(f'<ReadingSet href="/rs/{i}"/>' for i in range(MAX_LIST_ITEMS + 1))
    body = f'<ReadingSetList {NS} all="{MAX_LIST_ITEMS + 1}" results="{MAX_LIST_ITEMS + 1}">{items}</ReadingSetList>'

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        while read_request(tls):
            data = body.encode()
            tls.sendall(OK + b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        with pytest.raises(MeterProtocolError):
            async with meter._transport.batch() as b:
                await get_list(b, "/rs", "ReadingSet")


async def test_a_zero_padded_chunk_size_is_fine(pki: Pki) -> None:
    body = b"000000005\r\nhello\r\n0000\r\n\r\n"
    assert await _get(pki, OK + b"Transfer-Encoding: chunked\r\n\r\n" + body) == b"hello"


def test_numbers_too_long_for_any_type_are_refused_not_truncated() -> None:
    with pytest.raises(MeterProtocolError):
        Reading.from_xml(parse_xml(f"<Reading {NS}><value>{'0' * 1100}5</value></Reading>"))


def test_a_flood_of_elements_is_refused() -> None:
    from aio2030dot5.models import MAX_ELEMENTS

    with pytest.raises(MeterProtocolError):
        parse_xml(f"<R {NS}>" + "<a/>" * (MAX_ELEMENTS + 1) + "</R>")


@pytest.mark.parametrize("field", ["phase", "numberOfTouTiers", "kind"])
def test_a_discovered_reading_type_is_bounded_like_a_cached_one(field: str) -> None:
    with pytest.raises(MeterProtocolError):
        ReadingType.from_xml(parse_xml(f"<ReadingType {NS}><{field}>{2**40}</{field}></ReadingType>"))


def test_exceptions_survive_copy_and_pickle() -> None:
    import copy
    import pickle

    from aio2030dot5 import InvalidIdentity, MeterAuthError, MeterHttpError, MeterIdentityMismatch, MeterNotFound

    errors = [
        MeterIdentityMismatch("192.0.2.19", "A" * 40, "B" * 40),
        MeterNotFound("/upt/1", 404),
        MeterHttpError("/upt/1", 500, "Oops"),
        MeterAuthError("refused", "http_403"),
        InvalidIdentity("bad", ("why",)),
    ]
    for err in errors:
        for again in (copy.copy(err), pickle.loads(pickle.dumps(err))):
            assert type(again) is type(err) and str(again) == str(err) and vars(again) == vars(err)
    assert "A" * 40 not in str(errors[0])  # the message shortens the LFDIs


async def test_bytes_after_a_content_length_body_belong_to_the_next_response(pki: Pki) -> None:
    sctx = server_ctx(pki)

    def response(body: bytes) -> bytes:
        return OK + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(response(b"first") + response(b"second"))  # two responses in one write
        read_request(tls)
        tls.sendall(response(b"third"))  # what a client that lost "second" would read
        time.sleep(0.3)

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port)
        async with meter._transport.batch() as b:
            assert await b.get("/a") == b"first"
            assert await b.get("/b") == b"second"


@pytest.mark.parametrize("line", [b"\r\n", b";ext=1\r\n"])
async def test_an_empty_chunk_size_is_not_the_last_chunk(pki: Pki, line: bytes) -> None:
    with pytest.raises(MeterProtocolError):
        await _get(pki, OK + b"Transfer-Encoding: chunked\r\n\r\n" + line + b"5\r\nhello\r\n0\r\n\r\n")


def test_a_flood_of_attributes_is_refused() -> None:
    from aio2030dot5.models import MAX_ELEMENTS

    attrs = " ".join(f'a{i}="1"' for i in range(MAX_ELEMENTS + 1))
    with pytest.raises(MeterProtocolError):
        parse_xml(f"<R {NS} {attrs}/>")


# Underscores, Arabic-Indic and fullwidth digits, and a hex prefix are not xs:integer.
@pytest.mark.parametrize("number", ["1_000", "\u0665", "\uff15", "0x10"])
def test_integers_are_plain_ascii_digits(number: str) -> None:
    with pytest.raises(MeterProtocolError):
        Reading.from_xml(parse_xml(f"<Reading {NS}><value>{number}</value></Reading>"))


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
