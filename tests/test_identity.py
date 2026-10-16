"""Client and meter identity: certificates, LFDIs, SFDIs and keys."""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from aio2030dot5 import (
    Identity,
    InvalidIdentity,
    Meter,
    MeterAuthError,
    MeterIdentityMismatch,
    build_ssl_context,
    build_ssl_context_from_pem,
    format_lfdi,
    generate_identity,
    load_identity,
    manufacturer_name,
)
from aio2030dot5 import transport as T
from aio2030dot5.identity import check_identity, sfdi_from_lfdi
from aio2030dot5.models import ReadingType

from .conftest import FAST, Pki, make_meter
from .helpers import registered
from .meter_server import FakeMeter

# -- identity on the wire ----------------------------------------------------------------


def test_unparsable_identity_is_invalid_identity() -> None:
    with pytest.raises(InvalidIdentity):
        check_identity(b"garbage")
    ident = generate_identity()
    with pytest.raises(InvalidIdentity):
        check_identity(ident.cert_pem, b"not a key")


def test_a_self_signature_that_does_not_verify_is_reported() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    good = x509.load_pem_x509_certificate(generate_identity().cert_pem.encode())
    other_key = ec.generate_private_key(ec.SECP256R1())
    forged = (
        x509.CertificateBuilder()
        .subject_name(good.subject)
        .issuer_name(good.issuer)
        .public_key(good.public_key())
        .serial_number(good.serial_number)
        .not_valid_before(good.not_valid_before_utc)
        .not_valid_after(good.not_valid_after_utc)
        .sign(other_key, hashes.SHA256())  # signed by a different key
    )
    check = check_identity(forged.public_bytes(serialization.Encoding.PEM))
    assert "certificate's self-signature does not verify" in check.problems


@pytest.mark.parametrize("bad", ["ABC", " F289A6F0493D756E057A2B5B59538112697B5A15", "Z" * 40])
def test_sfdi_needs_a_real_lfdi(bad: str) -> None:
    with pytest.raises(ValueError):
        sfdi_from_lfdi(bad)


def _unused() -> None:  # keep imports used by type checkers
    _ = (ReadingType, T)


# -- identity in memory ------------------------------------------------------------------


def test_an_identity_round_trips_through_a_config_entry(pki: Pki) -> None:
    ident = registered(pki)
    stored = json.loads(json.dumps(ident.to_dict()))
    assert set(stored) == {"cert_pem", "key_pem"}
    again = Identity.from_dict(stored)
    assert (again.lfdi, again.sfdi, again.not_after) == (ident.lfdi, ident.sfdi, ident.not_after)
    assert again.problems == () and not again.expired() and again.days_remaining() > 1000


def test_the_private_key_never_appears_in_a_repr() -> None:
    ident = generate_identity()
    assert "PRIVATE KEY" not in repr(ident) and "PRIVATE KEY" not in str(ident)


def test_a_mismatched_pair_is_refused_even_when_lenient() -> None:
    a, b = generate_identity(), generate_identity()
    for strict in (True, False):
        with pytest.raises(InvalidIdentity) as exc:
            load_identity(a.cert_pem, b.key_pem, strict=strict)
        assert "private key does not match the certificate" in exc.value.problems


def test_an_expired_identity_is_refused_for_import_but_reloads(pki: Pki) -> None:
    later = datetime.now(UTC) + timedelta(days=4000)
    with pytest.raises(InvalidIdentity) as exc:
        load_identity(pki.client_cert.read_text(), pki.client_key.read_text(), now=later)
    assert any("expired" in p for p in exc.value.problems)
    ident = load_identity(pki.client_cert.read_text(), pki.client_key.read_text(), strict=False, now=later)
    assert any("expired" in p for p in ident.problems) and ident.expired(later)


@pytest.mark.parametrize(
    "data",
    [{}, {"cert_pem": "x"}, None, {"cert_pem": "garbage", "key_pem": "garbage"}],
)
def test_a_broken_stored_identity_is_invalid_identity(data: Any) -> None:
    with pytest.raises(InvalidIdentity):
        Identity.from_dict(data)


def test_non_ascii_pem_text_is_invalid_and_junk_bytes_are_not_kept(pki: Pki) -> None:
    with pytest.raises(InvalidIdentity):
        load_identity(pki.client_cert.read_text() + "é", pki.client_key.read_text())
    ident = load_identity(pki.client_cert.read_bytes() + "é".encode(), pki.client_key.read_bytes())
    assert ident.cert_pem == pki.client_cert.read_text()  # stored as a canonical re-encoding


def test_tls_context_from_pem_leaves_no_files(
    pki: Pki, fake_meter: FakeMeter, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    ident = registered(pki)
    ctx = build_ssl_context_from_pem(ident.cert_pem, ident.key_pem)
    assert list(tmp_path.iterdir()) == []
    meter = Meter("127.0.0.1", ctx, fake_meter.port, timeouts=FAST, min_connect_interval=0)
    assert asyncio.run(meter._transport.get("/dcap"))


async def test_meter_create_from_an_identity(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = await Meter.create(
        "127.0.0.1", registered(pki), fake_meter.port, timeouts=FAST, min_connect_interval=0, request_spacing=0
    )
    profile = await meter.discover()
    assert profile.certificate_lfdi == fake_meter.lfdi == meter.expected_lfdi


# -- a refusal proves nothing unless the peer showed it holds the key --------------------


def _messages(buf: bytes) -> list[tuple[int, bytes]]:
    out = []
    while len(buf) >= 4:
        n = int.from_bytes(buf[1:4], "big")
        if len(buf) < 4 + n:
            break
        out.append((buf[0], buf[: 4 + n]))
        buf = buf[4 + n :]
    return out


@pytest_asyncio.fixture
async def replayer(fake_meter: FakeMeter) -> AsyncIterator[int]:
    """A device without the meter's key: it relays the meter's ServerHello and
    Certificate (both public), then refuses us before anything is signed."""

    async def record(r: asyncio.StreamReader) -> tuple[int, bytes]:
        hdr = await r.readexactly(5)
        return hdr[0], await r.readexactly(int.from_bytes(hdr[3:5], "big"))

    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        mr, mw = await asyncio.open_connection("127.0.0.1", fake_meter.port)
        t, body = await record(cr)  # ClientHello, passed on to the real meter
        mw.write(bytes([t, 3, 3]) + len(body).to_bytes(2, "big") + body)
        flight = b""
        while not any(k == 14 for k, _ in _messages(flight)):
            flight += (await record(mr))[1]
        keep = b"".join(m for k, m in _messages(flight) if k in (2, 11))
        cw.write(b"\x16\x03\x03" + len(keep).to_bytes(2, "big") + keep)
        cw.write(b"\x15\x03\x03\x00\x02\x02\x2a")  # fatal bad_certificate
        await cw.drain()
        cw.close()
        mw.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()


async def test_a_replayed_certificate_is_not_the_meter(pki: Pki, fake_meter: FakeMeter, replayer: int) -> None:
    pinned = make_meter(pki, replayer, expected_lfdi=fake_meter.lfdi)
    with pytest.raises(MeterIdentityMismatch):  # not MeterAuthError (which means: re-register)
        await pinned._transport.get("/dcap")
    assert pinned._transport.peer is None
    with pytest.raises(MeterAuthError):  # probe_tls cannot say who refused
        await make_meter(pki, replayer).probe_tls()


async def test_a_real_refusal_still_identifies_the_meter(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    meter._transport._ctx = build_ssl_context(str(pki.other_client_cert), str(pki.other_client_key))
    info = await meter.probe_tls()
    assert not info.client_accepted and info.lfdi == fake_meter.lfdi


# -- identities --------------------------------------------------------------------------


def test_a_key_pasted_into_the_certificate_field_is_refused(pki: Pki) -> None:
    combined = pki.client_cert.read_text() + pki.client_key.read_text()
    for strict in (True, False):
        with pytest.raises(InvalidIdentity):
            load_identity(combined, pki.client_key.read_text(), strict=strict)


def test_no_pem_ever_appears_in_an_identity_repr(pki: Pki) -> None:
    ident = load_identity(pki.client_cert.read_text(), pki.client_key.read_text())
    assert "BEGIN" not in repr(ident) and ident.lfdi in repr(ident)


@pytest.mark.parametrize("data", [{"key_pem": None}, {"cert_pem": 1, "key_pem": 2}, [1]])
def test_odd_stored_identities_are_invalid_identity(pki: Pki, data: object) -> None:
    if isinstance(data, dict) and "cert_pem" not in data:
        data = {"cert_pem": pki.client_cert.read_text(), **data}  # a real certificate, no key
    with pytest.raises(InvalidIdentity):
        Identity.from_dict(data)  # type: ignore[arg-type]


# -- an encrypted key never prompts ------------------------------------------------------


def _encrypted_key(pki: Pki) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pki.client_key.read_bytes(), None)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    ).decode()


def test_an_encrypted_key_is_invalid_identity_not_a_prompt(pki: Pki, tmp_path: Path) -> None:
    enc = _encrypted_key(pki)
    with pytest.raises(InvalidIdentity):
        build_ssl_context_from_pem(pki.client_cert.read_text(), enc)
    (tmp_path / "k.pem").write_text(enc)
    with pytest.raises(InvalidIdentity):
        build_ssl_context(str(pki.client_cert), str(tmp_path / "k.pem"))
    with pytest.raises(InvalidIdentity):
        build_ssl_context_from_pem(pki.client_cert.read_text(), "é")


# -- LFDI formatting and manufacturers ---------------------------------------------------


def test_lfdi_as_utility_portals_accept_it() -> None:
    """Xcel Energy takes groups of five, or no dashes at all."""
    expected = "431ED-86C1F-202CD-D3FEB-3EF8D-CB9F4-457F0-EC47D"
    assert format_lfdi("431ED86C1F202CDD3FEB3EF8DCB9F4457F0EC47D") == expected
    assert format_lfdi("431e-d86c-1f20-2cdd-3feb-3ef8-dcb9-f445-7f0e-c47d") == expected
    assert format_lfdi(" 431ED 86C1F 202CD D3FEB 3EF8D CB9F4 457F0 EC47D\n") == expected
    for bad in ("ABCDEF", "431ED86C1F202CDD3FEB3EF8DCB9F4457F0EC47D00", "431ED86C1F202CDD3FEB3EF8DCB9F4457F0EC47G"):
        with pytest.raises(ValueError):
            format_lfdi(bad)


def test_manufacturers() -> None:
    assert manufacturer_name(1233) == "Itron"
    assert manufacturer_name(4) is None and manufacturer_name(None) is None
