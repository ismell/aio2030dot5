"""The meter is identified by its certificate's LFDI, not by its address."""

from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from aio2030dot5 import (
    MeterAuthError,
    MeterIdentityMismatch,
    MeterProfile,
    PeerCertificate,
    ProfileError,
    build_ssl_context,
)
from aio2030dot5.identity import lfdi_from_pem
from aio2030dot5.transport import _CertificateTap

from .conftest import Pki, _server_identity, make_meter
from .meter_server import FakeMeter


def server_lfdi(pki: Pki) -> str:
    return lfdi_from_pem(pki.server_cert.read_bytes())


def unregistered(pki: Pki, port: int, **kwargs: object):  # type: ignore[no-untyped-def]
    meter = make_meter(pki, port, **kwargs)
    meter.transport._ctx = build_ssl_context(str(pki.other_client_cert), str(pki.other_client_key))
    return meter


async def test_discover_pins_the_meter_it_found(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    assert profile.certificate_lfdi == meter.expected_lfdi == server_lfdi(pki)
    cached = MeterProfile.from_dict(json.loads(json.dumps(profile.to_dict())))
    assert cached.certificate_lfdi == server_lfdi(pki)


async def test_a_cached_profile_pins_a_fresh_meter_object(pki: Pki, fake_meter: FakeMeter) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    fresh = make_meter(pki, fake_meter.port)
    assert fresh.expected_lfdi is None
    await fresh.read(profile, profile.channels[:1])
    assert fresh.expected_lfdi == server_lfdi(pki)


async def test_a_profile_from_another_meter_is_refused(pki: Pki, fake_meter: FakeMeter) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    other = make_meter(pki, fake_meter.port, expected_lfdi="A" * 40)
    with pytest.raises(ProfileError):
        await other.read(profile, profile.channels[:1])
    assert fake_meter.log.connections == 1  # refused before connecting


async def test_another_device_at_the_address_gets_no_request(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, expected_lfdi="A" * 40)
    with pytest.raises(MeterIdentityMismatch) as exc:
        await meter.transport.get("/dcap")
    assert (exc.value.expected, exc.value.actual) == ("A" * 40, server_lfdi(pki))
    assert fake_meter.log.requests == []


async def test_a_meter_replaced_at_the_same_address_is_detected(pki: Pki, tmp_path: Path) -> None:
    other_cert, other_key = _server_identity(tmp_path)
    with (
        FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as a,
        FakeMeter(other_cert, other_key, pki.client_cert) as b,
    ):
        meter = make_meter(pki, a.port)
        profile = await meter.discover()
        # The meter's address now answers with a different device (a DHCP reshuffle).
        meter.transport.port = b.port
        with pytest.raises(MeterIdentityMismatch):
            await meter.read(profile, profile.channels[:1])
        assert b.log.requests == []


async def test_resumed_connections_are_checked_too(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    await meter.read(profile, profile.channels[:1])
    assert fake_meter.log.resumed >= 1
    assert meter.transport.peer is not None and meter.transport.peer.lfdi == server_lfdi(pki)
    meter.transport.expected_lfdi = "A" * 40
    with pytest.raises(MeterIdentityMismatch):
        await meter.transport.get("/dcap")


async def test_probe_tls_with_a_registered_certificate(pki: Pki, fake_meter: FakeMeter) -> None:
    info = await make_meter(pki, fake_meter.port).probe_tls()
    assert info.client_accepted and info.auth_reason is None
    assert info.certificate.lfdi == server_lfdi(pki)
    assert fake_meter.log.requests == []


async def test_probe_tls_identifies_a_meter_that_refuses_us(pki: Pki, fake_meter: FakeMeter) -> None:
    # The setup-flow case: our certificate is not registered yet, but the
    # meter's certificate arrived before its refusal.
    info = await unregistered(pki, fake_meter.port).probe_tls()
    assert not info.client_accepted and info.auth_reason == "certificate_rejected"
    assert info.certificate.lfdi == server_lfdi(pki)
    assert info.certificate.sfdi.isdigit()


async def test_probe_tls_ignores_the_pin(pki: Pki, fake_meter: FakeMeter) -> None:
    info = await make_meter(pki, fake_meter.port, expected_lfdi="A" * 40).probe_tls()
    assert info.certificate.lfdi == server_lfdi(pki)


async def test_refused_by_our_meter_is_an_auth_error(pki: Pki, fake_meter: FakeMeter) -> None:
    with pytest.raises(MeterAuthError):
        await unregistered(pki, fake_meter.port, expected_lfdi=server_lfdi(pki)).transport.get("/dcap")


async def test_refused_by_another_device_is_a_mismatch_not_an_auth_error(pki: Pki, fake_meter: FakeMeter) -> None:
    with pytest.raises(MeterIdentityMismatch):
        await unregistered(pki, fake_meter.port, expected_lfdi="A" * 40).transport.get("/dcap")


def test_expected_lfdi_must_be_an_lfdi(pki: Pki) -> None:
    with pytest.raises(ValueError):
        make_meter(pki, 1, expected_lfdi="not-an-lfdi")
    assert make_meter(pki, 1, expected_lfdi="a" * 40).expected_lfdi == "A" * 40


# -- the handshake tap ------------------------------------------------------------


def _record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type, 3, 3]) + len(body).to_bytes(2, "big") + body


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def _certificate_message(*certs: bytes) -> bytes:
    entries = b"".join(len(c).to_bytes(3, "big") + c for c in certs)
    return _handshake(11, len(entries).to_bytes(3, "big") + entries)


def _flight(pki: Pki) -> tuple[bytes, tuple[bytes, ...]]:
    leaf = ssl.PEM_cert_to_DER_cert(pki.server_cert.read_text())
    chain = (leaf, b"intermediate", b"root")
    msgs = _handshake(2, b"\x03\x03" + bytes(34)) + _certificate_message(*chain) + _handshake(14, b"")
    # The certificate message straddles two records, as it does on the wire.
    return _record(22, msgs[:700]) + _record(22, msgs[700:]), chain


def test_tap_reads_a_chain_split_across_records_and_reads(pki: Pki) -> None:
    stream, chain = _flight(pki)
    tap = _CertificateTap()
    for i in range(len(stream)):  # one byte per socket read
        tap.feed(stream[i : i + 1])
    assert tap.chain == chain and tap.done
    peer = PeerCertificate.from_chain(chain)
    assert peer.lfdi == server_lfdi(pki)


def test_tap_stops_at_server_hello_done_and_at_encrypted_records() -> None:
    tap = _CertificateTap()
    tap.feed(_record(22, _handshake(14, b"")) + _record(22, _certificate_message(b"late")))
    assert tap.done and tap.chain is None
    tap = _CertificateTap()
    tap.feed(_record(20, b"\x01") + _record(22, _certificate_message(b"encrypted")))
    assert tap.done and tap.chain is None


@pytest.mark.parametrize(
    "stream",
    [
        bytes(range(256)) * 300,  # junk past the size limit
        _record(22, _handshake(11, b"\x00\x00\x09\x00\x00\x05abc")),  # entry longer than the list
        _record(22, _handshake(11, b"\x00\x00\x00")),  # empty list
        _record(22, _handshake(11, b"\x00\x00\x03\x00\x00\x00")),  # zero-length certificate
    ],
)
def test_tap_never_raises_and_never_invents_a_chain(stream: bytes) -> None:
    tap = _CertificateTap()
    tap.feed(stream)
    assert tap.chain is None
