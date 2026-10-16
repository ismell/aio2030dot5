"""Regressions from the round-3 review (2026-10-06)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

from aio2030dot5 import (
    REDACT_KEYS,
    Direction,
    Identity,
    IntervalValue,
    InvalidIdentity,
    MeterAuthError,
    MeterIdentityMismatch,
    MeterProfile,
    ProfileError,
    Quantity,
    Statistic,
    Timeouts,
    build_ssl_context,
    build_ssl_context_from_pem,
    hourly_energy,
    load_identity,
)

from .conftest import Pki, make_meter
from .meter_server import FakeMeter

# -- M2: a refusal proves nothing unless the peer showed it holds the key -----------


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


# -- M1, L3: identities ---------------------------------------------------------------


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


# -- L1: an encrypted key never prompts ------------------------------------------------


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


# -- M3: one connection, one task ---------------------------------------------------


async def test_batch_connect_from_another_task_never_connects(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    async with meter._transport.batch() as b:
        results = await asyncio.gather(b.connect(), b.get("/dcap"), return_exceptions=True)
        stray = asyncio.create_task(b.connect())
        await asyncio.sleep(0)
    assert all(isinstance(r, RuntimeError) for r in results)
    with pytest.raises(RuntimeError):
        await stray
    await asyncio.sleep(0.2)
    assert fake_meter.log.connections == 0


# -- M4: pacing does not spend the deadline -------------------------------------------


async def test_connection_pacing_does_not_count_against_the_deadline(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, min_connect_interval=1.0, timeouts=Timeouts(2, 2, 2, batch=0.8))
    await meter._transport.get("/dcap")
    await meter._transport.get("/tm")  # waits ~1 s for pacing, within a 0.8 s deadline
    profile = await meter.discover()
    ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    meter._transport.timeouts = Timeouts(2, 2, 2, batch=3.0)
    await meter.read_intervals_since(ch, datetime.now(UTC) - timedelta(days=1))  # two batches, paced


# -- L2: hourly energy refuses data it cannot place ----------------------------------


def _iv(start: datetime, minutes: int, unit: str = "Wh") -> IntervalValue:
    return IntervalValue(start, start + timedelta(minutes=minutes), 1.0, unit)


T0 = datetime(2026, 10, 6, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    "values",
    [
        [_iv(T0, 120)],  # longer than an hour
        [_iv(T0 + timedelta(minutes=5), 60)],  # not aligned: crosses the hour
        [_iv(T0, 60), _iv(T0, 15)],  # overlapping
        [_iv(T0, 15), _iv(T0 + timedelta(hours=1), 15, "VAh")],  # units differ across hours
    ],
)
def test_hourly_energy_refuses_what_it_cannot_place(values: list[IntervalValue]) -> None:
    with pytest.raises(ValueError):
        hourly_energy(values)


# -- L4, L5 ----------------------------------------------------------------------------


async def test_a_malformed_pin_in_a_cached_profile_is_a_profile_error(pki: Pki, fake_meter: FakeMeter) -> None:
    d = (await make_meter(pki, fake_meter.port).discover()).to_dict()
    d["certificate_lfdi"] = "not-an-lfdi"
    with pytest.raises(ProfileError):
        MeterProfile.from_dict(d)


def test_mdns_instance_names_are_redacted() -> None:
    assert "instance" in REDACT_KEYS
