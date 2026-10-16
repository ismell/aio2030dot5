"""Regressions from the second (post-fix) review, 2026-10-06."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from datetime import UTC, datetime

import pytest

from aio2030dot5 import (
    Direction,
    InvalidIdentity,
    MeterConnectionError,
    MeterHttpError,
    MeterProfile,
    MeterProtocolError,
    ProfileError,
    Quantity,
    Statistic,
)
from aio2030dot5 import transport as T
from aio2030dot5.identity import check_identity, generate_identity, sfdi_from_lfdi
from aio2030dot5.models import MeterReadingInfo, Reading, ReadingSetInfo, ReadingType, interval_values, parse_xml
from aio2030dot5.profile import assign_keys, classify, resolve_href

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree
from .scripted_server import Server, read_request, rst, server_ctx
from .test_robustness import SlowTree
from .test_round2 import NS, PINNED_KEYS_3_2_50, rt

# -- transport ------------------------------------------------------------------


async def test_request_in_flight_when_its_batch_ends_cannot_connect(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        meter = make_meter(pki, fm.port)
        async with meter._transport.batch() as b:
            await b.get("/dcap")
            # A second request on the now-reused connection, left running past
            # the batch (e.g. by gather()). The batch's exit kills its
            # connection; the reused-connection retry must not reconnect.
            stray = asyncio.create_task(b.get("/tm?slow=1"))
            await asyncio.sleep(0.1)
        with pytest.raises((RuntimeError, MeterConnectionError)):
            await stray
        await asyncio.sleep(0.6)
        assert fm.log.connections == 1


async def test_a_failed_handshake_still_spaces_the_next_connect(pki: Pki) -> None:
    accepts: list[float] = []

    def handler(raw):  # type: ignore[no-untyped-def]
        accepts.append(time.monotonic())
        raw.recv(4096)
        time.sleep(0.5)  # a slow, clamping meter...
        rst(raw)  # ...that then resets

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port, min_connect_interval=0.4)
        for _ in range(2):
            with pytest.raises(MeterConnectionError):
                await meter._transport.get("/dcap")
    assert accepts[1] - accepts[0] >= 0.85  # 0.5 s handshake + 0.4 s spacing from its end


async def test_session_survives_a_network_failure(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    await meter._transport.get("/dcap")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    meter._transport.port = dead  # the meter "drops off the network"
    with pytest.raises(MeterConnectionError):
        await meter._transport.get("/dcap")
    meter._transport.port = fake_meter.port
    await meter._transport.get("/tm")
    assert fake_meter.log.resumed == 1  # the first connect after the outage resumed


async def test_nested_batch_on_the_same_meter_raises_instead_of_hanging(pki: Pki, fake_meter: FakeMeter) -> None:
    a, b = make_meter(pki, fake_meter.port), make_meter(pki, fake_meter.port)
    async with a._transport.batch():
        with pytest.raises(RuntimeError):
            async with asyncio.timeout(2):
                await b._transport.get("/dcap")


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\nok",
    ],
)
async def test_odd_framing_is_a_protocol_error(pki: Pki, response: bytes) -> None:
    sctx = server_ctx(pki)

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(response)
        time.sleep(0.5)

    with Server(handler) as srv:
        with pytest.raises(MeterProtocolError) as exc:
            await make_meter(pki, srv.port)._transport.get("/x")
    # A framing error, not an HTTP status surfacing as one.
    assert not isinstance(exc.value, MeterHttpError)


async def test_since_must_be_timezone_aware(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    ch = (await meter.discover()).find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    with pytest.raises(ValueError):
        await meter.read_intervals_since(ch, datetime(2026, 10, 6))


# -- classification and keys ------------------------------------------------------


def test_net_does_not_override_an_explicit_direction() -> None:
    assert classify(rt(uom=72, accumulationBehaviour=9, flowDirection=19), "Net Received")[2] == Direction.RECEIVED
    assert classify(rt(uom=72, accumulationBehaviour=9, flowDirection=1), "Net Metering Delivered")[2] == (
        Direction.DELIVERED
    )


def test_max_and_min_demand_from_the_description() -> None:
    avg = {"uom": 38, "kind": 8, "accumulationBehaviour": 12, "dataQualifier": 2}  # v1/v2 agents
    assert classify(rt(**avg), "Max Demand Delivered")[1] == Statistic.MAXIMUM
    assert classify(rt(**avg), "Instantaneous Demand")[1] == Statistic.INSTANTANEOUS


def test_instantaneous_total_keeps_its_direction_in_the_key() -> None:
    mr = MeterReadingInfo("/upt/1/mr/1", "A", None, None, None, None)
    t = rt(uom=38, kind=8, accumulationBehaviour=12, flowDirection=20)
    q, s, d = classify(t)
    assert assign_keys([(mr, q, s, d, 0)]) == [("power_total", False)]


def test_identical_channels_are_flagged_ambiguous() -> None:
    a = MeterReadingInfo("/upt/1/mr/1", "BBBB01", None, None, None, None)
    b = MeterReadingInfo("/upt/1/mr/2", "BBBB02", None, None, None, None)
    keys = assign_keys(
        [
            (b, Quantity.POWER, Statistic.INSTANTANEOUS, Direction.NONE, 0),
            (a, Quantity.POWER, Statistic.INSTANTANEOUS, Direction.NONE, 0),
        ]
    )
    assert keys == [("power_2", True), ("power", True)]


class TieredVAhTree(FixtureTree):
    """VAh Delivered claims ToU tiers in its ReadingType but its readings carry none."""

    def respond(self, target: str) -> tuple[int, str]:
        status, body = super().respond(target)
        if target == "/rt/5":
            body = body.replace("<numberOfTouTiers>0</numberOfTouTiers>", "<numberOfTouTiers>8</numberOfTouTiers>")
        return status, body


async def test_tou_is_confirmed_by_the_data(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=TieredVAhTree()) as fm:
        profile = await make_meter(pki, fm.port).discover()
    vah = next(c for c in profile.channels if c.meter_reading_href == "/upt/1/mr/5")
    assert vah.statistic == Statistic.SUMMATION and vah.key == "apparent_energy_summation_delivered"


async def test_pinned_keys_survive_the_cache_and_classification_is_not_recomputed(
    pki: Pki, fake_meter: FakeMeter, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    cached = json.loads(json.dumps(profile.to_dict()))
    # Even if classify() changed after an upgrade, a cached channel keeps its meaning.
    monkeypatch.setattr(
        "aio2030dot5.profile.classify", lambda *a, **k: (Quantity.OTHER, Statistic.OTHER, Direction.NONE)
    )
    again = MeterProfile.from_dict(cached)
    assert [c.key for c in again.channels] == PINNED_KEYS_3_2_50
    assert again.channel("energy_summation_delivered").statistic == Statistic.SUMMATION  # type: ignore[union-attr]
    cached["key_scheme"] = 0
    with pytest.raises(ProfileError):
        MeterProfile.from_dict(cached)


# -- links, numbers, intervals -------------------------------------------------------


def test_ipv6_meter_links() -> None:
    assert resolve_href("/", "/dcap", "fd00::5", 8081) == "/dcap"
    assert resolve_href("/dcap", "https://[fd00::5]:8081/upt", "[fd00::5]", 8081) == "/upt"


@pytest.mark.parametrize("href", ["https://192.0.2.19:99999/x", "https://192.0.2.19:abc/x", "http://[::1/x"])
def test_malformed_links_are_protocol_errors(href: str) -> None:
    with pytest.raises(MeterProtocolError):
        resolve_href("/dcap", href, "192.0.2.19", 8081)


@pytest.mark.parametrize(
    "xml",
    [
        f'<Reading xmlns="{NS}"><qualityFlags>0x01</qualityFlags></Reading>',
        f'<Reading xmlns="{NS}"><localID>-1</localID></Reading>',
        f'<Reading xmlns="{NS}"><value>{2**60}</value></Reading>',
    ],
)
def test_out_of_range_numbers_are_protocol_errors(xml: str) -> None:
    with pytest.raises(MeterProtocolError):
        Reading.from_xml(parse_xml(xml))


def test_multiplier_out_of_range_is_a_protocol_error() -> None:
    with pytest.raises(MeterProtocolError):
        rt(powerOfTenMultiplier=400)


def test_interval_slots_outside_their_set_are_dropped() -> None:
    start = datetime(2026, 10, 6, tzinfo=UTC)
    rs = ReadingSetInfo("/s", None, start, 3600, "/s/r", None)  # 4 slots
    readings = [Reading(None, 1, None, None, None, None, slot) for slot in (0, 3, 4, 200)]
    values = interval_values(rs, readings, rt(uom=72, accumulationBehaviour=4, intervalLength=900))
    assert [v.start for v in values] == [start, start.replace(minute=45)]


# -- identity ---------------------------------------------------------------------


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
