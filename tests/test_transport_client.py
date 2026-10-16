"""The transport and the Meter against the fake meter: discovery, reads, keep-alive and session resumption."""

from __future__ import annotations

import asyncio
import itertools
import json
import socket

import pytest

from aio2030dot5 import (
    Direction,
    MeterAuthError,
    MeterConnectionError,
    MeterNotFound,
    MeterProfile,
    MeterTimeout,
    Quantity,
    Statistic,
)
from aio2030dot5 import transport as transport_mod

from .conftest import FAST, Pki, make_meter
from .meter_server import FakeMeter


async def test_discover_classifies_every_reading(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()

    assert profile.software_version == "3.2.50" and profile.poll_rate == 900
    keys = {c.key for c in profile.channels}
    assert len(profile.channels) == 22
    assert {
        "power",
        "energy_summation_delivered",
        "energy_summation_received",
        "energy_tou_summation_delivered",
        "energy_tou_summation_received",
        "apparent_energy_summation_delivered",
        "reactive_energy_summation_received",
        "energy_interval_delivered",
        "energy_interval_received",
        "energy_interval_net",
        "power_maximum_delivered",
        "power_maximum_received",
        "power_factor",
        "power_factor_phase_a",
    } <= keys
    delivered = profile.find(Quantity.ENERGY, Statistic.SUMMATION, Direction.DELIVERED)
    assert delivered is not None and delivered.reading_href == "/upt/1/mr/3/r"
    tou = profile.find(Quantity.ENERGY, Statistic.TOU_SUMMATION, Direction.DELIVERED)
    assert tou is not None and tou.tou_reading_list_href == "/upt/1/mr/9/rs/1/r"
    pf = profile.find(Quantity.POWER_FACTOR, Statistic.INSTANTANEOUS)
    assert pf is not None and pf.phase == 224  # whole-meter preferred over phases

    # The whole walk is one connection.
    assert fake_meter.log.connections == 1
    assert meter.stats.connections == 1 and meter.stats.requests == len(fake_meter.log.requests)

    # Profiles survive a JSON round trip.
    again = MeterProfile.from_dict(json.loads(json.dumps(profile.to_dict())))
    assert again == profile


async def test_read_batch_and_session_resumption(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    snap = await meter.read(profile, profile.channels, include_time=True)

    assert snap.values["power"].value == 2439 and snap.values["power"].unit == "W"
    assert snap.values["energy_summation_delivered"].value == 42239863
    assert snap.values["power_factor"].value == pytest.approx(0.918)
    assert snap.values["power_factor_phase_a"].value is None
    tiers = snap.tou["energy_tou_summation_delivered"]
    assert tiers[0].value == pytest.approx(sum(tiers[t].value or 0 for t in (1, 2, 3)), abs=5)
    assert "energy_interval_delivered" not in snap.values  # intervals have their own call
    assert snap.clock_skew is not None

    # Second batch: a second connection, and it resumed the TLS session.
    assert fake_meter.log.connections == 2
    assert fake_meter.log.resumed == 1
    assert meter.stats.resumed_connections == 1


async def test_latest_intervals_only_complete_slots(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    values = await meter.read_latest_intervals(ch)
    assert len(values) == 18 and values[0].value == 986
    assert all(b.start - a.start == b.end - b.start for a, b in itertools.pairwise(values))
    # The newest-set lookup must not page through all 60 sets.
    assert sum("/upt/1/mr/12/rs?" in r for r in fake_meter.log.requests) == 1


async def test_lock_never_allows_two_connections(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    await asyncio.gather(*(meter.read(profile, profile.channels[:3]) for _ in range(5)))
    assert fake_meter.log.max_concurrent == 1
    assert fake_meter.log.connections == 6


async def test_min_connect_interval_spaces_connections(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, min_connect_interval=0.3)
    profile = await meter.discover()
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await meter.read(profile, profile.channels[:1])
    await meter.read(profile, profile.channels[:1])
    assert loop.time() - t0 >= 0.55


async def test_reconnects_when_meter_drops_idle_connection(pki: Pki) -> None:
    # The meter closes a kept-alive connection after 2 requests here; the batch
    # must transparently reconnect (resuming the session) and finish.
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, max_requests_per_connection=2) as fm:
        meter = make_meter(pki, fm.port)
        profile = await meter.discover()
        assert len(profile.channels) == 22
        assert fm.log.connections > 1 and fm.log.max_concurrent == 1
        assert fm.log.resumed == fm.log.connections - 1


async def test_unclean_closes_are_survived_by_reconnecting(pki: Pki) -> None:
    """The fake meter drops every second request's connection without close_notify.

    Whether the server then refuses to resume the TLS session depends on when
    CPython frees its SSL object (usually it does, occasionally not), so only the
    client's side is asserted: the walk completes, reconnecting each time.
    """
    with FakeMeter(
        pki.server_cert, pki.server_key, pki.client_cert, max_requests_per_connection=2, clean_close=False
    ) as fm:
        meter = make_meter(pki, fm.port)
        profile = await meter.discover()
        assert len(profile.channels) == 22
        assert meter.stats.reconnects_mid_batch == fm.log.connections - 1 > 0


async def test_server_without_keep_alive(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, honour_keep_alive=False) as fm:
        meter = make_meter(pki, fm.port)
        profile = await meter.discover()
        assert len(profile.channels) == 22
        assert fm.log.connections == len(fm.log.requests)


async def test_not_found_is_distinct(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    with pytest.raises(MeterNotFound) as exc:
        await meter._transport.get("/tp")
    assert exc.value.status == 404
    assert meter.stats.failures == 1


async def test_unregistered_certificate_is_auth_error(pki: Pki) -> None:
    # The meter trusts a different client certificate than the one we present.
    with FakeMeter(pki.server_cert, pki.server_key, pki.other_client_cert) as fm:
        meter = make_meter(pki, fm.port)
        with pytest.raises((MeterAuthError, MeterConnectionError)) as exc:
            await meter.discover()
        assert not isinstance(exc.value, MeterTimeout)


async def test_connection_refused() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    from aio2030dot5 import Meter

    meter = Meter("127.0.0.1", transport_mod.ssl.create_default_context(), port, timeouts=FAST)
    with pytest.raises(MeterConnectionError):
        await meter._transport.get("/dcap")


async def test_handshake_timeout(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, blackhole=True) as fm:
        meter = make_meter(pki, fm.port, timeouts=transport_mod.Timeouts(1.0, 0.5, 0.5))
        with pytest.raises(MeterTimeout):
            await meter._transport.get("/dcap")


async def test_bad_signature_is_retried_once(pki: Pki, fake_meter: FakeMeter, monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = transport_mod._TlsConnection.open
    calls = {"n": 0}

    async def flaky_open(*args: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise transport_mod._BadSignature("[SSL: BAD_SIGNATURE] bad signature")
        return await real_open(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(transport_mod._TlsConnection, "open", flaky_open)
    meter = make_meter(pki, fake_meter.port)
    assert b"DeviceCapability" in await meter._transport.get("/dcap")
    assert meter.stats.bad_signature_retries == 1 and calls["n"] == 2


async def test_bad_signature_twice_fails(pki: Pki, fake_meter: FakeMeter, monkeypatch: pytest.MonkeyPatch) -> None:
    async def always_bad(*args: object, **kwargs: object) -> object:
        raise transport_mod._BadSignature("[SSL: BAD_SIGNATURE] bad signature")

    monkeypatch.setattr(transport_mod._TlsConnection, "open", always_bad)
    meter = make_meter(pki, fake_meter.port)
    with pytest.raises(MeterConnectionError):
        await meter._transport.get("/dcap")
    assert meter.stats.bad_signature_retries == 1
