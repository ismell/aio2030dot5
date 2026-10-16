"""Meter: partial reads, one batch per call, snapshot replay, and its fixed address."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aio2030dot5 import (
    TIME_ERROR_KEY,
    Meter,
    MeterConnectionError,
    MeterError,
    MeterIdentityMismatch,
    MeterNotFound,
    MeterProtocolError,
    MeterSnapshot,
    Statistic,
)

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree


class BrokenClock(FixtureTree):
    """The fixture tree, with the Time resource gone or empty."""

    def __init__(self, path: str, status: int, body: str = "") -> None:
        super().__init__()
        self.exact[path] = (status, body)


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        pytest.param(404, "", MeterNotFound, id="gone"),
        pytest.param(200, '<Time xmlns="urn:ieee:std:2030.5:ns"/>', MeterProtocolError, id="no-currentTime"),
    ],
)
async def test_a_failed_clock_read_is_partial_too(
    pki: Pki, fake_meter: FakeMeter, status: int, body: str, kind: type[MeterError]
) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    assert profile.time_href
    readable = [c for c in profile.channels if c.statistic != Statistic.INTERVAL]
    tree = BrokenClock(profile.time_href, status, body)
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=tree) as fm:
        meter = make_meter(pki, fm.port)
        snapshot = await meter.read(profile, readable, include_time=True, partial=True)
        assert isinstance(snapshot.errors[TIME_ERROR_KEY], kind)
        assert snapshot.meter_time is None and snapshot.values  # the channels survive
        with pytest.raises(kind):
            await meter.read(profile, readable, include_time=True)


async def test_the_clock_is_read_first_and_dates_the_snapshot(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    before = datetime.now(UTC)
    snapshot = await meter.read(profile, profile.channels[:1], include_time=True)
    assert snapshot.meter_time is not None and before <= snapshot.fetched_at <= datetime.now(UTC)
    assert fake_meter.log.requests[-2].split("?")[0] == profile.time_href  # before the channel


@pytest.mark.parametrize("call", ["history", "since"])
async def test_reading_interval_history_is_one_batch(pki: Pki, fake_meter: FakeMeter, call: str) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    channel = profile.channel("energy_interval_delivered")
    assert channel is not None
    before = fake_meter.log.connections
    if call == "history":
        values = await meter.read_interval_history(channel)
    else:
        values = await meter.read_intervals_since(channel, datetime(2000, 1, 1, tzinfo=UTC))
    assert values
    assert fake_meter.log.connections - before == 1


def test_a_replayed_snapshot_keeps_rediscover_errors() -> None:
    snapshot = MeterSnapshot(
        fetched_at=datetime(2026, 1, 1, tzinfo=UTC),
        errors={"a": MeterNotFound("/upt/1/mr/3/r", 410), "b": MeterProtocolError("odd")},
    )
    replayed = MeterSnapshot.from_dict(snapshot.to_dict())
    gone = replayed.errors["a"]
    assert isinstance(gone, MeterNotFound) and (gone.path, gone.status) == ("/upt/1/mr/3/r", 410)
    assert type(replayed.errors["b"]) is MeterProtocolError


def test_a_moved_meter_is_not_a_connection_problem() -> None:
    """Back-off handlers for MeterConnectionError must not swallow it: relocate instead."""
    assert not issubclass(MeterIdentityMismatch, MeterConnectionError)
    assert issubclass(MeterIdentityMismatch, MeterError)


async def test_the_address_is_fixed(pki: Pki) -> None:
    meter = await Meter.from_files(
        "192.0.2.19", str(pki.client_cert), str(pki.client_key), 9999, dcap_path="/x", min_connect_interval=0.0
    )
    assert (meter.host, meter.port, meter.dcap_path) == ("192.0.2.19", 9999, "/x")
    with pytest.raises(AttributeError):
        meter.host = "elsewhere"  # type: ignore[misc]
