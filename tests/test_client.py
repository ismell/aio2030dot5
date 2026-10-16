"""Meter: partial reads, one batch per call, snapshot replay, and its fixed address."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aio2030dot5 import (
    REDACT_KEYS,
    TIME_ERROR_KEY,
    IntervalValue,
    Measurement,
    Meter,
    MeterConnectionError,
    MeterError,
    MeterIdentityMismatch,
    MeterInfo,
    MeterNotFound,
    MeterProfile,
    MeterProtocolError,
    MeterSnapshot,
    ProfileError,
    QualityFlags,
    Statistic,
    TouRegister,
    hourly_energy,
)

from .conftest import FAST, Pki, make_meter
from .helpers import registered
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


# -- probing -----------------------------------------------------------------------------


async def test_probe_says_who_the_meter_is_in_three_requests(pki: Pki, fake_meter: FakeMeter) -> None:
    info = await make_meter(pki, fake_meter.port).probe()
    assert info.lfdi == info.certificate_lfdi == fake_meter.lfdi
    assert info.sfdi == info.certificate_sfdi == fake_meter.sfdi
    assert (info.manufacturer_id, info.software_version) == (1233, "3.2.50")
    assert info.model is None and info.serial_number is None  # empty on this agent
    assert fake_meter.log.requests == ["/dcap", "/sdev", "/sdev/sdi"]
    assert MeterInfo.from_dict(json.loads(json.dumps(info.to_dict()))) == info


async def test_the_dcap_path_from_mdns_is_used(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, dcap_path="/sep2/dcap")
    with pytest.raises(MeterNotFound):
        await meter.probe()
    assert fake_meter.log.requests == ["/sep2/dcap"]


# -- values ------------------------------------------------------------------------------


async def test_tou_registers_are_typed_and_still_dicts(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    snap = await meter.read(profile, profile.channels, include_time=True)
    reg = snap.tou["energy_tou_summation_delivered"]
    assert isinstance(reg, TouRegister)
    assert reg.total is reg[0] and 0 not in reg.tiers and set(reg.tiers) == {1, 2, 3}
    assert dict(reg) == {t: reg[t] for t in reg}
    # A snapshot survives JSON (HA tests replay recorded snapshots).
    again = MeterSnapshot.from_dict(json.loads(json.dumps(snap.to_dict())))
    assert again == snap


def iv(minute: int, value: float | None, quality: QualityFlags | None = None, hour: int = 10) -> IntervalValue:
    start = datetime(2026, 10, 6, hour, minute, tzinfo=UTC)
    return IntervalValue(start, start + timedelta(minutes=15), value, "Wh", 72, quality)


def test_hourly_energy_sums_complete_hours() -> None:
    values = [iv(m, 100.0) for m in (0, 15, 30, 45)] + [iv(0, 50.0, hour=11), iv(15, 50.0, hour=11)]
    hours = hourly_energy([*values, iv(0, 100.0)])  # a duplicate counts once
    assert [(h.start.hour, h.value, h.complete) for h in hours] == [(10, 400.0, True)]
    partial = hourly_energy(values, complete_only=False)
    assert [(h.start.hour, h.value, h.covered) for h in partial] == [(10, 400.0, 3600), (11, 100.0, 1800)]


def test_hourly_energy_leaves_out_questionable_and_flags_estimated() -> None:
    est = QualityFlags.ESTIMATED_LINEAR
    hours = hourly_energy([iv(0, 1.0), iv(15, 1.0, est), iv(30, 1.0), iv(45, 1.0)])
    assert hours[0].estimated
    assert hourly_energy([iv(0, 1.0), iv(15, 9e9, QualityFlags.QUESTIONABLE), iv(30, 1.0), iv(45, 1.0)]) == []
    with pytest.raises(ValueError):
        hourly_energy([iv(0, 1.0), IntervalValue(iv(15, 1).start, iv(15, 1).end, 1.0, "VAh")])


def test_measurement_and_interval_dicts_round_trip() -> None:
    m = Measurement(1.5, "Wh", datetime(2026, 10, 6, tzinfo=UTC), 900, 2, 72, QualityFlags.VALID)
    assert Measurement.from_dict(json.loads(json.dumps(m.to_dict()))) == m
    v = iv(15, 3.0, QualityFlags.ESTIMATED_LINEAR)
    assert IntervalValue.from_dict(json.loads(json.dumps(v.to_dict()))) == v
    with pytest.raises(ValueError):
        Measurement.from_dict({"value": 1, "unit": "W", "start": "2026-10-06T00:00:00"})  # naive


# -- diagnostics -------------------------------------------------------------------------


def _redact(data: Any) -> Any:
    """What Home Assistant's async_redact_data does."""
    if isinstance(data, dict):
        return {k: "**REDACTED**" if k in REDACT_KEYS else _redact(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_redact(v) for v in data]
    return data


async def test_redaction_removes_every_identifier(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    info = await meter.probe()
    ident = registered(pki)
    dump = json.dumps(_redact({"profile": profile.to_dict(), "info": info.to_dict(), "identity": ident.to_dict()}))
    secrets = [fake_meter.lfdi, fake_meter.sfdi, ident.lfdi, "PRIVATE KEY", "CERTIFICATE", "127.0.0.1"]
    secrets += [c.mrid for c in profile.channels if c.mrid]
    assert [s for s in secrets if s in dump] == []


async def test_debug_logging_never_carries_pem(
    pki: Pki, fake_meter: FakeMeter, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="aio2030dot5")
    meter = await Meter.create(
        "127.0.0.1", registered(pki), fake_meter.port, timeouts=FAST, min_connect_interval=0, request_spacing=0
    )
    await meter.discover()
    assert "GET /dcap -> 200" in caplog.text and "connected in" in caplog.text
    assert "BEGIN" not in caplog.text and "PRIVATE" not in caplog.text


def _unused() -> None:
    _ = os


# -- cached pins and redaction -----------------------------------------------------------


async def test_a_malformed_pin_in_a_cached_profile_is_a_profile_error(pki: Pki, fake_meter: FakeMeter) -> None:
    d = (await make_meter(pki, fake_meter.port).discover()).to_dict()
    d["certificate_lfdi"] = "not-an-lfdi"
    with pytest.raises(ProfileError):
        MeterProfile.from_dict(d)


def test_mdns_instance_names_are_redacted() -> None:
    assert "instance" in REDACT_KEYS


# -- device information ------------------------------------------------------------------


class DescribedTree(FixtureTree):
    """A meter that fills in its DeviceInformation (Itron's is empty)."""

    def __init__(self) -> None:
        super().__init__()
        status, body = self.exact["/sdev/sdi"]
        for tag, value in (("mfModel", "Model X"), ("mfSerNum", "SN-1"), ("mfHwVer", "HW 2")):
            body = re.sub(rf"<{tag}>[^<]*</{tag}>", f"<{tag}>{value}</{tag}>", body)
        self.exact["/sdev/sdi"] = (status, body)


async def test_the_profile_keeps_what_the_meter_says_it_is(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=DescribedTree()) as fm:
        profile = await make_meter(pki, fm.port).discover()
    assert (profile.model, profile.serial_number, profile.hardware_version) == ("Model X", "SN-1", "HW 2")
    assert MeterProfile.from_dict(json.loads(json.dumps(profile.to_dict()))) == profile

    older = profile.to_dict()  # cached before these fields existed
    for key in ("model", "serial_number", "hardware_version"):
        del older[key]
    assert MeterProfile.from_dict(older).model is None
    for key in ("model", "software_version", "meter_lfdi", "meter_sfdi", "time_href", "device_information_href"):
        with pytest.raises(ProfileError):
            MeterProfile.from_dict({**profile.to_dict(), key: 5})
    assert MeterProfile.from_dict({**profile.to_dict(), "model": "  "}).model is None


async def test_an_empty_device_information_is_none(pki: Pki, fake_meter: FakeMeter) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    assert (profile.model, profile.serial_number, profile.hardware_version) == (None, None, None)
