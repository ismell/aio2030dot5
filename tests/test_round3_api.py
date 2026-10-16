"""Round 3: the API a Home Assistant integration builds on."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aio2030dot5 import (
    REDACT_KEYS,
    Identity,
    IntervalValue,
    InvalidIdentity,
    Measurement,
    Meter,
    MeterInfo,
    MeterNotFound,
    MeterSnapshot,
    MeterTimeout,
    QualityFlags,
    Timeouts,
    TouRegister,
    build_ssl_context_from_pem,
    generate_identity,
    hourly_energy,
    load_identity,
)

from .conftest import FAST, Pki, make_meter
from .meter_server import FakeMeter
from .test_robustness import SlowTree

# -- identity in memory -------------------------------------------------------------


def registered(pki: Pki) -> Identity:
    return load_identity(pki.client_cert.read_text(), pki.client_key.read_text())


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


# -- probing ---------------------------------------------------------------------------


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


# -- the batch deadline --------------------------------------------------------------


async def test_a_call_past_its_deadline_is_a_meter_timeout(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        meter = make_meter(pki, fm.port, timeouts=Timeouts(2, 2, 2, batch=0.2))
        with pytest.raises(MeterTimeout):
            await meter._transport.get("/tm?slow=1")


async def test_waiting_for_the_lock_does_not_count_against_the_deadline(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        slow = make_meter(pki, fm.port)
        quick = make_meter(pki, fm.port, timeouts=Timeouts(2, 2, 2, batch=0.4))
        backfill = asyncio.create_task(slow._transport.get("/tm?slow=1"))  # holds the meter ~0.5 s
        await asyncio.sleep(0.05)
        assert await quick._transport.get("/dcap")  # queued ~0.5 s, then quick
        await backfill


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


# -- diagnostics ---------------------------------------------------------------------------


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
