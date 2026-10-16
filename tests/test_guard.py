"""ReadingGuard: plausibility of single readings, of rebases over time, and of whole snapshots."""

from __future__ import annotations

import dataclasses
import logging
import time

import pytest

from aio2030dot5 import (
    AcceptedReadings,
    Direction,
    MeterNotFound,
    MeterProfile,
    MeterSnapshot,
    QualityFlags,
    Quantity,
    ReadingGuard,
    Statistic,
    TouRegister,
    questionable,
)

from .conftest import Pki, make_meter
from .meter_server import FakeMeter

NOW = 1_800_000_000.0
HOUR = 3600.0
DAY = 24 * HOUR
LIFETIME = 50_000_000.0  # a 50 MWh lifetime register


# -- single readings ----------------------------------------------------------------


def test_power_beyond_a_residential_service_is_dropped() -> None:
    guard = ReadingGuard()
    assert guard.power("power", -12_000.0) == -12_000.0
    assert guard.power("power", 4e6) is None
    assert guard.power("power", None) is None
    assert guard.rejected == 1


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        pytest.param(1_000_000.0, True, id="unchanged"),
        pytest.param(1_049_000.0, True, id="a-full-hour-at-49-kW"),
        pytest.param(1_100_000.0, False, id="faster-than-50-kW"),
        pytest.param(999_999.0, False, id="backwards"),
    ],
)
def test_register_growth_is_bounded(value: float, accepted: bool) -> None:
    guard = ReadingGuard()
    assert guard.register("r", 1_000_000.0, 0.0) == 1_000_000.0
    assert (guard.register("r", value, HOUR) == value) is accepted


def test_a_net_register_may_fall_but_not_faster_than_the_service_allows() -> None:
    guard = ReadingGuard()
    assert guard.register("net", 1_000_000.0, 0.0, monotonic=False) == 1_000_000.0
    assert guard.register("net", 990_000.0, HOUR, monotonic=False) == 990_000.0  # exporting
    assert guard.register("net", 900_000.0, HOUR + 60, monotonic=False) is None  # 90 kWh in a minute


def test_a_run_of_rejections_is_logged_once(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="aio2030dot5")
    guard = ReadingGuard()
    for _ in range(5):
        guard.power("power", 9e9)
    guard.power("power", 1.0)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "plausible again" in caplog.text


# -- rebasing: a new series is adopted only once it has lasted ------------------------


def _series(guard: ReadingGuard, values: list[float], start: float, step: float) -> list[float | None]:
    return [guard.register("r", v, start + step * (i + 1)) for i, v in enumerate(values)]


def test_a_consistent_new_series_above_is_adopted_after_an_hour() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, NOW)
    results = _series(guard, [9e9 + 10 * i for i in range(62)], NOW, 60.0)
    assert results[:60] == [None] * 60  # three reads are not enough: it has to last an hour
    assert results[60] == 9e9 + 600
    assert guard.rebases == {"r": NOW + 61 * 60} and guard.resets == {}


def test_a_stuck_spike_shorter_than_the_confirmation_is_never_adopted() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, NOW)
    assert _series(guard, [9e9] * 30, NOW, 60.0) == [None] * 30  # half an hour stuck
    assert guard.register("r", 1_010.0, NOW + 31 * 60) == 1_010.0
    assert guard.rebases == {}


def test_a_meter_answering_zero_for_a_while_is_not_a_reset() -> None:
    """However often it is polled: confirmation is by time, not by count."""
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    assert _series(guard, [0.0] * 120, NOW, 60.0) == [None] * 120  # two hours of zeros
    back = guard.register("r", LIFETIME + 10, NOW + 121 * 60)
    assert back == LIFETIME + 10
    assert guard.resets == {} and guard.rebases == {}


def test_a_drop_lasting_a_day_is_a_reset_and_the_old_series_can_return() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    results = _series(guard, [float(i) for i in range(26)], NOW, HOUR)
    assert results[:23] == [None] * 23 and results[24] == 24.0  # adopted after 24 h
    assert guard.resets["r"] == guard.rebases["r"] == NOW + 25 * HOUR
    # The meter returns to its real register: back to the earlier series at once,
    # recorded as another rebase so a consumer starts a new cycle, not a 50 MWh step.
    t = NOW + 27 * HOUR
    assert guard.register("r", LIFETIME + 100, t) == LIFETIME + 100
    assert guard.rebases["r"] == t and "r" not in guard.displaced


def test_an_inconsistent_run_starts_over() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    for i, spike in enumerate((9e9, 5e9, 9e9, 5e9, 9e9)):
        assert guard.register("r", spike, HOUR * (i + 1)) is None
    assert guard.register("r", 1_010.0, 6 * HOUR) == 1_010.0
    assert guard.register("r", None, 7 * HOUR) is None


def test_the_state_survives_a_restart() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    guard.resets["r"] = guard.rebases["r"] = 5.0
    guard.displaced["r"] = (9_000.0, 1.0)
    data = guard.to_dict()
    data["registers"]["bad"] = "x"
    data["resets"]["worse"] = "y"
    restarted = ReadingGuard.from_dict(data)
    assert restarted.registers == {"r": (1_000.0, 0.0)}
    assert restarted.resets == restarted.rebases == {"r": 5.0}
    assert restarted.displaced == {"r": (9_000.0, 1.0)}
    assert restarted.register("r", 9e9, 60.0) is None
    for junk in (None, [1], {"registers": [1], "resets": 3}):
        assert ReadingGuard.from_dict(junk).registers == {}
    custom = ReadingGuard(max_power=10_000.0)
    custom.restore(data)
    assert custom.max_power == 10_000.0 and custom.registers == {"r": (1_000.0, 0.0)}


# -- whole snapshots ----------------------------------------------------------------


async def _snapshot(pki: Pki, fake_meter: FakeMeter) -> tuple[MeterProfile, MeterSnapshot]:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    readable = [c for c in profile.channels if c.statistic != Statistic.INTERVAL]
    return profile, await meter.read(profile, readable)


def _key(profile: MeterProfile, statistic: Statistic | None = None, quantity: Quantity | None = None) -> str:
    return next(
        c.key
        for c in profile.channels
        if (statistic is None or c.statistic == statistic) and (quantity is None or c.quantity == quantity)
    )


def _with_value(snapshot: MeterSnapshot, key: str, **changes: object) -> MeterSnapshot:
    values = dict(snapshot.values)
    values[key] = dataclasses.replace(values[key], **changes)  # type: ignore[arg-type]
    return dataclasses.replace(snapshot, values=values)


async def test_a_healthy_snapshot_passes_unchanged(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    accepted = ReadingGuard().accept(snapshot, profile, NOW)

    assert isinstance(accepted, AcceptedReadings)
    assert accepted.values == {key: m.value for key, m in snapshot.values.items()}
    assert snapshot.tou  # the real meter has ToU registers
    for key, register in snapshot.tou.items():
        assert accepted.tou[key] == {tier: m.value for tier, m in register.items()}  # tier 0 included


async def test_the_meters_own_questionable_flag_wins(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    key = _key(profile, statistic=Statistic.SUMMATION)
    flagged = _with_value(snapshot, key, quality=QualityFlags.QUESTIONABLE)
    assert questionable(flagged.values[key])
    guard = ReadingGuard()

    assert guard.accept(flagged, profile, NOW).values[key] is None
    assert key not in guard.registers  # a flagged reading never becomes the baseline


async def test_a_questionable_power_reading_does_not_end_a_run_of_rejections(
    pki: Pki, fake_meter: FakeMeter, caplog: pytest.LogCaptureFixture
) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    power = _key(profile, quantity=Quantity.POWER)
    guard = ReadingGuard()
    guard.accept(_with_value(snapshot, power, value=9e9), profile, NOW)
    caplog.set_level(logging.INFO, logger="aio2030dot5")
    guard.accept(_with_value(snapshot, power, quality=QualityFlags.QUESTIONABLE), profile, NOW + 60)
    assert "plausible again" not in caplog.text


async def test_a_net_channel_is_guarded_without_monotonicity(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    energy = _key(profile, statistic=Statistic.SUMMATION)
    channels = tuple(
        dataclasses.replace(c, direction=Direction.NET) if c.key == energy else c for c in profile.channels
    )
    net = dataclasses.replace(profile, channels=channels)
    guard = ReadingGuard()
    guard.accept(snapshot, net, NOW)
    total = snapshot.values[energy].value
    assert total is not None
    assert guard.accept(_with_value(snapshot, energy, value=total - 500), net, NOW + HOUR).values[energy] == total - 500


async def test_implausible_values_are_dropped(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    power = _key(profile, quantity=Quantity.POWER)
    energy = _key(profile, statistic=Statistic.SUMMATION)
    guard = ReadingGuard()
    guard.accept(snapshot, profile, NOW)
    total = snapshot.values[energy].value
    assert total is not None

    spiky = _with_value(snapshot, power, value=10_000_000.0)
    spiky = _with_value(spiky, energy, value=total - 5_000)  # a lifetime register going backwards
    accepted = guard.accept(spiky, profile, NOW + 60)

    assert accepted.values[power] is None
    assert accepted.values[energy] is None
    assert guard.rejected == 2


async def test_tou_tiers_are_guarded_one_by_one(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    key, register = next(iter(snapshot.tou.items()))
    tier = next(t for t, m in register.items() if t > 0 and m.value is not None)
    guard = ReadingGuard()
    guard.accept(snapshot, profile, NOW)

    tiers = dict(register.items())
    tiers[tier] = dataclasses.replace(tiers[tier], value=tiers[tier].value - 5_000)  # type: ignore[operator]
    dropped = dataclasses.replace(snapshot, tou={**snapshot.tou, key: TouRegister(tiers)})
    accepted = guard.accept(dropped, profile, NOW + 60)

    assert accepted.tou[key][tier] is None
    assert all(v is not None for t, v in accepted.tou[key].items() if t != tier and register[t].value is not None)


async def test_failed_reads_are_unknown_and_strangers_skipped(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    failed = _key(profile, statistic=Statistic.SUMMATION)
    values = {k: m for k, m in snapshot.values.items() if k != failed}
    values["not_in_profile"] = snapshot.values[failed]
    odd = dataclasses.replace(
        snapshot,
        values=values,
        tou={**snapshot.tou, "not_in_profile": next(iter(snapshot.tou.values()))},
        errors={failed: MeterNotFound("gone", 404)},
    )
    accepted = ReadingGuard().accept(odd, profile, NOW)

    assert accepted.values[failed] is None
    assert "not_in_profile" not in accepted.values
    assert "not_in_profile" not in accepted.tou


async def test_a_failed_tou_register_is_unknown_in_tou_not_values(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    key = next(iter(snapshot.tou))
    channel = profile.channel(key)
    assert channel is not None
    odd = dataclasses.replace(
        snapshot,
        tou={k: r for k, r in snapshot.tou.items() if k != key},
        errors={key: MeterNotFound("gone", 404), "not_in_profile": MeterNotFound("gone", 404)},
    )
    accepted = ReadingGuard().accept(odd, profile, NOW)
    assert key not in accepted.values and "not_in_profile" not in accepted.values
    assert accepted.tou[key] == dict.fromkeys((0, *channel.tou_tiers))


async def test_now_defaults_to_the_clock(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    guard = ReadingGuard()
    guard.accept(snapshot, profile)
    energy = _key(profile, statistic=Statistic.SUMMATION)
    assert abs(guard.registers[energy][1] - time.time()) < 60
