"""ReadingGuard: plausibility of single readings, of rebases over time, and of whole snapshots."""

from __future__ import annotations

import dataclasses
import logging

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
QUARTER = 900.0  # a poll every 15 minutes: well inside the 30-minute gap that breaks a run
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


def test_a_consistent_new_series_above_is_adopted_after_a_day() -> None:
    """Upward as downward: a real change happens once in a meter's life, while an
    adopted glitch would stay in a consumer's statistics for good."""
    guard = ReadingGuard()
    guard.register("r", 1_000.0, NOW)
    results = _series(guard, [9e9 + 10 * i for i in range(100)], NOW, QUARTER)
    assert results[:96] == [None] * 96 and results[96] == 9e9 + 960
    assert guard.rebases == {"r": NOW + 97 * QUARTER} and guard.resets == {}


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
    results = _series(guard, [float(i) for i in range(100)], NOW, QUARTER)
    assert results[:96] == [None] * 96 and results[96] == 96.0  # adopted after 24 h
    assert guard.resets["r"] == guard.rebases["r"] == NOW + 97 * QUARTER
    # The meter returns to its real register: back to the earlier series at once,
    # recorded as another rebase so a consumer starts a new cycle, not a 50 MWh step.
    t = NOW + 101 * QUARTER
    assert guard.register("r", LIFETIME + 100, t) == LIFETIME + 100
    assert guard.rebases["r"] == t and "r" not in guard.displaced


def test_a_stuck_high_value_adopted_after_a_day_gives_way_to_the_real_register() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    results = _series(guard, [9e9] * 100, NOW, QUARTER)  # stuck for a day: adopted
    assert results[-1] == 9e9 and "r" in guard.rebases
    t = NOW + 101 * QUARTER
    assert guard.register("r", LIFETIME + 50, t) == LIFETIME + 50  # back at once, not after a day
    assert guard.resets == {"r": t}  # a return that steps down is a new cycle


def test_a_confirmation_survives_restarts() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    t = NOW
    for _ in range(96):  # a consumer restarting after every poll while the meter reads ~0
        t += QUARTER
        assert guard.register("r", (t - NOW) / 900, t) is None
        guard = ReadingGuard.from_dict(guard.to_dict())
    t += QUARTER
    assert guard.register("r", (t - NOW) / 900, t) == 97.0  # adopted: the run kept its start
    assert "r" in guard.resets


def test_downtime_counts_only_up_to_max_gap_toward_a_confirmation() -> None:
    """An outage is not observation: 10 h without reads adds only 2 h (max_gap)."""
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    before = _series(guard, [float(i) for i in range(48)], NOW, QUARTER)  # 11.75 h observed
    resume = NOW + 48 * QUARTER + 10 * HOUR  # 10 h with no reads at all
    after = _series(guard, [float(i) for i in range(100, 160)], resume, QUARTER)
    assert before == [None] * 48
    adopted = next(i for i, v in enumerate(after) if v is not None)
    # 11.75 h + 2 h (the outage, capped) + 15 min (resume) + the rest at 15 min a read: 24 h after ~40 more reads.
    assert 38 <= adopted <= 42
    assert "r" in guard.resets


def test_a_slow_poller_still_confirms_a_reset() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    results = _series(guard, [float(i) for i in range(60)], NOW, 1800.0)  # every 30 minutes
    assert results[47] is None and results[48] == 48.0  # 24 h observed after the first read


def test_jittered_polls_with_a_missed_poll_and_a_stray_still_confirm() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    t, adopted = NOW, None
    for i in range(140):
        t += QUARTER + (37 if i % 3 else -23)  # not exactly 900 s apart
        if i == 50:
            t += QUARTER  # a missed poll
        value = 9e12 if i == 70 else float(i)  # one absurd read
        if guard.register("r", value, t) is not None and adopted is None:
            adopted = t
    assert adopted is not None and DAY <= adopted - NOW <= DAY + 2 * HOUR


def test_a_lone_spike_does_not_restart_a_long_confirmation() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    values = [float(i) for i in range(100)]
    values[80] = 9e12  # one absurd read, 20 hours in
    results = _series(guard, values, NOW, QUARTER)
    assert results[80] is None and results[96] == 96.0  # adopted after 24 h despite the spike


def test_an_inconsistent_run_starts_over() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    for i, spike in enumerate((9e9, 5e9, 9e9, 5e9, 9e9)):
        assert guard.register("r", spike, QUARTER * (i + 1)) is None
    assert guard.register("r", 1_010.0, 6 * HOUR) == 1_010.0
    assert guard.register("r", None, 7 * HOUR) is None


def test_the_state_survives_a_restart() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    guard.resets["r"] = guard.rebases["r"] = 5.0
    guard.displaced["r"] = (9_000.0, 1.0, 2.0)
    data = guard.to_dict()
    data["registers"]["bad"] = "x"
    data["resets"]["worse"] = "y"
    restarted = ReadingGuard.from_dict(data)
    assert restarted.registers == {"r": (1_000.0, 0.0)}
    assert restarted.resets == restarted.rebases == {"r": 5.0}
    assert restarted.displaced == {"r": (9_000.0, 1.0, 2.0)}
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
    spiky = _with_value(spiky, energy, value=total - 5e6)  # a lifetime register going far backwards
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
    tiers[tier] = dataclasses.replace(tiers[tier], value=tiers[tier].value - 5e6)  # type: ignore[operator]
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


async def test_the_meters_clock_never_widens_the_bound(pki: Pki, fake_meter: FakeMeter) -> None:
    """A reading dated a year ahead is judged at the consumer's clock: a spike stays a spike."""
    from datetime import UTC, datetime

    profile, snapshot = await _snapshot(pki, fake_meter)
    energy = _key(profile, statistic=Statistic.SUMMATION)
    total = snapshot.values[energy].value
    assert total is not None
    guard = ReadingGuard()
    guard.accept(snapshot, profile, NOW)
    future = datetime(2100, 1, 1, tzinfo=UTC)
    spike = _with_value(snapshot, energy, value=total + 4e8, start=future)
    assert guard.accept(spike, profile, NOW + 60).values[energy] is None
    assert guard.accept(snapshot, profile, NOW + 120).values[energy] == total  # the real register still flows


def test_a_register_refreshed_hourly_is_not_a_spike() -> None:
    """ToU tiers on an Itron change about once an hour: polled every minute, the
    step after an hour of EV charging must still be plausible."""
    guard = ReadingGuard()
    guard.register("tier", 1_000_000.0, NOW)
    for minute in range(1, 67):  # the same stale value at every poll
        assert guard.register("tier", 1_000_000.0, NOW + 60 * minute) == 1_000_000.0
    assert guard.register("tier", 1_007_500.0, NOW + 67 * 60) == 1_007_500.0  # 7.5 kWh in 67 min
    assert guard.registers["tier"] == (1_007_500.0, NOW + 67 * 60)


def test_malformed_saved_state_is_ignored_entry_by_entry() -> None:
    state = {
        "registers": {"ok": [1.0, 2.0], "dict": {"x": 1}, "short": "ab", "inf": [1, float("inf")], "long": [1, 2, 3]},
        "pending": {
            "ok": [1, 2, 3, 4, 1, 0],  # a run that tolerated one stray: kept
            "huge": [1, 2, 3, 10**400, 0, 0],
            "strays": [1, 2, 3, 2, 9, 0],
            "fraction": [1, 2, 3, 4.5, 0, 0],
            "backwards": [1, 5, 3, 4, 0, 0],
            "text": [1, 2, 3, "4", 0, 0],
            "dict": {"a": 1},
        },
        "rebases": {"ok": 5, "bool": True, "huge": 10**400, "text": "5"},
    }
    guard = ReadingGuard.from_dict(state)
    assert guard.registers == {"ok": (1.0, 2.0)}
    assert guard.pending == ["ok"]
    assert guard.rebases == {"ok": 5.0}


def test_a_spike_after_a_quiet_spell_is_still_a_spike() -> None:
    """A register that sat still (an off-peak tier over a weekend, export at night)
    earns at most max_refresh of growth, not the whole quiet spell."""
    guard = ReadingGuard()
    guard.register("tier", 7_745_743.0, NOW)
    t = NOW
    for _ in range(68 * 60):  # 68 h unchanged, read every minute
        t += 60
        assert guard.register("tier", 7_745_743.0, t) == 7_745_743.0
    assert guard.register("tier", 7_745_743.0 + 2e6, t + 60) is None  # +2 MWh
    assert guard.register("tier", 7_745_743.0 + 50, t + 120) == 7_745_743.0 + 50  # the real register goes on


def test_growth_while_the_consumer_was_down_is_allowed() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000_000.0, NOW)
    assert guard.register("r", 1_030_000.0, NOW + 10 * HOUR) == 1_030_000.0  # 30 kWh in a 10 h outage


def test_a_run_saved_right_after_a_stray_survives_a_restart() -> None:
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    _series(guard, [float(i) for i in range(8)], NOW, QUARTER)
    guard.register("r", 9e12, NOW + 9 * QUARTER)  # a tolerated stray
    assert guard.pending == ["r"]
    assert ReadingGuard.from_dict(guard.to_dict()).pending == ["r"]


def test_after_a_small_accepted_glitch_the_value_is_held_until_the_register_catches_up() -> None:
    """A glitch within the growth bound cannot be told from real use. The real
    register then reads a little below it: hold, never decrease, never a reset."""
    guard = ReadingGuard()
    guard.register("r", 1_000_000.0, NOW)
    assert guard.register("r", 1_008_000.0, NOW + QUARTER) == 1_008_000.0  # +8 kWh in 15 min: plausible
    assert guard.register("r", 1_000_050.0, NOW + 2 * QUARTER) == 1_008_000.0  # the real register: held
    assert guard.register("r", 1_007_000.0, NOW + 5 * HOUR) == 1_008_000.0
    assert guard.register("r", 1_009_000.0, NOW + 6 * HOUR) == 1_009_000.0  # caught up
    assert guard.resets == {} and guard.rejected == 0


def test_an_outage_does_not_confirm_a_spike() -> None:
    """Spike, 70 minutes of silence, spike, spike: no gap counts for more than 2 h,
    and a run needs a day, so nothing is adopted."""
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    spike = LIFETIME + 4e8
    for when in (NOW + 60, NOW + 60 + 70 * 60, NOW + 120 + 70 * 60, NOW + 180 + 70 * 60):
        assert guard.register("r", spike, when) is None
    restarted = ReadingGuard.from_dict(guard.to_dict())  # nor across a restart
    assert restarted.register("r", spike, NOW + 65 * 60 + 2 * HOUR) is None
    assert guard.rebases == {} and restarted.rebases == {}


def test_strays_add_no_time_to_a_run() -> None:
    """20 h of zeros with real reads among them never make a day of zeros."""
    guard = ReadingGuard()
    guard.register("r", LIFETIME, NOW)
    t = NOW
    for i in range(1200):  # a minute apart; every fifth read is the real register
        t += 60
        value = 0.0 if i % 5 else LIFETIME + i
        guard.register("r", value, t)
    assert guard.resets == {}


def test_a_net_register_needs_a_day_to_rebase_too() -> None:
    guard = ReadingGuard()
    guard.register("net", 5_000_000.0, NOW, monotonic=False)
    results = [guard.register("net", 0.0, NOW + 60 * (i + 1), monotonic=False) for i in range(120)]
    assert results == [None] * 120 and guard.rebases == {}  # two hours of zeros: not a new baseline


def test_growth_is_allowed_after_the_consumers_clock_steps_back() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000_000.0, NOW)
    guard.register("r", 1_000_100.0, NOW + 60)
    # The host reboots with its clock an hour behind; meanwhile the meter counted 1.5 kWh.
    assert guard.register("r", 1_001_600.0, NOW - HOUR) == 1_001_600.0
    assert guard.register("r", 1_001_700.0, NOW - HOUR + 60) == 1_001_700.0
