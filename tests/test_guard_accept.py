"""ReadingGuard.accept: a whole snapshot through the meter's flags and the guard."""

from __future__ import annotations

import dataclasses
import time

from aio2030dot5 import (
    AcceptedReadings,
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
        assert 0 not in accepted.tou[key]  # the total is the channel itself
        assert accepted.tou[key] == {tier: m.value for tier, m in register.items() if tier > 0}


async def test_the_meters_own_questionable_flag_wins(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    key = _key(profile, statistic=Statistic.SUMMATION)
    flagged = _with_value(snapshot, key, quality=QualityFlags.QUESTIONABLE)
    assert questionable(flagged.values[key])
    guard = ReadingGuard()

    assert guard.accept(flagged, profile, NOW).values[key] is None
    assert key not in guard.registers  # a flagged reading never becomes the baseline


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


async def test_now_defaults_to_the_clock(pki: Pki, fake_meter: FakeMeter) -> None:
    profile, snapshot = await _snapshot(pki, fake_meter)
    guard = ReadingGuard()
    guard.accept(snapshot, profile)
    energy = _key(profile, statistic=Statistic.SUMMATION)
    assert abs(guard.registers[energy][1] - time.time()) < 60
