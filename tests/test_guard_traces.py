"""ReadingGuard over many randomized, realistic traces (seeded, so reproducible).

A trace is a register the way an Itron agent and a Home Assistant poller see it:
growth at household power, flat spells (nights, weekends, idle ToU tiers),
refreshes only every hour or so, polls a minute or a quarter apart with jitter,
missed polls and consumer outages. Glitches are injected into it: absurd spikes,
bursts of zeros (an agent restarting before its metrology is up), stray reads.
Whatever the trace, the guard must:

* never accept an injected glitch;
* keep the accepted series non-decreasing, except at a recorded reset;
* never lose the real register for long: after a glitch ends, the next real
  read is accepted.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

import pytest

from aio2030dot5 import ReadingGuard

START = 1_800_000_000.0


@dataclass
class Read:
    time: float
    value: float
    glitch: bool


def trace(rng: random.Random, hours: int) -> list[Read]:
    """Polls of one register, with glitches mixed in."""
    poll = rng.choice([60.0, 900.0])
    refresh = rng.choice([0.0, 3600.0, 4000.0])  # 0: the meter updates the register at every read
    power = rng.uniform(0, 12_000)  # W, changes every so often
    value, shown, t, last_refresh = rng.uniform(1e6, 5e7), 0.0, START, START
    shown = value
    reads: list[Read] = []
    while t < START + hours * 3600:
        step = poll + rng.uniform(-0.1, 0.1) * poll
        if rng.random() < 0.01:
            step += rng.choice([poll, 3 * 3600.0])  # a missed poll, or a consumer outage
        t += step
        if rng.random() < 0.02:
            power = rng.choice([0.0, rng.uniform(0, 12_000)])  # a flat spell, or a new load
        value += power * step / 3600
        if refresh == 0 or t - last_refresh >= refresh:
            shown, last_refresh = value, t
        roll = rng.random() if reads else 1.0  # the first read is the baseline: never a glitch
        if roll < 0.004:
            reads.append(Read(t, shown + rng.choice([2e6, 4e8, 9e12]), glitch=True))
        elif roll < 0.006:
            burst = rng.randint(1, 40)  # zeros for up to 40 polls (at most 10 h: far from a day)
            for _ in range(burst):
                reads.append(Read(t, 0.0, glitch=True))
                t += poll
        else:
            reads.append(Read(t, shown, glitch=False))
    return reads


@pytest.mark.parametrize("seed", range(200))
def test_the_guard_keeps_its_promises(seed: int) -> None:
    rng = random.Random(seed)
    guard = ReadingGuard()
    accepted: list[tuple[float, float]] = []
    lost_since: float | None = None
    for read in trace(rng, hours=rng.choice([6, 48, 120])):
        value = guard.register("r", read.value, read.time)
        if read.glitch:
            assert value is None, f"seed {seed}: accepted glitch {read.value} at {read.time - START:.0f} s"
            continue
        if value is None:
            lost_since = read.time if lost_since is None else lost_since
            assert read.time - lost_since < 3 * 3600, (
                f"seed {seed}: real register lost since {lost_since - START:.0f} s"
            )
            continue
        lost_since = None
        if accepted and value < accepted[-1][1]:
            assert guard.resets.get("r") == read.time, f"seed {seed}: unrecorded decrease at {read.time - START:.0f} s"
        accepted.append((read.time, value))
    assert accepted, f"seed {seed}: nothing accepted"
