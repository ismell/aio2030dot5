"""Drop readings a healthy meter cannot produce.

Brief absurd spikes have been seen from HAN agents (and are cheap to guard
against), and one bad sample of a lifetime register corrupts a consumer's
long-term statistics for good. :class:`ReadingGuard` is an optional filter for
consumers. :meth:`ReadingGuard.accept` applies it to a whole
:class:`MeterSnapshot`, together with the meter's own verdict (readings it flags
questionable).

**Time.** All times are the consumer's clock, never the meter's. For each
register the guard keeps its value, when that value was *first seen*, and when
it was *last seen* (its latest accepted read).

**Power** must be within +/- ``max_power`` W (a residential 240 V service tops
out near 48 kW).

**A register** (energy, VAh, varh totals and ToU tiers) must not decrease, and
may grow by at most ``max_power`` times its *allowance* plus 1 kWh of slack.
The allowance is the time since the value was first seen, but no more than the
time it was last seen plus ``max_refresh`` (default 90 min)::

    allowance = min(now - first_seen, now - last_seen + max_refresh)

where ``last_seen`` is the latest accepted read of the register. Rejected reads
do not count: while a glitch lasts, the real register keeps growing. A
register the meter refreshes only now and then (ToU tiers, about hourly on an
Itron) may so step by what the time since its last change allows, while one
that merely sat still (an off-peak tier over a weekend, the export register at
night) earns no more than ``max_refresh``: a spike after a quiet spell is still
a spike. Time the consumer could not read the meter (a restart, an outage)
counts in full. A *net* register (delivered minus received) may move either
way, by the same allowance. A glitch within what the allowance permits --
about 76 kWh with the defaults -- cannot be told from real use. If one is
accepted, the real register reads a little below it afterwards; a monotonic
register cannot really decrease by that little (a reset drops it far lower), so
the guard *holds* the accepted value until the real register catches up: a
consumer's total stays right, only its timing shifts.

**A new baseline** -- a replaced or reset meter -- shows up as rejected reads
that are consistent with each other (a *run*). The guard adopts a run only after
``confirm`` consistent reads (12) over ``confirm_seconds`` (24 h) of observation,
in either direction: a real change of baseline happens once in a meter's life,
while one adopted glitch would stay in a consumer's statistics for good. Only
observed time counts: the gap before each consistent read adds at most
``confirm_seconds / confirm`` (2 h), so no outage or restart confirms anything,
while polling every 15 or 30 minutes, with missed polls, still adds up. A run
tolerates one stray read per four consistent ones (a lone spike does not cost a
day's confirmation); strays add no time. Reads alternating between two series
never form a run. Runs are part of :meth:`ReadingGuard.to_dict`.

Every adoption is recorded in :attr:`ReadingGuard.rebases` (and reported by
:meth:`ReadingGuard.accept`), and a downward one also in
:attr:`ReadingGuard.resets`: a consumer keeping a running total should start a
new accumulation cycle at either rather than book the step. After a rebase the
baseline it replaced is kept for ``confirm_seconds``; if the meter comes back
to it -- the "new series" was a long-lived glitch after all -- the guard returns
to it at once (another rebase; a reset too if that is a step down).

If the consumer's clock steps back, the elapsed time is unknown: the register is allowed ``max_refresh`` from there.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .client import MeterSnapshot
from .models import Measurement, QualityFlags
from .profile import Direction, MeterProfile, Quantity, Statistic

__all__ = ["AcceptedReadings", "ReadingGuard", "questionable"]

_LOGGER = logging.getLogger(__name__)
_SLACK_WH = 1000.0
# Bounds for restored runs: a stored run past these is corrupt, not a long confirmation.
_MAX_RUN_READS = 1_000_000
_MAX_RUN_SECONDS = 30 * 86400.0


@dataclass(slots=True)
class _Run:
    """Consistent rejected reads that may become the new baseline."""

    value: float  # its latest value
    first_seen: float  # when that value was first seen
    last_read: float  # the latest consistent read
    count: int = 1  # consistent reads
    strays: int = 0  # inconsistent reads tolerated inside the run
    observed: float = 0.0  # seconds of observation, each gap counted up to confirm_seconds / confirm


def _strays_allowed(strays: int, count: int) -> bool:
    """The run invariant: at most one stray per four consistent reads."""
    return 0 <= strays and strays * 4 <= count


@dataclass(frozen=True, slots=True)
class AcceptedReadings:
    """What :meth:`ReadingGuard.accept` lets through from one snapshot.

    ``values`` maps each profiled channel the snapshot read, or failed to read,
    to its value. ``tou`` maps each profiled ToU register to ``{tier: value}``
    for every tier the meter returned, including tier 0 (the register's total);
    a register that failed to read maps its known tiers to None. A value is None
    where the read failed, the meter flagged the reading questionable, or the
    guard found it implausible. ``rebased`` names the registers whose value is a
    new baseline (see :attr:`ReadingGuard.rebases`).
    """

    values: dict[str, float | None] = field(default_factory=dict)
    tou: dict[str, dict[int, float | None]] = field(default_factory=dict)
    # Registers this snapshot moved to a new baseline (channel keys, and
    # "<key>_tier_<n>" for tiers): start a new accumulation cycle for them.
    rebased: frozenset[str] = frozenset()


def questionable(measurement: Measurement) -> bool:
    """True if the meter itself flags the reading as questionable."""
    return measurement.quality is not None and bool(measurement.quality & QualityFlags.QUESTIONABLE)


class ReadingGuard:
    """Plausibility checks for one meter's readings (see the module docs). Persist
    with :meth:`to_dict` / :meth:`from_dict` so a spike right after a restart is caught."""

    def __init__(
        self,
        max_power: float = 50_000.0,
        confirm: int = 12,
        confirm_seconds: float = 86400.0,
        max_refresh: float = 5400.0,
    ) -> None:
        self.max_power = max_power
        self.confirm = confirm
        self.confirm_seconds = confirm_seconds
        self.max_refresh = max_refresh
        # key -> (value, epoch seconds the value was first seen)
        self.registers: dict[str, tuple[float, float]] = {}
        # key -> epoch seconds of the latest accepted read of the register
        self.last_seen: dict[str, float] = {}
        # key -> epoch seconds of the last rebase of any kind / of a downward one
        self.rebases: dict[str, float] = {}
        self.resets: dict[str, float] = {}
        # key -> (value, first seen, last seen) of the baseline the last rebase
        # replaced; kept for confirm_seconds after that rebase
        self.displaced: dict[str, tuple[float, float, float]] = {}
        self._pending: dict[str, _Run] = {}
        self.rejected = 0
        self._rejecting: set[str] = set()  # keys in a run of rejections (logged once)

    @property
    def pending(self) -> list[str]:
        """The keys with a run of reads being confirmed as a new baseline."""
        return sorted(self._pending)

    def accept(self, snapshot: MeterSnapshot, profile: MeterProfile, now: float | None = None) -> AcceptedReadings:
        """Filter a whole snapshot (``now``: epoch seconds, default the clock).

        Summation channels and ToU tiers go through :meth:`register` (keyed
        ``"<key>_tier_<n>"`` for tiers; a net channel may decrease), power
        channels through :meth:`power`; other channels pass as read. A reading
        the meter flags questionable is None and never reaches the guard.
        Channels not in ``profile`` are skipped.
        """
        now = time.time() if now is None else now
        rebases_before = dict(self.rebases)
        values: dict[str, float | None] = {}
        tou: dict[str, dict[int, float | None]] = {}
        for key in snapshot.errors:
            channel = profile.channel(key)
            if channel is None:
                continue
            if channel.statistic == Statistic.TOU_SUMMATION:
                tou[key] = dict.fromkeys((0, *channel.tou_tiers))
            else:
                values[key] = None
        for key, measurement in snapshot.values.items():
            channel = profile.channel(key)
            if channel is None:
                continue
            value = measurement.value
            if value is None or questionable(measurement):
                value = None
            elif channel.statistic == Statistic.SUMMATION:
                value = self.register(key, value, now, monotonic=channel.direction != Direction.NET)
            elif channel.quantity == Quantity.POWER:
                value = self.power(key, value)
            values[key] = value
        for key, register in snapshot.tou.items():
            channel = profile.channel(key)
            if channel is None:
                continue
            monotonic = channel.direction != Direction.NET
            tou[key] = {
                tier: None
                if m.value is None or questionable(m)
                else self.register(f"{key}_tier_{tier}", m.value, now, monotonic=monotonic)
                for tier, m in register.items()
            }
        rebased = frozenset(k for k, when in self.rebases.items() if rebases_before.get(k) != when)
        return AcceptedReadings(values, tou, rebased)

    def power(self, key: str, value: float | None) -> float | None:
        """The power reading, or None if it is implausible."""
        if value is None:
            return None
        if abs(value) <= self.max_power:
            self._recovered(key)
            return value
        self._reject(key, value, f"outside +/- {self.max_power:.0f} W")
        return None

    def register(self, key: str, value: float | None, now: float, *, monotonic: bool = True) -> float | None:
        """The register reading (``now``: epoch seconds, the consumer's clock), or
        None if it is implausible. ``monotonic=False`` for a net register, which
        may decrease."""
        if value is None:
            return None
        last = self.registers.get(key)
        if last is None:
            self._adopt(key, value, now)
            return value
        last_value, first_seen = last
        last_seen = self.last_seen.get(key, first_seen)
        if now < last_seen:
            # The consumer's clock stepped back (e.g. a host without a clock, before
            # NTP): elapsed time is unknown, so allow max_refresh, from here.
            first_seen, last_seen = now - self.max_refresh, now
            self.registers[key] = (last_value, first_seen)
            self.last_seen[key] = now
        displaced = self.displaced.get(key)
        if displaced is not None and now - self.rebases.get(key, displaced[2]) > self.confirm_seconds:
            del self.displaced[key]  # expired: the new series stands
            displaced = None
        if value == last_value or (monotonic and last_value - self._hold_margin <= value < last_value):
            # Unchanged -- or a little below an accepted value, which a register
            # that never decreases can only be after a small glitch was accepted:
            # hold the accepted value until the real register catches up.
            self.last_seen[key] = now
            self._pending.pop(key, None)
            self._recovered(key)
            return last_value
        if self._plausible(last_value, first_seen, last_seen, value, now, monotonic):
            self._adopt(key, value, now)
            return value
        if displaced is not None and self._plausible(*displaced, value, now, monotonic):
            _LOGGER.warning("%s: back to the earlier series at %s (was %s)", key, value, last_value)
            del self.displaced[key]
            self.rebases[key] = now
            if monotonic and value < last_value:
                self.resets[key] = now  # a step down: a new cycle for a consumer's running total
            self._adopt(key, value, now)
            return value
        run = self._track(key, value, now, monotonic)
        if run is None or run.count < self.confirm or run.observed < self.confirm_seconds:
            self._reject(key, value, f"after {last_value:.0f}")
            return None
        _LOGGER.warning(
            "%s: rebasing from %s to %s after %d consistent reads over %.0f s (meter replaced or reset?)",
            key,
            last_value,
            value,
            run.count,
            run.observed,
        )
        self.rebases[key] = now
        if monotonic and value < last_value:
            self.resets[key] = now
        self.displaced[key] = (last_value, first_seen, last_seen)
        self._adopt(key, value, now)
        return value

    def _track(self, key: str, value: float, now: float, monotonic: bool) -> _Run | None:
        """Add a rejected read to its run (see the module docs). The run ``value``
        belongs to, or None if it is a stray the run tolerates."""
        run = self._pending.get(key)
        if run is not None:
            if self._plausible(run.value, run.first_seen, run.last_read, value, now, monotonic):
                run.observed += min(max(now - run.last_read, 0.0), self.confirm_seconds / self.confirm)
                if value != run.value:
                    run.value, run.first_seen = value, now
                run.last_read = now
                run.count += 1
                return run
            if _strays_allowed(run.strays + 1, run.count):
                run.strays += 1  # no time: only consistent reads observe the series
                return None
        run = self._pending[key] = _Run(value, now, now)
        return run

    @property
    def _hold_margin(self) -> float:
        """The largest glitch the growth bound can let through, in Wh."""
        return self.max_power * self.max_refresh / 3600 + _SLACK_WH

    def _adopt(self, key: str, value: float, now: float) -> None:
        self._pending.pop(key, None)
        self.registers[key] = (value, now)
        self.last_seen[key] = now
        self._recovered(key)

    def _allowance(self, first_seen: float, last_seen: float, now: float) -> float:
        """Seconds of growth a register earned since its value was first seen."""
        return max(min(now - first_seen, now - last_seen + self.max_refresh), 1.0)

    def _plausible(
        self, prev: float, first_seen: float, last_seen: float, value: float, now: float, monotonic: bool
    ) -> bool:
        bound = self.max_power * self._allowance(first_seen, last_seen, now) / 3600 + _SLACK_WH
        if monotonic:
            return prev <= value <= prev + bound
        return abs(value - prev) <= bound

    def _reject(self, key: str, value: float, why: str) -> None:
        self.rejected += 1
        if key in self._rejecting:
            _LOGGER.debug("%s: dropped implausible value %s (%s)", key, value, why)
        else:
            self._rejecting.add(key)
            _LOGGER.warning("%s: dropped implausible value %s (%s)", key, value, why)

    def _recovered(self, key: str) -> None:
        if key in self._rejecting:
            self._rejecting.discard(key)
            _LOGGER.info("%s: plausible again", key)

    def to_dict(self) -> dict[str, Any]:
        """The state to persist (JSON-safe), including runs still being confirmed."""
        return {
            "registers": {key: list(reading) for key, reading in self.registers.items()},
            "last_seen": dict(self.last_seen),
            "rebases": dict(self.rebases),
            "resets": dict(self.resets),
            "displaced": {key: list(reading) for key, reading in self.displaced.items()},
            "pending": {
                key: [r.value, r.first_seen, r.last_read, r.count, r.strays, r.observed]
                for key, r in self._pending.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Any) -> ReadingGuard:
        """A guard with the default limits, restored from :meth:`to_dict` output."""
        guard = cls()
        guard.restore(data)
        return guard

    def restore(self, data: Any) -> None:
        """Load :meth:`to_dict` output (also 0.3.x state) into this guard, e.g. one
        built with other limits. Malformed entries are ignored one by one; the
        rest is kept."""
        if not isinstance(data, Mapping):
            return
        for key, reading in _items(data.get("registers")):
            numbers = _numbers(reading, 2)
            if numbers is not None:
                self.registers[str(key)] = (numbers[0], numbers[1])
        for key, reading in _items(data.get("displaced")):
            numbers = _numbers(reading, 3) or _numbers(reading, 2)  # 2: saved before last_seen was kept
            if numbers is not None:
                self.displaced[str(key)] = (numbers[0], numbers[1], numbers[-1])
        for name in ("last_seen", "rebases", "resets"):
            target = getattr(self, name)
            for key, when in _items(data.get(name)):
                numbers = _numbers([when], 1)
                if numbers is not None:
                    target[str(key)] = numbers[0]
        for key, run in _items(data.get("pending")):
            numbers = _numbers(run, 6)
            if numbers is None:
                continue
            value, first_seen, last_read, count, strays, observed = numbers
            if (
                count.is_integer()
                and strays.is_integer()
                and 1 <= count <= _MAX_RUN_READS
                and _strays_allowed(int(strays), int(count))
                and 0 <= observed <= _MAX_RUN_SECONDS
                and first_seen <= last_read
            ):
                self._pending[str(key)] = _Run(value, first_seen, last_read, int(count), int(strays), observed)


def _items(section: Any) -> list[tuple[Any, Any]]:
    """The entries of a stored section, or none if it is not a mapping."""
    return list(section.items()) if isinstance(section, Mapping) else []


def _numbers(entry: Any, length: int) -> list[float] | None:
    """A stored list of ``length`` finite numbers, or None if it is anything else."""
    if not isinstance(entry, list | tuple) or len(entry) != length:
        return None
    try:
        return [_finite(x) for x in entry]
    except ValueError:
        return None


def _finite(value: Any) -> float:
    """A stored number; ValueError for anything else: bools, strings, NaN, infinities."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"not a number: {value!r}")
    try:
        number = float(value)
    except OverflowError:
        raise ValueError("too large") from None
    if not math.isfinite(number):
        raise ValueError(f"not finite: {value!r}")
    return number
