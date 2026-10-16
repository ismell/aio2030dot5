"""Drop readings a healthy meter cannot produce.

Brief absurd spikes have been seen from HAN agents (and are cheap to guard
against), and one bad sample of a lifetime register corrupts a consumer's
long-term statistics for good. :class:`ReadingGuard` is an optional filter for
consumers:

* power must be within +/- ``max_power`` W (a residential 240 V service tops
  out near 48 kW);
* a register (energy, VAh, varh totals and ToU tiers) must not decrease, and
  may grow no faster than ``max_power`` allows since the last accepted value
  (plus 1 kWh of slack). A *net* register (delivered minus received) may move
  either way, at that same rate.

:meth:`ReadingGuard.accept` applies all of that to a whole :class:`MeterSnapshot`,
together with the meter's own verdict (readings it flags questionable).

A real change of baseline -- a replaced or reset meter -- shows up as rejected
reads that are consistent *with each other*. The guard adopts such a series
only once it has lasted: ``confirm`` reads over at least ``confirm_seconds``
(default 1 h), or, when the new series is *below* the old one,
``confirm_decrease`` reads over at least ``confirm_decrease_seconds`` (default
24 h). The time spans matter more than the counts: they keep a meter that
answers 0 for a while (an agent restarting before its metrology is up) from
being taken for a reset however often it is polled.

A run survives a restart (it is part of :meth:`ReadingGuard.to_dict`) and the
odd stray reading (one per four consistent reads), but reads alternating
between two series never form one.

Every adoption is recorded in :attr:`ReadingGuard.rebases`, and a downward one
also in :attr:`ReadingGuard.resets`: a consumer keeping a running total should
start a new accumulation cycle at either rather than book the step. After any
rebase the baseline it replaced is kept for ``confirm_decrease_seconds``; if the
meter comes back to it -- the "new series" was a long-lived glitch after all --
the guard returns to it at once (another rebase, never a reset).
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


@dataclass(slots=True)
class _Run:
    """Consistent rejected reads that may be a new baseline."""

    first_time: float
    last: tuple[float, float]  # (value, epoch seconds) of the latest read
    count: int = 1
    strays: int = 0  # inconsistent reads tolerated inside the run

    def extend(self, cur: tuple[float, float]) -> None:
        self.last = cur
        self.count += 1


@dataclass(frozen=True, slots=True)
class AcceptedReadings:
    """What :meth:`ReadingGuard.accept` lets through from one snapshot.

    ``values`` maps each profiled channel the snapshot read, or failed to read,
    to its value. ``tou`` maps each profiled ToU register to ``{tier: value}``
    for every tier the meter returned, including tier 0 (the register's total);
    a register that failed to read maps its known tiers to None. A value is None
    where the read failed, the meter flagged the reading questionable, or the
    guard found it implausible.
    """

    values: dict[str, float | None] = field(default_factory=dict)
    tou: dict[str, dict[int, float | None]] = field(default_factory=dict)


def questionable(measurement: Measurement) -> bool:
    """True if the meter itself flags the reading as questionable."""
    return measurement.quality is not None and bool(measurement.quality & QualityFlags.QUESTIONABLE)


class ReadingGuard:
    """Plausibility checks for one meter's readings. Persist with
    :meth:`to_dict` / :meth:`from_dict` so a spike right after a restart is caught."""

    def __init__(
        self,
        max_power: float = 50_000.0,
        confirm: int = 3,
        confirm_decrease: int = 12,
        confirm_seconds: float = 3600.0,
        confirm_decrease_seconds: float = 86400.0,
    ) -> None:
        self.max_power = max_power
        self.confirm = confirm
        self.confirm_decrease = confirm_decrease
        self.confirm_seconds = confirm_seconds
        self.confirm_decrease_seconds = confirm_decrease_seconds
        # key -> (value, epoch seconds) of the last accepted reading
        self.registers: dict[str, tuple[float, float]] = {}
        # key -> epoch seconds of the last rebase of any kind / of a downward one
        self.rebases: dict[str, float] = {}
        self.resets: dict[str, float] = {}
        # key -> (value, epoch seconds) of the baseline the last rebase replaced;
        # kept for confirm_decrease_seconds after that rebase
        self.displaced: dict[str, tuple[float, float]] = {}
        # key -> the run of consistent rejected reads that may become the baseline
        self.pending: dict[str, _Run] = {}
        self.rejected = 0
        self._rejecting: set[str] = set()  # keys in a run of rejections (logged once)

    def accept(self, snapshot: MeterSnapshot, profile: MeterProfile, now: float | None = None) -> AcceptedReadings:
        """Filter a whole snapshot (``now``: epoch seconds, default the clock).

        Summation channels and ToU tiers go through :meth:`register` (keyed
        ``"<key>_tier_<n>"`` for tiers; a net channel may decrease), power
        channels through :meth:`power`; other channels pass as read. A reading
        the meter flags questionable is None and never reaches the guard.
        Channels not in ``profile`` are skipped.

        A register is judged at the time the meter took the reading (its
        ``start``) when it says, else ``now``: a register the meter refreshes
        only now and then (ToU tiers, about hourly on an Itron) then grows by
        what the elapsed time allows, however often it is polled.
        """
        now = time.time() if now is None else now
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
                value = self.register(
                    key, value, _taken(measurement, now), monotonic=channel.direction != Direction.NET
                )
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
                else self.register(f"{key}_tier_{tier}", m.value, _taken(m, now), monotonic=monotonic)
                for tier, m in register.items()
            }
        return AcceptedReadings(values, tou)

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
        """The register reading (``now``: epoch seconds), or None if it is
        implausible. ``monotonic=False`` for a net register, which may decrease."""
        if value is None:
            return None
        cur = (value, now)
        displaced = self.displaced.get(key)
        if displaced is not None and now - self.rebases.get(key, displaced[1]) > self.confirm_decrease_seconds:
            del self.displaced[key]  # expired: the new series stands
            displaced = None
        last = self.registers.get(key)
        if last is None or self._plausible(last, cur, monotonic):
            self._adopt(key, cur)
            return value
        if displaced is not None:
            if self._plausible(displaced, cur, monotonic):
                _LOGGER.warning("%s: back to the earlier series at %s (was %s)", key, value, last[0])
                del self.displaced[key]
                self.rebases[key] = now
                self._adopt(key, cur)
                return value
        run = self._track(key, cur, monotonic)
        if run is None:  # a stray inside an established run: rejected, the run kept
            self._reject(key, value, f"after {last[0]:.0f}")
            return None
        down = monotonic and value < last[0]
        needed, span = (
            (self.confirm_decrease, self.confirm_decrease_seconds) if down else (self.confirm, self.confirm_seconds)
        )
        if run.count >= needed and now - run.first_time >= span:
            _LOGGER.warning(
                "%s: rebasing from %s to %s after %d consistent reads over %.0f s (meter replaced or reset?)",
                key,
                last[0],
                value,
                run.count,
                now - run.first_time,
            )
            self.rebases[key] = now
            if down:
                self.resets[key] = now
            self.displaced[key] = last
            self._adopt(key, cur)
            return value
        self._reject(key, value, f"after {last[0]:.0f}")
        return None

    def _track(self, key: str, cur: tuple[float, float], monotonic: bool) -> _Run | None:
        """Add a rejected read to the run it is consistent with. A read that is
        not is a stray: an established run tolerates one stray per four
        consistent reads (a lone spike does not cost a day's confirmation),
        but no more -- reads alternating between two series never form a run.
        The run ``cur`` belongs to, or None if ``cur`` is a tolerated stray."""
        run = self.pending.get(key)
        if run is not None and self._plausible(run.last, cur, monotonic):
            run.extend(cur)
            return run
        if run is not None and (run.strays + 1) * 4 <= run.count:
            run.strays += 1
            return None
        run = self.pending[key] = _Run(cur[1], cur)
        return run

    def _adopt(self, key: str, cur: tuple[float, float]) -> None:
        self.pending.pop(key, None)
        self.registers[key] = cur
        self._recovered(key)

    def _plausible(self, prev: tuple[float, float], cur: tuple[float, float], monotonic: bool = True) -> bool:
        (prev_value, prev_time), (value, now) = prev, cur
        bound = self.max_power * max(now - prev_time, 1.0) / 3600 + _SLACK_WH
        if monotonic:
            return prev_value <= value <= prev_value + bound
        return abs(value - prev_value) <= bound

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
            "rebases": dict(self.rebases),
            "resets": dict(self.resets),
            "displaced": {key: list(reading) for key, reading in self.displaced.items()},
            "pending": {key: [r.first_time, *r.last, r.count, r.strays] for key, r in self.pending.items()},
        }

    @classmethod
    def from_dict(cls, data: Any) -> ReadingGuard:
        """A guard with the default limits, restored from :meth:`to_dict` output."""
        guard = cls()
        guard.restore(data)
        return guard

    def restore(self, data: Any) -> None:
        """Load :meth:`to_dict` output into this guard (e.g. one built with other
        limits). Malformed or missing state is ignored, entry by entry."""
        if not isinstance(data, Mapping):
            return
        for name in ("registers", "displaced"):
            readings = data.get(name)
            target = getattr(self, name)
            for key, reading in readings.items() if isinstance(readings, Mapping) else ():
                try:
                    value, when = _finite(reading[0]), _finite(reading[1])
                    if len(reading) != 2:
                        continue
                    target[str(key)] = (value, when)
                except (TypeError, ValueError):
                    continue
        runs = data.get("pending")
        for key, run in runs.items() if isinstance(runs, Mapping) else ():
            try:
                first, value, when, count, strays = run
                self.pending[str(key)] = _Run(
                    _finite(first), (_finite(value), _finite(when)), max(int(count), 1), max(int(strays), 0)
                )
            except (TypeError, ValueError):
                continue
        for name in ("rebases", "resets"):
            times = data.get(name)
            target = getattr(self, name)
            for key, when in times.items() if isinstance(times, Mapping) else ():
                try:
                    target[str(key)] = _finite(when)
                except (TypeError, ValueError):
                    continue


def _taken(measurement: Measurement, now: float) -> float:
    """When the meter took a reading (epoch seconds), else ``now``."""
    return measurement.start.timestamp() if measurement.start is not None else now


def _finite(value: Any) -> float:
    """A stored number; ValueError for anything else, incl. bools, NaN and infinities."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise ValueError(f"not a number: {value!r}")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"not finite: {value!r}")
    return number
