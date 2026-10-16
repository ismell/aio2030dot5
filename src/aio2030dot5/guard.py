"""Drop readings a healthy meter cannot produce.

Brief absurd spikes have been reported from Itron HAN agents, and one bad
sample of a lifetime register corrupts a consumer's long-term statistics for
good. :class:`ReadingGuard` is an optional filter for consumers:

* power must be within +/- ``max_power`` W (a residential 240 V service tops
  out near 48 kW);
* a register (energy, VAh, varh totals and ToU tiers) must not decrease, and
  may grow no faster than ``max_power`` allows since the last accepted value
  (plus 1 kWh of slack).

:meth:`ReadingGuard.accept` applies all of that to a whole :class:`MeterSnapshot`,
together with the meter's own verdict (readings it flags questionable).

A real change of baseline shows up as rejected reads that are consistent
*with each other*. After ``confirm`` of them (``confirm_decrease`` when the
new series is below the old one, so a meter answering 0 for a while is not
taken for a reset) the guard rebases. A rebase downward is a register reset:
it is recorded in :attr:`ReadingGuard.resets`, so a consumer can start a new
accumulation cycle (Home Assistant: ``last_reset``) instead of booking a
negative change.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .models import QualityFlags
from .profile import Quantity, Statistic

if TYPE_CHECKING:
    from .client import MeterSnapshot
    from .models import Measurement
    from .profile import MeterProfile

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AcceptedReadings:
    """What :meth:`ReadingGuard.accept` lets through from one snapshot.

    ``values`` maps each channel the snapshot read (or failed to read) to its
    value, or None where the read failed, the meter flagged the reading
    questionable, or the guard found it implausible. ``tou`` maps each ToU
    register to ``{tier: value}`` for tiers 1..n (tier 0, the total, is the
    register's own channel), None on the same grounds.
    """

    values: dict[str, float | None] = field(default_factory=dict)
    tou: dict[str, dict[int, float | None]] = field(default_factory=dict)


def questionable(measurement: Measurement) -> bool:
    """True if the meter itself flags the reading as questionable."""
    return measurement.quality is not None and bool(measurement.quality & QualityFlags.QUESTIONABLE)


class ReadingGuard:
    """Plausibility checks for one meter's readings. Persist with
    :meth:`as_dict` / :meth:`load` so a spike right after a restart is caught."""

    def __init__(self, max_power: float = 50_000.0, confirm: int = 3, confirm_decrease: int = 12) -> None:
        self.max_power = max_power
        self.confirm = confirm
        self.confirm_decrease = confirm_decrease
        # key -> (value, epoch seconds) of the last accepted reading
        self.registers: dict[str, tuple[float, float]] = {}
        # key -> epoch seconds of the last downward rebase (a register reset)
        self.resets: dict[str, float] = {}
        self.pending: dict[str, list[tuple[float, float]]] = {}
        self.rejected = 0
        self._rejecting: set[str] = set()  # keys in a run of rejections (logged once)

    def accept(self, snapshot: MeterSnapshot, profile: MeterProfile, now: float | None = None) -> AcceptedReadings:
        """Filter a whole snapshot (``now``: epoch seconds, default the clock).

        Summation channels and ToU tiers go through :meth:`register` (keyed
        ``"<key>_tier_<n>"`` for tiers), power channels through :meth:`power`;
        other channels pass as read. Channels not in ``profile`` are skipped.
        """
        now = time.time() if now is None else now
        values: dict[str, float | None] = dict.fromkeys(snapshot.errors)
        for key, measurement in snapshot.values.items():
            channel = profile.channel(key)
            if channel is None:
                continue
            value = None if questionable(measurement) else measurement.value
            if channel.statistic == Statistic.SUMMATION:
                value = self.register(key, value, now)
            elif channel.quantity == Quantity.POWER:
                value = self.power(key, value)
            values[key] = value
        tou: dict[str, dict[int, float | None]] = {}
        for key, register in snapshot.tou.items():
            if profile.channel(key) is None:
                continue
            tou[key] = {
                tier: self.register(f"{key}_tier_{tier}", None if questionable(m) else m.value, now)
                for tier, m in register.items()
                if tier > 0
            }
        return AcceptedReadings(values, tou)

    def power(self, key: str, value: float | None) -> float | None:
        """The power reading, or None if it is implausible."""
        if value is None or abs(value) <= self.max_power:
            self._recovered(key)
            return value
        self._reject(key, value, f"outside +/- {self.max_power:.0f} W")
        return None

    def register(self, key: str, value: float | None, now: float) -> float | None:
        """The register reading (``now``: epoch seconds), or None if it is
        implausible."""
        if value is None:
            return None
        cur = (value, now)
        last = self.registers.get(key)
        if last is None or self._plausible(last, cur):
            self.pending.pop(key, None)
            self.registers[key] = cur
            self._recovered(key)
            return value
        run = self.pending.setdefault(key, [])
        if run and not self._plausible(run[-1], cur):
            run.clear()  # not a consistent new series: start over from this read
        run.append(cur)
        needed = self.confirm_decrease if value < last[0] else self.confirm
        if len(run) >= needed:
            _LOGGER.warning(
                "%s: rebasing from %s to %s after %d consistent reads (meter replaced or reset?)",
                key,
                last[0],
                value,
                len(run),
            )
            del self.pending[key]
            self.registers[key] = cur
            if value < last[0]:
                self.resets[key] = now
            self._recovered(key)
            return value
        self._reject(key, value, f"after {last[0]:.0f}")
        return None

    def _plausible(self, prev: tuple[float, float], cur: tuple[float, float]) -> bool:
        (prev_value, prev_time), (value, time) = prev, cur
        return prev_value <= value <= prev_value + self.max_power * max(time - prev_time, 1.0) / 3600 + 1000

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

    def as_dict(self) -> dict[str, Any]:
        """The state to persist (JSON-safe)."""
        return {
            "registers": {key: list(reading) for key, reading in self.registers.items()},
            "resets": dict(self.resets),
        }

    def load(self, data: Any) -> None:
        """Restore :meth:`as_dict` output; anything malformed is ignored."""
        if not isinstance(data, dict):
            return
        registers = data.get("registers", {})
        for key, reading in registers.items() if isinstance(registers, dict) else ():
            try:
                value, time = reading
                self.registers[str(key)] = (float(value), float(time))
            except (TypeError, ValueError):
                continue
        resets = data.get("resets", {})
        for key, time in resets.items() if isinstance(resets, dict) else ():
            try:
                self.resets[str(key)] = float(time)
            except (TypeError, ValueError):
                continue
