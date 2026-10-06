"""High-level async client for an IEEE 2030.5 HAN meter.

Policy-free on purpose: no polling loop, no backoff, no caching to disk.
Consumers (an MQTT bridge, a Home Assistant DataUpdateCoordinator) own
cadence and decide what to do with each exception class.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .exceptions import MeterProtocolError
from .models import (
    DeviceInformation,
    IntervalValue,
    Measurement,
    MeterTime,
    Reading,
    ReadingSetInfo,
    interval_values,
    parse_xml,
)
from .profile import Channel, MeterProfile, Statistic, discover, get_list
from .transport import Batch, MeterTransport, Timeouts, TransportStats, build_ssl_context


@dataclass(frozen=True, slots=True)
class MeterSnapshot:
    """One batch of readings, keyed by :attr:`Channel.key`."""

    fetched_at: datetime
    values: dict[str, Measurement] = field(default_factory=dict)
    # ToU registers: channel key -> {tier: Measurement}. Tier 0 is the total.
    tou: dict[str, dict[int, Measurement]] = field(default_factory=dict)
    meter_time: MeterTime | None = None

    @property
    def clock_skew(self) -> timedelta | None:
        """Meter clock minus local clock (positive: meter is ahead)."""
        if self.meter_time is None:
            return None
        return self.meter_time.current_time - self.fetched_at


class Meter:
    """An IEEE 2030.5 meter reachable over the HAN (local) interface.

    Every public coroutine runs as one batch on one connection, and the
    instance never opens two connections at once. Share a single ``Meter``
    per physical meter.
    """

    def __init__(
        self,
        host: str,
        ssl_context: ssl.SSLContext,
        port: int = 8081,
        *,
        timeouts: Timeouts | None = None,
        min_connect_interval: float = 2.0,
        request_spacing: float = 0.25,
    ) -> None:
        self.host = host
        self.port = port
        self.transport = MeterTransport(
            host,
            port,
            ssl_context,
            timeouts=timeouts,
            min_connect_interval=min_connect_interval,
            request_spacing=request_spacing,
        )

    @classmethod
    async def from_files(cls, host: str, cert_path: str, key_path: str, port: int = 8081, **kwargs: object) -> Meter:
        """Build the TLS context off the event loop (it reads files)."""
        ctx = await asyncio.to_thread(build_ssl_context, cert_path, key_path)
        return cls(host, ctx, port, **kwargs)  # type: ignore[arg-type]

    @property
    def stats(self) -> TransportStats:
        return self.transport.stats

    async def discover(self) -> MeterProfile:
        """Walk the resource tree (~30 GETs, one connection)."""
        async with self.transport.batch() as b:
            return await discover(b, self.host, self.port)

    async def read(
        self,
        profile: MeterProfile,
        channels: Iterable[Channel],
        *,
        include_time: bool = False,
    ) -> MeterSnapshot:
        """Read the latest value of each channel in one batch.

        Interval channels are skipped; use :meth:`read_latest_intervals`.
        Raises ``MeterNotFound`` if a profiled path vanished (rediscover).
        """
        values: dict[str, Measurement] = {}
        tou: dict[str, dict[int, Measurement]] = {}
        meter_time = None
        fetched_at = datetime.now(UTC)
        async with self.transport.batch() as b:
            for ch in channels:
                if ch.statistic == Statistic.TOU_SUMMATION and ch.tou_reading_list_href:
                    tou[ch.key] = await _read_tou(b, ch)
                elif ch.reading_href and ch.statistic != Statistic.INTERVAL:
                    reading = Reading.from_xml(parse_xml(await b.get(ch.reading_href)))
                    values[ch.key] = Measurement.of(reading, ch.reading_type)
            if include_time and profile.time_href:
                meter_time = MeterTime.from_xml(parse_xml(await b.get(profile.time_href)))
                fetched_at = datetime.now(UTC)
        return MeterSnapshot(fetched_at=fetched_at, values=values, tou=tou, meter_time=meter_time)

    async def read_latest_intervals(self, channel: Channel, *, complete_only: bool = True) -> list[IntervalValue]:
        """Intervals in the newest ReadingSet of an interval channel (oldest first)."""
        if channel.statistic != Statistic.INTERVAL or not channel.reading_set_list_href:
            raise ValueError(f"{channel.key} is not an interval channel")
        async with self.transport.batch() as b:
            newest = await _newest_set(b, channel.reading_set_list_href)
            if newest is None:
                return []
            return await _read_set(b, channel, newest, complete_only)

    async def read_interval_history(
        self, channel: Channel, *, max_sets: int | None = None, complete_only: bool = True
    ) -> list[IntervalValue]:
        """Every stored interval (oldest first). Expensive: ~2 GETs per 12 h set
        on an Itron agent (60 sets = 30 days); use sparingly, e.g. for backfill."""
        if channel.statistic != Statistic.INTERVAL or not channel.reading_set_list_href:
            raise ValueError(f"{channel.key} is not an interval channel")
        out: list[IntervalValue] = []
        async with self.transport.batch() as b:
            _, sets = await get_list(b, channel.reading_set_list_href, "ReadingSet", limit=max_sets)
            for elem in sets:
                out.extend(await _read_set(b, channel, ReadingSetInfo.from_xml(elem), complete_only))
        out.sort(key=lambda v: v.start)
        return out

    async def device_information(self, profile: MeterProfile) -> DeviceInformation | None:
        if not profile.device_information_href:
            return None
        async with self.transport.batch() as b:
            return DeviceInformation.from_xml(parse_xml(await b.get(profile.device_information_href)))

    async def meter_time(self, profile: MeterProfile) -> MeterTime:
        if not profile.time_href:
            raise MeterProtocolError("meter advertises no TimeLink")
        async with self.transport.batch() as b:
            return MeterTime.from_xml(parse_xml(await b.get(profile.time_href)))


async def _read_tou(b: Batch, ch: Channel) -> dict[int, Measurement]:
    assert ch.tou_reading_list_href
    _, elems = await get_list(b, ch.tou_reading_list_href, "Reading")
    tiers: dict[int, Measurement] = {}
    for e in elems:
        r = Reading.from_xml(e)
        if r.tou_tier is not None:
            tiers[r.tou_tier] = Measurement.of(r, ch.reading_type)
    return tiers


async def _newest_set(b: Batch, href: str) -> ReadingSetInfo | None:
    """The ReadingSet with the latest start, without assuming list order."""
    page, elems = await get_list(b, href, "ReadingSet", limit=2)
    sets = [ReadingSetInfo.from_xml(e) for e in elems]
    if not sets:
        return None
    if len(sets) == 2 and _start(sets[0]) < _start(sets[1]) and page.all > 2:
        # Ascending order: the newest set is the last one.
        _, last = await get_list(b, href, "ReadingSet", start=page.all - 1, limit=1)
        sets.extend(ReadingSetInfo.from_xml(e) for e in last)
    return max(sets, key=_start)


def _start(s: ReadingSetInfo) -> datetime:
    return s.start or datetime.min.replace(tzinfo=UTC)


async def _read_set(b: Batch, ch: Channel, rs: ReadingSetInfo, complete_only: bool) -> list[IntervalValue]:
    if not rs.reading_list_href:
        return []
    _, elems = await get_list(b, rs.reading_list_href, "Reading")
    values = interval_values(rs, [Reading.from_xml(e) for e in elems], ch.reading_type)
    if complete_only and rs.start is not None and rs.duration is not None:
        horizon = rs.start + timedelta(seconds=rs.duration)
        values = [v for v in values if v.end <= horizon]
    return values


__all__ = ["Meter", "MeterSnapshot"]
