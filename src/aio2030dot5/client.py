"""High-level async client for an IEEE 2030.5 HAN meter.

Policy-free on purpose: no polling loop, no backoff, no caching to disk.
Consumers (an MQTT bridge, a Home Assistant DataUpdateCoordinator) own
cadence and decide what to do with each exception class.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .exceptions import MeterNotFound, MeterProtocolError
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
from .profile import Channel, MeterProfile, Statistic, discover, get_list, resolve_href
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
        async with self.transport.batch() as b:
            # Taken once the lock is ours, not while queued behind another batch.
            fetched_at = datetime.now(UTC)
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

    # -- interval data -----------------------------------------------------------
    #
    # An Itron agent keeps 60 ReadingSets of 12 h (UTC-aligned, newest first),
    # each holding up to 48 15-min Readings. The newest set is partial: its
    # duration grows and only completed intervals are listed.

    async def read_latest_intervals(
        self, channel: Channel, *, sets: int = 2, complete_only: bool = True
    ) -> list[IntervalValue]:
        """Completed intervals from the newest ``sets`` ReadingSets (oldest
        first). Two sets, so the last interval before a set boundary
        (11:45-12:00, 23:45-00:00 UTC) is not lost while the new set is empty."""
        _require_interval(channel)
        async with self.transport.batch() as b:
            newest = await _newest_sets(b, channel.reading_set_list_href, sets, self.host, self.port)
            return await _read_sets(b, channel, newest, complete_only, self.host, self.port)

    async def list_interval_sets(self, channel: Channel) -> list[ReadingSetInfo]:
        """Every stored ReadingSet of an interval channel, newest first."""
        href = _require_interval(channel)
        async with self.transport.batch() as b:
            _, elems = await get_list(b, href, "ReadingSet")
        sets = [_resolve_set(href, ReadingSetInfo.from_xml(e), self.host, self.port) for e in elems]
        return sorted(sets, key=_start, reverse=True)

    async def read_interval_sets(
        self, channel: Channel, sets: Iterable[ReadingSetInfo], *, complete_only: bool = True
    ) -> list[IntervalValue]:
        """The intervals of the given sets (from :meth:`list_interval_sets`),
        oldest first, in one batch. Chunk long histories into several calls so
        other readers get the meter in between. A set that rolled off the
        meter meanwhile is skipped."""
        _require_interval(channel)
        async with self.transport.batch() as b:
            return await _read_sets(b, channel, list(sets), complete_only, self.host, self.port)

    async def read_intervals_since(
        self, channel: Channel, since: datetime, *, complete_only: bool = True
    ) -> list[IntervalValue]:
        """Completed intervals ending after ``since`` (oldest first)."""
        wanted = [
            rs
            for rs in await self.list_interval_sets(channel)
            if rs.start is not None and rs.start + timedelta(seconds=rs.duration or 0) > since
        ]
        values = await self.read_interval_sets(channel, wanted, complete_only=complete_only)
        return [v for v in values if v.end > since]

    async def read_interval_history(
        self, channel: Channel, *, max_sets: int | None = None, complete_only: bool = True
    ) -> list[IntervalValue]:
        """Every stored interval (oldest first), or the newest ``max_sets``
        sets. Expensive (~2 GETs per set, 60 sets on an Itron agent) and holds
        the meter for the whole walk; prefer list/read_interval_sets in chunks."""
        sets = await self.list_interval_sets(channel)
        return await self.read_interval_sets(channel, sets[:max_sets], complete_only=complete_only)

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


def _require_interval(channel: Channel) -> str:
    """The channel's ReadingSetList href; ValueError if it is not interval data."""
    if channel.statistic != Statistic.INTERVAL or not channel.reading_set_list_href:
        raise ValueError(f"{channel.key} is not an interval channel")
    return channel.reading_set_list_href


async def _read_tou(b: Batch, ch: Channel) -> dict[int, Measurement]:
    assert ch.tou_reading_list_href
    _, elems = await get_list(b, ch.tou_reading_list_href, "Reading")
    tiers: dict[int, Measurement] = {}
    for e in elems:
        r = Reading.from_xml(e)
        if r.tou_tier is not None:
            tiers[r.tou_tier] = Measurement.of(r, ch.reading_type)
    return tiers


def _resolve_set(base: str, rs: ReadingSetInfo, host: str, port: int) -> ReadingSetInfo:
    href = resolve_href(base, rs.href, host, port) if rs.href else base
    return dataclasses.replace(
        rs,
        href=href,
        reading_list_href=resolve_href(href, rs.reading_list_href, host, port) if rs.reading_list_href else None,
    )


async def _newest_sets(b: Batch, href: str | None, count: int, host: str, port: int) -> list[ReadingSetInfo]:
    """The ``count`` ReadingSets with the latest starts, without assuming list order."""
    assert href
    page, elems = await get_list(b, href, "ReadingSet", limit=max(count, 2))
    sets = [_resolve_set(href, ReadingSetInfo.from_xml(e), host, port) for e in elems]
    if len(sets) >= 2 and _start(sets[0]) < _start(sets[1]) and page.all > len(sets):
        # Ascending order (the spec asks for newest first): read the tail instead.
        _, tail = await get_list(b, href, "ReadingSet", start=max(page.all - count, 0), limit=count)
        sets.extend(_resolve_set(href, ReadingSetInfo.from_xml(e), host, port) for e in tail)
    return sorted(sets, key=_start, reverse=True)[:count]


def _start(s: ReadingSetInfo) -> datetime:
    return s.start or datetime.min.replace(tzinfo=UTC)


async def _read_sets(
    b: Batch, ch: Channel, sets: list[ReadingSetInfo], complete_only: bool, host: str, port: int
) -> list[IntervalValue]:
    out: list[IntervalValue] = []
    for rs in sets:
        if not rs.reading_list_href:
            continue
        try:
            _, elems = await get_list(b, rs.reading_list_href, "Reading")
        except MeterNotFound:
            continue  # the set rolled off the meter since it was listed
        values = interval_values(rs, [Reading.from_xml(e) for e in elems], ch.reading_type)
        if complete_only and rs.start is not None and rs.duration is not None:
            horizon = rs.start + timedelta(seconds=rs.duration)
            values = [v for v in values if v.end <= horizon]
        out.extend(values)
    out.sort(key=lambda v: v.start)
    return out


__all__ = ["Meter", "MeterSnapshot"]
