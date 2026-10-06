"""High-level async client for an IEEE 2030.5 HAN meter.

Policy-free on purpose: no polling loop, no backoff, no caching to disk.
Consumers (an MQTT bridge, a Home Assistant DataUpdateCoordinator) own
cadence and decide what to do with each exception class.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .exceptions import MeterAuthError, MeterNotFound, MeterProtocolError, ProfileError
from .identity import Identity
from .models import (
    DeviceInformation,
    IntervalValue,
    Measurement,
    MeterTime,
    Reading,
    ReadingSetInfo,
    TouRegister,
    _from_iso,
    _iso,
    interval_values,
    parse_xml,
)
from .profile import Channel, MeterInfo, MeterProfile, Statistic, discover, get_list, read_meter_info, resolve_href
from .transport import (
    Batch,
    MeterTransport,
    PeerCertificate,
    Timeouts,
    TransportStats,
    async_build_ssl_context,
    build_ssl_context,
)

_LOGGER = logging.getLogger(__name__)

# Keys in this library's to_dict() output (and in Identity.to_dict()) that
# identify the meter, its owner's premises or a secret. For Home Assistant
# diagnostics: async_redact_data(data, REDACT_KEYS).
REDACT_KEYS = frozenset(
    {
        "cert_pem",
        "key_pem",
        "lfdi",
        "sfdi",
        "meter_lfdi",
        "meter_sfdi",
        "certificate_lfdi",
        "serial_number",
        "mrid",
        "host",
    }
)


@dataclass(frozen=True, slots=True)
class MeterSnapshot:
    """One batch of readings, keyed by :attr:`Channel.key`."""

    fetched_at: datetime
    values: dict[str, Measurement] = field(default_factory=dict)
    # ToU registers by channel key. Tier 0 is the total.
    tou: dict[str, TouRegister] = field(default_factory=dict)
    meter_time: MeterTime | None = None

    @property
    def clock_skew(self) -> timedelta | None:
        """Meter clock minus local clock (positive: meter is ahead)."""
        if self.meter_time is None:
            return None
        return self.meter_time.current_time - self.fetched_at

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe, e.g. to record a fixture or for diagnostics."""
        return {
            "fetched_at": _iso(self.fetched_at),
            "values": {k: m.to_dict() for k, m in self.values.items()},
            "tou": {k: r.to_dict() for k, r in self.tou.items()},
            "meter_time": self.meter_time.to_dict() if self.meter_time else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MeterSnapshot:
        fetched_at = _from_iso(d["fetched_at"])
        if fetched_at is None:
            raise ValueError("fetched_at is required")
        return cls(
            fetched_at=fetched_at,
            values={k: Measurement.from_dict(m) for k, m in d.get("values", {}).items()},
            tou={k: TouRegister.from_dict(r) for k, r in d.get("tou", {}).items()},
            meter_time=MeterTime.from_dict(d["meter_time"]) if d.get("meter_time") else None,
        )


@dataclass(frozen=True, slots=True)
class PeerInfo:
    """What :meth:`Meter.probe_tls` found at an address."""

    certificate: PeerCertificate  # .lfdi / .sfdi identify the meter
    client_accepted: bool  # the handshake completed with our certificate
    auth_reason: str | None = None  # MeterAuthError.reason when it did not

    @property
    def lfdi(self) -> str:
        return self.certificate.lfdi

    @property
    def sfdi(self) -> str:
        return self.certificate.sfdi


class Meter:
    """An IEEE 2030.5 meter reachable over the HAN (local) interface.

    Every public coroutine runs as one batch on one connection, and the
    instance never opens two connections at once. Share a single ``Meter``
    per physical meter.

    The meter is identified by its LFDI, not its address: every connection
    checks the meter's certificate against ``expected_lfdi`` before sending a
    request, and raises :class:`MeterIdentityMismatch` if another device
    answers (e.g. after a DHCP change -- find the meter again by mDNS). If
    ``expected_lfdi`` is not given, :meth:`discover` pins the meter it finds,
    and :meth:`read` pins the one a cached profile was discovered from.
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
        expected_lfdi: str | None = None,
        dcap_path: str = "/dcap",
    ) -> None:
        self.host = host
        self.port = port
        # Where discovery starts: the DNS-SD TXT record ``dcap`` when the
        # meter was found by mDNS.
        self.dcap_path = dcap_path
        self.transport = MeterTransport(
            host,
            port,
            ssl_context,
            timeouts=timeouts,
            min_connect_interval=min_connect_interval,
            request_spacing=request_spacing,
            expected_lfdi=expected_lfdi,
        )

    @classmethod
    async def create(
        cls,
        host: str,
        identity: Identity,
        port: int = 8081,
        *,
        timeouts: Timeouts | None = None,
        expected_lfdi: str | None = None,
        dcap_path: str = "/dcap",
        min_connect_interval: float = 2.0,
        request_spacing: float = 0.25,
    ) -> Meter:
        """A Meter using ``identity`` (e.g. from a config entry). Builds the
        TLS context off the event loop. ``expected_lfdi`` is the meter's
        LFDI, if already known; otherwise the first discover() pins it."""
        ctx = await async_build_ssl_context(identity)
        return cls(
            host,
            ctx,
            port,
            timeouts=timeouts,
            min_connect_interval=min_connect_interval,
            request_spacing=request_spacing,
            expected_lfdi=expected_lfdi,
            dcap_path=dcap_path,
        )

    @classmethod
    async def from_files(cls, host: str, cert_path: str, key_path: str, port: int = 8081, **kwargs: object) -> Meter:
        """Build the TLS context off the event loop (it reads files)."""
        ctx = await asyncio.to_thread(build_ssl_context, cert_path, key_path)
        return cls(host, ctx, port, **kwargs)  # type: ignore[arg-type]

    @property
    def stats(self) -> TransportStats:
        return self.transport.stats

    @property
    def expected_lfdi(self) -> str | None:
        return self.transport.expected_lfdi

    async def probe_tls(self) -> PeerInfo:
        """Who is at this address, and does it take our certificate?

        One handshake, then a clean close: no request, and no identity check
        (compare ``certificate.lfdi`` yourself). Works before our certificate
        is registered -- the meter sends its certificate before refusing ours.
        Agents that refuse only after the handshake report ``client_accepted``
        and fail on the first request instead.

        Raises ``MeterConnectionError``/``MeterTimeout`` if nothing answers,
        ``MeterProtocolError`` if the device sent no certificate.
        """
        try:
            async with self.transport.batch(verify_identity=False) as b:
                peer = await b.connect()
        except MeterAuthError as err:
            if self.transport.peer is None:
                raise
            return PeerInfo(self.transport.peer, client_accepted=False, auth_reason=err.reason)
        if peer is None:
            raise MeterProtocolError(f"{self.host}:{self.port} presented no certificate")
        return PeerInfo(peer, client_accepted=True)

    async def probe(self) -> MeterInfo:
        """Who the meter is, once our certificate is registered: 1-3 GETs on
        one connection (DeviceCapability, SelfDevice, DeviceInformation).
        Checks ``expected_lfdi`` like every call; does not pin."""
        async with self.transport.batch() as b:
            return await read_meter_info(b, self.host, self.port, dcap_path=self.dcap_path)

    async def discover(self, *, dcap_path: str | None = None) -> MeterProfile:
        """Walk the resource tree (~30 GETs, one connection), starting at
        ``dcap_path`` (default: the Meter's). Pins the meter
        (``expected_lfdi``) if nothing was pinned yet."""
        async with self.transport.batch() as b:
            peer = await b.connect()
            profile = await discover(b, self.host, self.port, dcap_path=dcap_path or self.dcap_path)
        if peer is None:
            return profile
        if profile.meter_lfdi and profile.meter_lfdi.upper() != peer.lfdi:
            _LOGGER.warning(
                "%s: /sdev reports LFDI %s but its TLS certificate is %s; pinning the certificate",
                self.host,
                profile.meter_lfdi,
                peer.lfdi,
            )
        if self.transport.expected_lfdi is None:
            self.transport.expected_lfdi = peer.lfdi
        return dataclasses.replace(profile, certificate_lfdi=peer.lfdi)

    def _pin(self, profile: MeterProfile) -> None:
        """Adopt a cached profile's meter identity, or refuse a profile from
        another meter."""
        pinned = profile.certificate_lfdi.upper() if profile.certificate_lfdi else None
        if pinned is None:
            return
        if self.transport.expected_lfdi is None:
            self.transport.expected_lfdi = pinned
        elif self.transport.expected_lfdi != pinned:
            raise ProfileError(f"profile is from meter {pinned}, but this Meter expects {self.transport.expected_lfdi}")

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
        self._pin(profile)
        values: dict[str, Measurement] = {}
        tou: dict[str, TouRegister] = {}
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
        """Completed intervals ending after ``since`` (an aware datetime), oldest first."""
        if since.tzinfo is None:
            raise ValueError("since must be timezone-aware (the meter speaks UTC)")
        wanted = [
            rs
            for rs in await self.list_interval_sets(channel)
            # A set of unknown length might reach past ``since``: keep it.
            if rs.start is not None and (rs.duration is None or rs.start + timedelta(seconds=rs.duration) > since)
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
        self._pin(profile)
        if not profile.device_information_href:
            return None
        async with self.transport.batch() as b:
            return DeviceInformation.from_xml(parse_xml(await b.get(profile.device_information_href)))

    async def meter_time(self, profile: MeterProfile) -> MeterTime:
        self._pin(profile)
        if not profile.time_href:
            raise MeterProtocolError("meter advertises no TimeLink")
        async with self.transport.batch() as b:
            return MeterTime.from_xml(parse_xml(await b.get(profile.time_href)))


def _require_interval(channel: Channel) -> str:
    """The channel's ReadingSetList href; ValueError if it is not interval data."""
    if channel.statistic != Statistic.INTERVAL or not channel.reading_set_list_href:
        raise ValueError(f"{channel.key} is not an interval channel")
    return channel.reading_set_list_href


async def _read_tou(b: Batch, ch: Channel) -> TouRegister:
    assert ch.tou_reading_list_href
    _, elems = await get_list(b, ch.tou_reading_list_href, "Reading")
    tiers: dict[int, Measurement] = {}
    for e in elems:
        r = Reading.from_xml(e)
        if r.tou_tier is not None:
            tiers[r.tou_tier] = Measurement.of(r, ch.reading_type)
    return TouRegister(tiers)


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
        if rs.start is None:
            continue  # cannot be placed in time
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


__all__ = ["REDACT_KEYS", "Meter", "MeterSnapshot", "PeerInfo"]
