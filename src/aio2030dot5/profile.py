"""Meter discovery and the cacheable MeterProfile.

Discovery walks /dcap -> /sdev -> /upt -> MeterReadingList -> ReadingTypes on
ONE connection and classifies every MeterReading by its ReadingType, so
consumers ask for "energy delivered" instead of hard-coding ``/upt/1/mr/3``
(the numbering differs between agent versions).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from .exceptions import MeterProtocolError
from .models import (
    Accumulation,
    DataQualifier,
    DeviceCapability,
    DeviceInformation,
    FlowDirection,
    Kind,
    ListPage,
    MeterReadingInfo,
    ReadingSetInfo,
    ReadingType,
    SelfDevice,
    Uom,
    UsagePoint,
    children,
    local_name,
    parse_xml,
)
from .transport import Batch

PROFILE_VERSION = 1
PAGE_SIZE = 25  # the Itron agent pages large lists itself; 25 is always accepted


class Quantity(enum.StrEnum):
    POWER = "power"
    ENERGY = "energy"
    APPARENT_ENERGY = "apparent_energy"
    REACTIVE_ENERGY = "reactive_energy"
    POWER_FACTOR = "power_factor"
    OTHER = "other"


class Statistic(enum.StrEnum):
    INSTANTANEOUS = "instantaneous"
    MAXIMUM = "maximum"
    SUMMATION = "summation"
    TOU_SUMMATION = "tou_summation"
    INTERVAL = "interval"
    OTHER = "other"


class Direction(enum.StrEnum):
    DELIVERED = "delivered"  # grid -> customer (import)
    RECEIVED = "received"  # customer -> grid (export)
    NET = "net"
    NONE = "none"


_QUANTITY_BY_UOM = {
    Uom.WATT: Quantity.POWER,
    Uom.WATT_HOUR: Quantity.ENERGY,
    Uom.VOLT_AMPERE_HOUR: Quantity.APPARENT_ENERGY,
    Uom.VAR_HOUR: Quantity.REACTIVE_ENERGY,
    Uom.POWER_FACTOR: Quantity.POWER_FACTOR,
}

_DIRECTION = {
    FlowDirection.DELIVERED: Direction.DELIVERED,
    FlowDirection.RECEIVED: Direction.RECEIVED,
    FlowDirection.NET: Direction.NET,
}


def classify(rt: ReadingType) -> tuple[Quantity, Statistic, Direction]:
    quantity = _QUANTITY_BY_UOM.get(rt.uom, Quantity.OTHER)
    direction = _DIRECTION.get(rt.flow_direction, Direction.NONE)
    if rt.accumulation == Accumulation.DELTA and rt.interval_length:
        statistic = Statistic.INTERVAL
    elif rt.accumulation == Accumulation.SUMMATION:
        statistic = Statistic.TOU_SUMMATION if rt.tou_tiers > 0 else Statistic.SUMMATION
    elif rt.data_qualifier == DataQualifier.MAXIMUM:
        statistic = Statistic.MAXIMUM
    elif rt.accumulation == Accumulation.INSTANTANEOUS or rt.kind in (Kind.DEMAND, Kind.POWER):
        statistic = Statistic.INSTANTANEOUS
    else:
        statistic = Statistic.OTHER
    return quantity, statistic, direction


@dataclass(frozen=True, slots=True)
class Channel:
    """One classified MeterReading and where to read it."""

    key: str  # stable, human-readable, unique within a profile
    description: str | None
    meter_reading_href: str
    reading_type: ReadingType
    quantity: Quantity
    statistic: Statistic
    direction: Direction
    phase: int
    reading_href: str | None
    reading_set_list_href: str | None
    # For ToU registers: the ReadingList holding one Reading per tier.
    tou_reading_list_href: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "description": self.description,
            "meter_reading_href": self.meter_reading_href,
            "reading_type": self.reading_type.to_dict(),
            "reading_href": self.reading_href,
            "reading_set_list_href": self.reading_set_list_href,
            "tou_reading_list_href": self.tou_reading_list_href,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Channel:
        rt = ReadingType.from_dict(d["reading_type"])
        q, s, dirn = classify(rt)
        return cls(
            key=d["key"],
            description=d.get("description"),
            meter_reading_href=d["meter_reading_href"],
            reading_type=rt,
            quantity=q,
            statistic=s,
            direction=dirn,
            phase=rt.phase,
            reading_href=d.get("reading_href"),
            reading_set_list_href=d.get("reading_set_list_href"),
            tou_reading_list_href=d.get("tou_reading_list_href"),
        )


@dataclass(frozen=True, slots=True)
class MeterProfile:
    """Everything discovery learned. Cache it with :meth:`to_dict` to skip
    rediscovery (~30 GETs) on restart; rediscover on ``MeterNotFound``."""

    host: str
    port: int
    meter_lfdi: str | None
    meter_sfdi: str | None
    manufacturer_id: int | None
    software_version: str | None
    time_href: str | None
    usage_point_href: str
    poll_rate: int | None
    channels: tuple[Channel, ...] = field(default_factory=tuple)
    device_information_href: str | None = None

    def find(
        self,
        quantity: Quantity,
        statistic: Statistic,
        direction: Direction | None = None,
        *,
        phase: int | None = None,
    ) -> Channel | None:
        """The first channel matching, or None. ``phase=None`` prefers the
        whole-meter channel (phase 0 or the all-phases value 224)."""
        matches = [
            c
            for c in self.channels
            if c.quantity == quantity
            and c.statistic == statistic
            and (direction is None or c.direction == direction)
            and (phase is None or c.phase == phase)
        ]
        if phase is None:
            matches.sort(key=lambda c: 0 if c.phase in (0, 224) else 1)
        return matches[0] if matches else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": PROFILE_VERSION,
            "host": self.host,
            "port": self.port,
            "meter_lfdi": self.meter_lfdi,
            "meter_sfdi": self.meter_sfdi,
            "manufacturer_id": self.manufacturer_id,
            "software_version": self.software_version,
            "time_href": self.time_href,
            "usage_point_href": self.usage_point_href,
            "poll_rate": self.poll_rate,
            "device_information_href": self.device_information_href,
            "channels": [c.to_dict() for c in self.channels],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MeterProfile:
        if d.get("version") != PROFILE_VERSION:
            raise ValueError(f"unsupported profile version {d.get('version')!r}")
        return cls(
            host=d["host"],
            port=d["port"],
            meter_lfdi=d.get("meter_lfdi"),
            meter_sfdi=d.get("meter_sfdi"),
            manufacturer_id=d.get("manufacturer_id"),
            software_version=d.get("software_version"),
            time_href=d.get("time_href"),
            usage_point_href=d["usage_point_href"],
            poll_rate=d.get("poll_rate"),
            channels=tuple(Channel.from_dict(c) for c in d["channels"]),
            device_information_href=d.get("device_information_href"),
        )


def _paged(href: str, start: int, limit: int) -> str:
    sep = "&" if "?" in href else "?"
    return f"{href}{sep}s={start}&l={limit}"


async def get_list(
    batch: Batch, href: str, item: str, *, start: int = 0, limit: int | None = None
) -> tuple[ListPage, list[Any]]:
    """GET every page of a 2030.5 list from ``start`` (or at most ``limit`` items)."""
    items: list[Any] = []
    page: ListPage | None = None
    while True:
        want = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - len(items))
        root = parse_xml(await batch.get(_paged(href, start, want)))
        if not local_name(root.tag).endswith("List"):
            raise MeterProtocolError(f"{href} is not a list (<{local_name(root.tag)}>)")
        page = ListPage.of(root)
        got = children(root, item)
        items.extend(got)
        start += len(got)
        if not got or start >= page.all or (limit is not None and len(items) >= limit):
            return page, items


def _channel_key(q: Quantity, s: Statistic, d: Direction, phase: int, taken: set[str]) -> str:
    parts = [q.value]
    if s != Statistic.INSTANTANEOUS:
        parts.append(s.value)
        if d != Direction.NONE:
            parts.append(d.value)
    # Instantaneous values carry no direction in the key: Itron's "Instantaneous
    # Demand" is flowDirection=1 yet signed (negative while exporting).
    if phase not in (0, 224):
        parts.append({128: "phase_a", 64: "phase_b", 32: "phase_c"}.get(phase, f"phase_{phase}"))
    key = "_".join(parts)
    n = 2
    while key in taken:
        key = f"{'_'.join(parts)}_{n}"
        n += 1
    taken.add(key)
    return key


async def discover(batch: Batch, host: str, port: int) -> MeterProfile:
    dcap = DeviceCapability.from_xml(parse_xml(await batch.get("/dcap")))
    if not dcap.usage_point_list_href:
        raise MeterProtocolError("DeviceCapability has no UsagePointListLink")

    lfdi = sfdi = sw = info_href = None
    mfid = None
    if dcap.self_device_href:
        sdev = SelfDevice.from_xml(parse_xml(await batch.get(dcap.self_device_href)))
        sfdi, lfdi, info_href = sdev.sfdi, sdev.lfdi, sdev.device_information_href
        if info_href:
            info = DeviceInformation.from_xml(parse_xml(await batch.get(info_href)))
            lfdi = info.lfdi or lfdi
            sw, mfid = info.software_version, info.manufacturer_id

    upt_page_root = parse_xml(await batch.get(_paged(dcap.usage_point_list_href, 0, PAGE_SIZE)))
    poll_rate = upt_page_root.get("pollRate")
    points = [UsagePoint.from_xml(e) for e in children(upt_page_root, "UsagePoint")]
    # serviceCategoryKind 0 = electricity; fall back to the first usage point.
    point = next((p for p in points if p.service_category in (0, None) and p.meter_reading_list_href), None)
    if point is None or not point.meter_reading_list_href:
        raise MeterProtocolError("no electricity UsagePoint with a MeterReadingListLink")

    _, mr_elems = await get_list(batch, point.meter_reading_list_href, "MeterReading")
    infos = [MeterReadingInfo.from_xml(e) for e in mr_elems]

    channels: list[Channel] = []
    taken: set[str] = set()
    for mr in sorted(infos, key=_href_order):
        if not mr.reading_type_href:
            continue
        rt = ReadingType.from_xml(parse_xml(await batch.get(mr.reading_type_href)))
        q, s, d = classify(rt)
        tou_list = None
        if s == Statistic.TOU_SUMMATION and mr.reading_set_list_href:
            _, sets = await get_list(batch, mr.reading_set_list_href, "ReadingSet", limit=1)
            if sets:
                tou_list = ReadingSetInfo.from_xml(sets[0]).reading_list_href
        channels.append(
            Channel(
                key=_channel_key(q, s, d, rt.phase, taken),
                description=mr.description,
                meter_reading_href=mr.href,
                reading_type=rt,
                quantity=q,
                statistic=s,
                direction=d,
                phase=rt.phase,
                reading_href=mr.reading_href,
                reading_set_list_href=mr.reading_set_list_href,
                tou_reading_list_href=tou_list,
            )
        )

    return MeterProfile(
        host=host,
        port=port,
        meter_lfdi=lfdi,
        meter_sfdi=sfdi,
        manufacturer_id=mfid,
        software_version=sw,
        time_href=dcap.time_href,
        usage_point_href=point.href,
        poll_rate=int(poll_rate) if poll_rate and poll_rate.isdigit() else None,
        channels=tuple(channels),
        device_information_href=info_href,
    )


def _href_order(info: MeterReadingInfo) -> tuple[int, str]:
    tail = info.href.rstrip("/").rsplit("/", 1)[-1]
    return (int(tail), info.href) if tail.isdigit() else (1 << 30, info.href)
