"""Meter discovery and the cacheable MeterProfile.

Discovery walks DeviceCapability -> SelfDevice -> UsagePointList ->
MeterReadingList -> ReadingTypes on ONE connection and classifies every
MeterReading, so consumers ask for "energy delivered" instead of
hard-coding ``/upt/1/mr/3`` (numbering differs between agent versions).

Channel keys are part of the public API (consumers build entity IDs from
them) and are pinned by tests against real agent captures. A key is
derived from what a channel *is* -- quantity, statistic, direction, phase
-- never from its position in a list.
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from .exceptions import MeterProtocolError, ProfileError
from .identity import sfdi_from_lfdi
from .models import (
    Accumulation,
    DataQualifier,
    DeviceCapability,
    DeviceInformation,
    FlowDirection,
    Kind,
    ListPage,
    MeterReadingInfo,
    Reading,
    ReadingSetInfo,
    ReadingType,
    RoleFlags,
    SelfDevice,
    Uom,
    UsagePoint,
    children,
    local_name,
    parse_xml,
)
from .transport import Batch

_LOGGER = logging.getLogger(__name__)

PROFILE_VERSION = 3
ITRON_PEN = 1233  # DeviceInformation.mfID: the vendor's IANA enterprise number
# Bump whenever classify() or the key format changes in a way that could
# change an existing channel's key; cached profiles from another scheme are
# rejected so the consumer rediscovers (and can map old keys to new ones).
KEY_SCHEME = 1
PAGE_SIZE = 25  # the Itron agent pages large lists itself; 25 is always accepted
DEFAULT_POLL_RATE = 900  # IEEE 2030.5 default when a list omits pollRate


class Quantity(enum.StrEnum):
    POWER = "power"
    ENERGY = "energy"
    APPARENT_POWER = "apparent_power"
    APPARENT_ENERGY = "apparent_energy"
    REACTIVE_POWER = "reactive_power"
    REACTIVE_ENERGY = "reactive_energy"
    POWER_FACTOR = "power_factor"
    VOLTAGE = "voltage"
    CURRENT = "current"
    FREQUENCY = "frequency"
    OTHER = "other"


class Statistic(enum.StrEnum):
    INSTANTANEOUS = "instantaneous"
    MAXIMUM = "maximum"
    MINIMUM = "minimum"
    CUMULATIVE = "cumulative"
    SUMMATION = "summation"
    TOU_SUMMATION = "tou_summation"
    INTERVAL = "interval"
    OTHER = "other"


class Direction(enum.StrEnum):
    DELIVERED = "delivered"  # grid -> customer (import)
    RECEIVED = "received"  # customer -> grid (export)
    NET = "net"
    TOTAL = "total"
    NONE = "none"


_QUANTITY_BY_UOM = {
    Uom.WATT: Quantity.POWER,
    Uom.WATT_HOUR: Quantity.ENERGY,
    Uom.VOLT_AMPERE: Quantity.APPARENT_POWER,
    Uom.VOLT_AMPERE_HOUR: Quantity.APPARENT_ENERGY,
    Uom.VAR: Quantity.REACTIVE_POWER,
    Uom.VAR_HOUR: Quantity.REACTIVE_ENERGY,
    Uom.POWER_FACTOR: Quantity.POWER_FACTOR,
    Uom.VOLT: Quantity.VOLTAGE,
    Uom.AMPERE: Quantity.CURRENT,
    Uom.HERTZ: Quantity.FREQUENCY,
}

_DIRECTION = {
    FlowDirection.DELIVERED: Direction.DELIVERED,
    FlowDirection.RECEIVED: Direction.RECEIVED,
    FlowDirection.NET: Direction.NET,
    FlowDirection.TOTAL: Direction.TOTAL,
}

_PHASES = {
    128: "phase_a",
    64: "phase_b",
    32: "phase_c",
    129: "phase_an",
    65: "phase_bn",
    33: "phase_cn",
    132: "phase_ab",
    66: "phase_bc",
    40: "phase_ca",
}
WHOLE_METER_PHASES = (0, 224)


def classify(
    rt: ReadingType, description: str | None = None, *, itron: bool = True
) -> tuple[Quantity, Statistic, Direction]:
    """What a MeterReading measures, from its ReadingType -- and, for Itron
    agents (``itron``), its description breaking ties the ReadingType leaves
    open.

    Description rules exist because Itron agents publish ReadingTypes that
    are not distinguishable on their own: before 3.2.50 the ToU and plain
    summation registers have identical ReadingTypes, and older v3 agents
    give "WH Net (Interval)" flowDirection 1 (delivered). Itron's own SDK
    tells them apart by description the same way. Descriptions are free text,
    so other vendors' are not interpreted.
    """
    quantity = _QUANTITY_BY_UOM.get(Uom(rt.uom), Quantity.OTHER)
    direction = _DIRECTION.get(FlowDirection(rt.flow_direction), Direction.NONE)
    if rt.accumulation == Accumulation.DELTA and rt.interval_length:
        statistic = Statistic.INTERVAL
    elif rt.accumulation == Accumulation.SUMMATION:
        statistic = Statistic.TOU_SUMMATION if rt.tou_tiers > 0 else Statistic.SUMMATION
    elif rt.accumulation == Accumulation.CUMULATIVE:
        statistic = Statistic.CUMULATIVE
    elif rt.data_qualifier == DataQualifier.MAXIMUM:
        statistic = Statistic.MAXIMUM
    elif rt.data_qualifier == DataQualifier.MINIMUM:
        statistic = Statistic.MINIMUM
    elif rt.accumulation == Accumulation.INSTANTANEOUS or rt.kind in (Kind.DEMAND, Kind.POWER):
        statistic = Statistic.INSTANTANEOUS
    else:
        statistic = Statistic.OTHER

    if description and itron:
        words = set(re.findall(r"[a-z]+", description.lower()))
        if statistic in (Statistic.SUMMATION, Statistic.TOU_SUMMATION):
            if "tou" in words:
                statistic = Statistic.TOU_SUMMATION
            elif "summation" in words:
                statistic = Statistic.SUMMATION
        if statistic == Statistic.INSTANTANEOUS and quantity == Quantity.POWER:
            # v1/v2 agents tag every demand dataQualifier 2 (average).
            if words & {"max", "maximum"}:
                statistic = Statistic.MAXIMUM
            elif words & {"min", "minimum"}:
                statistic = Statistic.MINIMUM
        # "Net" only overrides a direction the ReadingType leaves vague
        # (none, or delivered as older agents mislabel it), and only when the
        # description names no other direction ("Net Metering Delivered").
        if (
            "net" in words
            and direction in (Direction.NONE, Direction.DELIVERED)
            and not words & {"delivered", "received"}
        ):
            direction = Direction.NET
    return quantity, statistic, direction


@dataclass(frozen=True, slots=True)
class Channel:
    """One classified MeterReading and where to read it."""

    key: str  # stable, human-readable, unique within a profile (see module doc)
    mrid: str | None  # the meter's own identifier for the MeterReading
    description: str | None
    meter_reading_href: str
    reading_type: ReadingType
    quantity: Quantity
    statistic: Statistic
    direction: Direction
    phase: int
    reading_href: str | None
    reading_set_list_href: str | None
    # For ToU registers: the ReadingList holding one Reading per tier, and
    # the tiers that held a value at discovery (Itron: tier 0 is the total).
    tou_reading_list_href: str | None = None
    tou_tiers: tuple[int, ...] = ()
    # Another channel classified identically, so this key carries a _N
    # suffix that depends on mRIDs -- treat as unstable (a classifier gap).
    ambiguous: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "quantity": self.quantity.value,
            "statistic": self.statistic.value,
            "direction": self.direction.value,
            "ambiguous": self.ambiguous,
            "mrid": self.mrid,
            "description": self.description,
            "meter_reading_href": self.meter_reading_href,
            "reading_type": self.reading_type.to_dict(),
            "reading_href": self.reading_href,
            "reading_set_list_href": self.reading_set_list_href,
            "tou_reading_list_href": self.tou_reading_list_href,
            "tou_tiers": list(self.tou_tiers),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Channel:
        # The classification is restored as stored, never recomputed: a key
        # must keep meaning what it meant when it was assigned.
        rt = ReadingType.from_dict(d["reading_type"])
        return cls(
            key=d["key"],
            mrid=d.get("mrid"),
            description=d.get("description"),
            meter_reading_href=d["meter_reading_href"],
            reading_type=rt,
            quantity=Quantity(d["quantity"]),
            statistic=Statistic(d["statistic"]),
            direction=Direction(d["direction"]),
            phase=rt.phase,
            reading_href=d.get("reading_href"),
            reading_set_list_href=d.get("reading_set_list_href"),
            tou_reading_list_href=d.get("tou_reading_list_href"),
            tou_tiers=tuple(d.get("tou_tiers") or ()),
            ambiguous=bool(d.get("ambiguous", False)),
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
    poll_rate: int
    channels: tuple[Channel, ...] = field(default_factory=tuple)
    device_information_href: str | None = None
    # LFDI of the TLS certificate seen during discovery: the identity to pin
    # (Meter(expected_lfdi=)). Equal to meter_lfdi on a conforming agent.
    certificate_lfdi: str | None = None

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
            matches.sort(key=lambda c: 0 if c.phase in WHOLE_METER_PHASES else 1)
        return matches[0] if matches else None

    def channel(self, key: str) -> Channel | None:
        return next((c for c in self.channels if c.key == key), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": PROFILE_VERSION,
            "key_scheme": KEY_SCHEME,
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
            "certificate_lfdi": self.certificate_lfdi,
            "channels": [c.to_dict() for c in self.channels],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MeterProfile:
        """Raises :class:`ProfileError` for another version or a malformed dict."""
        if not isinstance(d, dict) or d.get("version") != PROFILE_VERSION or d.get("key_scheme") != KEY_SCHEME:
            got = (d.get("version"), d.get("key_scheme")) if isinstance(d, dict) else d
            raise ProfileError(f"unsupported profile (version, key scheme) {got!r}")
        pin = d.get("certificate_lfdi")
        if pin is not None and (not isinstance(pin, str) or not re.fullmatch(r"[0-9A-F]{40}", pin)):
            raise ProfileError(f"malformed certificate_lfdi {pin!r}")
        try:
            return cls(
                host=d["host"],
                port=d["port"],
                meter_lfdi=d.get("meter_lfdi"),
                meter_sfdi=d.get("meter_sfdi"),
                manufacturer_id=d.get("manufacturer_id"),
                software_version=d.get("software_version"),
                time_href=d.get("time_href"),
                usage_point_href=d["usage_point_href"],
                poll_rate=int(d.get("poll_rate") or DEFAULT_POLL_RATE),
                channels=tuple(Channel.from_dict(c) for c in d["channels"]),
                device_information_href=d.get("device_information_href"),
                certificate_lfdi=d.get("certificate_lfdi"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as err:
            raise ProfileError(f"malformed profile: {err!r}") from err


# -- links --------------------------------------------------------------------


def resolve_href(base: str, href: str, host: str, port: int) -> str:
    """Resolve a link from the resource at ``base`` to an origin-form target.

    2030.5 links may be relative or absolute URIs. Relative ones resolve
    against the resource they came from. An absolute one must be HTTP(S) on
    the meter's port; its host is not compared, since a server may name
    itself differently from the address we connected to (a hostname, another
    of its addresses). Only the path is used, and it is requested on our own
    connection -- the one whose certificate is pinned -- so nothing is ever
    sent elsewhere. A link to another port is a protocol error.
    """
    bare = host.strip("[]").split("%", 1)[0].lower()  # IPv6 literal without zone
    origin = f"https://[{bare}]:{port}" if ":" in bare else f"https://{bare}:{port}"
    try:
        parts = urlsplit(urljoin(origin + base, href.strip()))
        link_port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as err:  # bad port, unbalanced brackets, ...
        raise MeterProtocolError(f"malformed link from meter: {href!r}") from err
    if parts.scheme not in ("https", "http") or not parts.hostname or link_port != port:
        raise MeterProtocolError(f"link to another server: {href!r}")
    return parts.path + (f"?{parts.query}" if parts.query else "")


def _paged(href: str, start: int, limit: int) -> str:
    sep = "&" if "?" in href else "?"
    return f"{href}{sep}s={start}&l={limit}"


async def get_list(
    batch: Batch, href: str, item: str, *, start: int = 0, limit: int | None = None
) -> tuple[ListPage, list[Any]]:
    """GET every page of a 2030.5 list from ``start`` (or at most ``limit`` items).

    Pages are followed by the count actually returned and the list's own
    ``all``: agents return short pages, and a Kitu-based agent's
    ``ReadingListLink@all`` is stale until the list is fetched once.
    """
    items: list[Any] = []
    page: ListPage | None = None
    seen: set[str] = set()
    while True:
        want = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - len(items))
        root = parse_xml(await batch.get(_paged(href, start, want)))
        if not local_name(root.tag).endswith("List"):
            raise MeterProtocolError(f"{href} is not a list (<{local_name(root.tag)}>)")
        page = ListPage.of(root)
        got = [e for e in children(root, item) if (e.get("href") or id(e)) not in seen]
        seen.update(e.get("href") or "" for e in got)
        items.extend(got)
        start += len(got)
        if not got or start >= page.all or (limit is not None and len(items) >= limit):
            return page, items


# -- keys -----------------------------------------------------------------------


def _base_key(q: Quantity, s: Statistic, d: Direction, phase: int) -> str:
    parts = [q.value]
    if s != Statistic.INSTANTANEOUS:
        parts.append(s.value)
    if d != Direction.NONE and not (s == Statistic.INSTANTANEOUS and d == Direction.DELIVERED):
        # Instantaneous values that say "delivered" carry no direction in the
        # key: Itron's "Instantaneous Demand" is flowDirection=1 yet signed
        # (negative while exporting). Every other direction is kept.
        parts.append(d.value)
    if phase not in WHOLE_METER_PHASES:
        parts.append(_PHASES.get(phase, f"phase_{phase}"))
    return "_".join(parts)


def assign_keys(entries: list[tuple[MeterReadingInfo, Quantity, Statistic, Direction, int]]) -> list[tuple[str, bool]]:
    """Keys for classified MeterReadings, in input order.

    Channels that classify identically get ``_2``, ``_3``... in order of their
    mRID (the meter's stable identifier), falling back to href -- never in
    order of list position.
    """
    groups: dict[str, list[int]] = {}
    for i, (_, q, s, d, phase) in enumerate(entries):
        groups.setdefault(_base_key(q, s, d, phase), []).append(i)
    keys: list[tuple[str, bool]] = [("", False)] * len(entries)
    for base, idxs in groups.items():
        idxs.sort(key=lambda i: (entries[i][0].mrid or "", _href_order(entries[i][0])))
        ambiguous = len(idxs) > 1
        if ambiguous:
            _LOGGER.warning(
                "%d meter readings classify as %r (%s); their keys depend on mRID order",
                len(idxs),
                base,
                ", ".join(entries[i][0].description or entries[i][0].href for i in idxs),
            )
        for n, i in enumerate(idxs):
            keys[i] = (base if n == 0 else f"{base}_{n + 1}", ambiguous)
    return keys


def _href_order(info: MeterReadingInfo) -> tuple[int, str]:
    tail = info.href.rstrip("/").rsplit("/", 1)[-1]
    return (int(tail), info.href) if tail.isdigit() else (1 << 30, info.href)


def _rank_usage_point(p: UsagePoint) -> tuple[int, int, int, int]:
    """Lower is better: a real (non-mirror) electricity meter that is on,
    preferably the premises aggregation point."""
    return (
        0 if p.service_category in (0, None) else 1,
        0 if not p.role_flags & RoleFlags.IS_MIRROR else 1,
        0 if p.status in (1, None) else 1,
        0 if p.role_flags & RoleFlags.IS_PREMISES_AGGREGATION_POINT else 1,
    )


# -- discovery ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MeterInfo:
    """Who the meter says it is (DeviceCapability, SelfDevice and
    DeviceInformation), and the identity its certificate proves."""

    lfdi: str | None  # as the meter reports it
    sfdi: str | None
    certificate_lfdi: str | None  # SHA-256 of its TLS certificate: the one to trust
    manufacturer_id: int | None
    model: str | None
    serial_number: str | None
    hardware_version: str | None
    software_version: str | None
    dcap_path: str
    time_href: str | None = None
    usage_point_list_href: str | None = None
    device_information_href: str | None = None

    @property
    def certificate_sfdi(self) -> str | None:
        return sfdi_from_lfdi(self.certificate_lfdi) if self.certificate_lfdi else None

    def to_dict(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MeterInfo:
        fields: dict[str, Any] = {f: d.get(f) for f in cls.__dataclass_fields__}
        fields["dcap_path"] = fields["dcap_path"] or "/dcap"
        return cls(**fields)


async def read_meter_info(batch: Batch, host: str, port: int, *, dcap_path: str = "/dcap") -> MeterInfo:
    """DeviceCapability, SelfDevice and DeviceInformation: 1-3 GETs."""

    def resolve(base: str, href: str) -> str:
        return resolve_href(base, href, host, port)

    dcap_path = resolve("/", dcap_path)
    dcap = DeviceCapability.from_xml(parse_xml(await batch.get(dcap_path)))
    lfdi = sfdi = info_href = None
    info: DeviceInformation | None = None
    if dcap.self_device_href:
        sdev_href = resolve(dcap_path, dcap.self_device_href)
        sdev = SelfDevice.from_xml(parse_xml(await batch.get(sdev_href)))
        sfdi, lfdi = sdev.sfdi, sdev.lfdi
        if sdev.device_information_href:
            info_href = resolve(sdev_href, sdev.device_information_href)
            info = DeviceInformation.from_xml(parse_xml(await batch.get(info_href)))
            lfdi = info.lfdi or lfdi
    return MeterInfo(
        lfdi=lfdi.upper() if lfdi else None,
        sfdi=sfdi,
        certificate_lfdi=batch.peer.lfdi if batch.peer else None,
        manufacturer_id=info.manufacturer_id if info else None,
        model=(info.model or None) if info else None,
        serial_number=(info.serial_number or None) if info else None,
        hardware_version=(info.hardware_version or None) if info else None,
        software_version=info.software_version if info else None,
        dcap_path=dcap_path,
        time_href=resolve(dcap_path, dcap.time_href) if dcap.time_href else None,
        usage_point_list_href=resolve(dcap_path, dcap.usage_point_list_href) if dcap.usage_point_list_href else None,
        device_information_href=info_href,
    )


async def discover(batch: Batch, host: str, port: int, *, dcap_path: str = "/dcap") -> MeterProfile:
    """Walk the meter's resource tree. ``dcap_path`` comes from the DNS-SD
    TXT record ``dcap`` when the meter was found by mDNS."""

    def resolve(base: str, href: str) -> str:
        return resolve_href(base, href, host, port)

    meter = await read_meter_info(batch, host, port, dcap_path=dcap_path)
    if not meter.usage_point_list_href:
        raise MeterProtocolError("DeviceCapability has no UsagePointListLink")
    upt_href = meter.usage_point_list_href
    time_href = meter.time_href
    lfdi, sfdi, sw, mfid, info_href = (
        meter.lfdi,
        meter.sfdi,
        meter.software_version,
        meter.manufacturer_id,
        meter.device_information_href,
    )

    page, upt_elems = await get_list(batch, upt_href, "UsagePoint")
    points = sorted((UsagePoint.from_xml(e) for e in upt_elems), key=_rank_usage_point)
    point = next((p for p in points if p.meter_reading_list_href), None)
    if point is None or point.meter_reading_list_href is None:
        raise MeterProtocolError("no UsagePoint with a MeterReadingListLink")
    point_href = resolve(upt_href, point.href) if point.href else upt_href
    mr_list_href = resolve(point_href, point.meter_reading_list_href)

    _, mr_elems = await get_list(batch, mr_list_href, "MeterReading")
    infos = sorted((MeterReadingInfo.from_xml(e) for e in mr_elems), key=_href_order)

    classified = []
    for mr in infos:
        if not mr.reading_type_href:
            continue
        mr_href = resolve(mr_list_href, mr.href) if mr.href else mr_list_href
        rt = ReadingType.from_xml(parse_xml(await batch.get(resolve(mr_href, mr.reading_type_href))))
        q, s, d = classify(rt, mr.description, itron=meter.manufacturer_id == ITRON_PEN)
        set_list_href = resolve(mr_href, mr.reading_set_list_href) if mr.reading_set_list_href else None
        tou_list: str | None = None
        tiers: tuple[int, ...] = ()
        if s == Statistic.TOU_SUMMATION:
            tagged = False
            if set_list_href:
                try:
                    tou_list, tiers, tagged = await _discover_tou(batch, set_list_href, host, port)
                except MeterProtocolError as err:  # incl. 404: an optional resource
                    _LOGGER.warning("%s: cannot read its ToU tiers (%s); treating it as a plain register", mr_href, err)
            if not tagged:
                # Only readings tagged with a touTier make a ToU register: a
                # ReadingType or a description saying so is not enough.
                s, tou_list, tiers = Statistic.SUMMATION, None, ()
        classified.append((mr, mr_href, rt, q, s, d, set_list_href, tou_list, tiers))

    if not classified:
        raise MeterProtocolError(f"{mr_list_href} lists no MeterReading with a ReadingType: nothing to read")
    keys = assign_keys([(mr, q, s, d, rt.phase) for mr, _, rt, q, s, d, *_ in classified])
    channels: list[Channel] = []
    for (key, ambiguous), (mr, mr_href, rt, q, s, d, set_list_href, tou_list, tiers) in zip(
        keys, classified, strict=True
    ):
        reading_href = resolve(mr_href, mr.reading_href) if mr.reading_href else None
        channels.append(
            Channel(
                key=key,
                mrid=mr.mrid,
                description=mr.description,
                meter_reading_href=mr_href,
                reading_type=rt,
                quantity=q,
                statistic=s,
                direction=d,
                phase=rt.phase,
                reading_href=reading_href,
                reading_set_list_href=set_list_href,
                tou_reading_list_href=tou_list,
                tou_tiers=tiers,
                ambiguous=ambiguous,
            )
        )

    return MeterProfile(
        host=host,
        port=port,
        meter_lfdi=lfdi,
        meter_sfdi=sfdi,
        manufacturer_id=mfid,
        software_version=sw,
        time_href=time_href,
        usage_point_href=point_href,
        poll_rate=page.poll_rate or DEFAULT_POLL_RATE,
        channels=tuple(channels),
        device_information_href=info_href,
    )


async def _discover_tou(
    batch: Batch, set_list_href: str, host: str, port: int
) -> tuple[str | None, tuple[int, ...], bool]:
    """The ToU tier ReadingList, the tiers in use (holding a value), and
    whether any reading carries a touTier at all."""
    _, sets = await get_list(batch, set_list_href, "ReadingSet", limit=1)
    if not sets:
        return None, (), False
    rs = ReadingSetInfo.from_xml(sets[0])
    if not rs.reading_list_href:
        return None, (), False
    rs_href = resolve_href(set_list_href, rs.href, host, port) if rs.href else set_list_href
    list_href = resolve_href(rs_href, rs.reading_list_href, host, port)
    _, elems = await get_list(batch, list_href, "Reading")
    readings = [Reading.from_xml(e) for e in elems]
    tiers = tuple(sorted({r.tou_tier for r in readings if r.tou_tier is not None and r.raw_value is not None}))
    return list_href, tiers, any(r.tou_tier is not None for r in readings)
