"""IEEE 2030.5 metering resources as plain, frozen dataclasses.

Only the subset a HAN metering client needs: DeviceCapability, Time,
DeviceInformation, UsagePoint, MeterReading, ReadingType, Reading and
ReadingSet. Parsing is namespace-agnostic and tolerant: absent elements
become ``None`` rather than errors, because real agents omit fields freely
(an Itron agent returns ``<Reading/>`` with no value for an unused phase).
"""

from __future__ import annotations

import enum
import itertools
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .exceptions import MeterProtocolError, ProfileError


class Uom(enum.IntEnum):
    """UomType values seen on metering endpoints (2030.5 Table 'UomType')."""

    UNKNOWN = 0
    POWER_FACTOR = 65  # cos(theta)
    WATT = 38
    WATT_HOUR = 72
    VOLT_AMPERE_HOUR = 71
    VAR_HOUR = 73
    VOLT_AMPERE = 61
    VAR = 63
    VOLT = 29
    AMPERE = 5
    HERTZ = 33

    @classmethod
    def _missing_(cls, value: object) -> Uom:
        return cls.UNKNOWN


class FlowDirection(enum.IntEnum):
    """Direction of energy flow relative to the customer."""

    NOT_APPLICABLE = 0
    DELIVERED = 1  # utility -> customer (import)
    RECEIVED = 19  # customer -> utility (export)
    # Not in sep.xsd ("all other values reserved"), but IEC 61968-9 values
    # that Itron agents use.
    NET = 4  # delivered minus received
    TOTAL = 20  # delivered plus received

    @classmethod
    def _missing_(cls, value: object) -> FlowDirection:
        return cls.NOT_APPLICABLE


class Accumulation(enum.IntEnum):
    """accumulationBehaviour: how a reading's value accumulates over time."""

    NOT_APPLICABLE = 0
    CUMULATIVE = 3
    DELTA = 4  # per-interval values (interval data)
    INDICATING = 6
    SUMMATION = 9  # ever-increasing register
    INSTANTANEOUS = 12

    @classmethod
    def _missing_(cls, value: object) -> Accumulation:
        return cls.NOT_APPLICABLE


class DataQualifier(enum.IntEnum):
    NOT_APPLICABLE = 0
    AVERAGE = 2
    MAXIMUM = 8
    MINIMUM = 9
    NORMAL = 12

    @classmethod
    def _missing_(cls, value: object) -> DataQualifier:
        return cls.NOT_APPLICABLE


class Kind(enum.IntEnum):
    NOT_APPLICABLE = 0
    CURRENCY = 3
    DEMAND = 8
    ENERGY = 12
    POWER = 37

    @classmethod
    def _missing_(cls, value: object) -> Kind:
        return cls.NOT_APPLICABLE


UNIT_SYMBOLS: dict[Uom, str] = {
    Uom.WATT: "W",
    Uom.WATT_HOUR: "Wh",
    Uom.VOLT_AMPERE_HOUR: "VAh",
    Uom.VAR_HOUR: "varh",
    Uom.VOLT_AMPERE: "VA",
    Uom.VAR: "var",
    Uom.VOLT: "V",
    Uom.AMPERE: "A",
    Uom.HERTZ: "Hz",
    Uom.POWER_FACTOR: "",
}


# -- XML helpers --------------------------------------------------------------


_DOCTYPE = ("<!DOCTYPE", "<!ENTITY")
_DOCTYPE_BYTES = tuple(m.encode(enc) for m in _DOCTYPE for enc in ("ascii", "utf-16-le", "utf-16-be"))
MAX_TEXT = 1024  # no 2030.5 text element is longer than a few dozen characters


def parse_xml(body: bytes | str) -> ET.Element:
    """Parse a resource. A document type declaration is refused outright: no
    2030.5 resource has one, and internal entities would let a device inflate
    a capped response by orders of magnitude."""
    if any(m in body for m in (_DOCTYPE if isinstance(body, str) else _DOCTYPE_BYTES)):  # type: ignore[operator]
        raise MeterProtocolError("XML from meter has a document type declaration")
    try:
        return ET.fromstring(body)
    except ET.ParseError as err:
        raise MeterProtocolError(f"malformed XML from meter: {err}") from err


def short(value: object, limit: int = 64) -> str:
    """Device text for an error message: repr'd and cut to ``limit`` characters."""
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child(elem: ET.Element, name: str) -> ET.Element | None:
    for c in elem:
        if local_name(c.tag) == name:
            return c
    return None


def children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem if local_name(c.tag) == name]


def text(elem: ET.Element, name: str) -> str | None:
    """A child element's text, stripped and at most ``MAX_TEXT`` characters."""
    c = child(elem, name)
    if c is None or c.text is None:
        return None
    t = c.text.strip()[:MAX_TEXT]
    return t or None


def int_or_none(elem: ET.Element, name: str) -> int | None:
    t = text(elem, name)
    if t is None:
        return None
    try:
        return int(t)
    except ValueError as err:
        raise MeterProtocolError(f"<{name}> is not an integer: {short(t)}") from err


def link(elem: ET.Element, name: str) -> str | None:
    c = child(elem, name)
    return c.get("href") if c is not None else None


def expect_root(elem: ET.Element, name: str) -> None:
    if local_name(elem.tag) != name:
        raise MeterProtocolError(f"expected <{name}>, got <{local_name(elem.tag)}>")


def epoch(value: int | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError) as err:
        raise MeterProtocolError(f"timestamp out of range: {value}") from err


def int_attr(elem: ET.Element, name: str, default: int = 0) -> int:
    raw = elem.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as err:
        raise MeterProtocolError(f"attribute {name}={short(raw)} is not an integer") from err


_HEX = re.compile(r"[0-9A-Fa-f]+")


def hex_or_none(value: str | None, what: str, digits: int = 16) -> int | None:
    """Strict hexBinary of at most ``digits`` hex digits: no sign, prefix or padding."""
    if value is None:
        return None
    if len(value) > digits or not _HEX.fullmatch(value):
        raise MeterProtocolError(f"{what} {short(value)} is not hexBinary of up to {digits} digits")
    return int(value, 16)


INT48 = 2**47  # Reading values are Int48
UINT32 = 2**32  # durations and interval lengths, in seconds


def add_seconds(start: datetime, seconds: int) -> datetime:
    """``start`` plus ``seconds``, or MeterProtocolError past the calendar's end."""
    try:
        return start + timedelta(seconds=seconds)
    except OverflowError as err:
        raise MeterProtocolError(f"{start.isoformat()} + {seconds} s is out of range") from err


def int_in_range(elem: ET.Element, name: str, lo: int, hi: int) -> int | None:
    value = int_or_none(elem, name)
    if value is not None and not lo <= value < hi:
        raise MeterProtocolError(f"<{name}> {value} out of range")
    return value


# -- resources ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ListPage:
    """Paging attributes common to every 2030.5 *List resource."""

    all: int
    results: int
    poll_rate: int | None = None  # only on lists of pollable resources

    @classmethod
    def of(cls, elem: ET.Element) -> ListPage:
        return cls(
            all=int_attr(elem, "all"),
            results=int_attr(elem, "results"),
            poll_rate=int_attr(elem, "pollRate") if elem.get("pollRate") else None,
        )


@dataclass(frozen=True, slots=True)
class DeviceCapability:
    time_href: str | None
    usage_point_list_href: str | None
    self_device_href: str | None
    end_device_list_href: str | None

    @classmethod
    def from_xml(cls, root: ET.Element) -> DeviceCapability:
        expect_root(root, "DeviceCapability")
        return cls(
            time_href=link(root, "TimeLink"),
            usage_point_list_href=link(root, "UsagePointListLink"),
            self_device_href=link(root, "SelfDeviceLink"),
            end_device_list_href=link(root, "EndDeviceListLink"),
        )


@dataclass(frozen=True, slots=True)
class MeterTime:
    current_time: datetime
    tz_offset: int
    dst_offset: int
    quality: int | None

    @classmethod
    def from_xml(cls, root: ET.Element) -> MeterTime:
        expect_root(root, "Time")
        current = epoch(int_or_none(root, "currentTime"))
        if current is None:
            raise MeterProtocolError("Time has no currentTime")
        return cls(
            current_time=current,
            tz_offset=int_or_none(root, "tzOffset") or 0,
            dst_offset=int_or_none(root, "dstOffset") or 0,
            quality=int_or_none(root, "quality"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_time": _iso(self.current_time),
            "tz_offset": self.tz_offset,
            "dst_offset": self.dst_offset,
            "quality": self.quality,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> MeterTime:
        current = _from_iso(d["current_time"])
        if current is None:
            raise ValueError("current_time is required")
        return cls(current, d.get("tz_offset", 0), d.get("dst_offset", 0), d.get("quality"))


@dataclass(frozen=True, slots=True)
class SelfDevice:
    sfdi: str | None
    lfdi: str | None
    device_information_href: str | None

    @classmethod
    def from_xml(cls, root: ET.Element) -> SelfDevice:
        expect_root(root, "SelfDevice")
        return cls(
            sfdi=_sfdi(text(root, "sFDI")),
            lfdi=text(root, "lFDI"),
            device_information_href=link(root, "DeviceInformationLink"),
        )


@dataclass(frozen=True, slots=True)
class DeviceInformation:
    lfdi: str | None
    manufacturer_id: int | None
    model: str | None
    serial_number: str | None
    hardware_version: str | None
    software_version: str | None

    @classmethod
    def from_xml(cls, root: ET.Element) -> DeviceInformation:
        expect_root(root, "DeviceInformation")
        return cls(
            lfdi=text(root, "lFDI"),
            manufacturer_id=int_or_none(root, "mfID"),
            model=text(root, "mfModel"),
            serial_number=text(root, "mfSerNum"),
            hardware_version=text(root, "mfHwVer"),
            software_version=text(root, "swVer"),
        )


class RoleFlags(enum.IntFlag):
    """UsagePoint roleFlags (HexBinary16)."""

    IS_MIRROR = 0x01
    IS_PREMISES_AGGREGATION_POINT = 0x02
    IS_PEV = 0x04
    IS_DER = 0x08
    IS_REVENUE_QUALITY = 0x10
    IS_DC = 0x20
    IS_SUBMETER = 0x40


@dataclass(frozen=True, slots=True)
class UsagePoint:
    href: str
    description: str | None
    service_category: int | None
    status: int | None
    role_flags: RoleFlags
    meter_reading_list_href: str | None

    @classmethod
    def from_xml(cls, elem: ET.Element) -> UsagePoint:
        expect_root(elem, "UsagePoint")
        return cls(
            href=elem.get("href", ""),
            description=text(elem, "description"),
            service_category=int_or_none(elem, "serviceCategoryKind"),
            status=int_or_none(elem, "status"),
            role_flags=RoleFlags(hex_or_none(text(elem, "roleFlags"), "roleFlags") or 0),
            meter_reading_list_href=link(elem, "MeterReadingListLink"),
        )


@dataclass(frozen=True, slots=True)
class MeterReadingInfo:
    """A MeterReading item: what it is called and where its data lives."""

    href: str
    mrid: str | None
    description: str | None
    reading_type_href: str | None
    reading_href: str | None
    reading_set_list_href: str | None

    @classmethod
    def from_xml(cls, elem: ET.Element) -> MeterReadingInfo:
        expect_root(elem, "MeterReading")
        return cls(
            href=elem.get("href", ""),
            mrid=text(elem, "mRID"),
            description=text(elem, "description"),
            reading_type_href=link(elem, "ReadingTypeLink"),
            reading_href=link(elem, "ReadingLink"),
            reading_set_list_href=link(elem, "ReadingSetListLink"),
        )


class QualityFlags(enum.IntFlag):
    """Reading qualityFlags (HexBinary16 bitmap, IEEE 2030.5). "00" = none set."""

    VALID = 0x01
    MANUALLY_EDITED = 0x02
    ESTIMATED_REFERENCE_DAY = 0x04
    ESTIMATED_LINEAR = 0x08
    QUESTIONABLE = 0x10
    DERIVED = 0x20
    PROJECTED = 0x40

    @property
    def is_estimated(self) -> bool:
        return bool(self & (QualityFlags.ESTIMATED_REFERENCE_DAY | QualityFlags.ESTIMATED_LINEAR))


@dataclass(frozen=True, slots=True)
class ReadingType:
    """A ReadingType with its codes kept as the meter sent them.

    The codes are plain ints, not enums, so a value this library does not
    know survives parsing and caching unchanged; compare them with the enum
    members (``rt.uom == Uom.WATT``), which are ints.
    """

    kind: int
    uom: int
    flow_direction: int
    accumulation: int
    data_qualifier: int
    power_of_ten_multiplier: int
    tou_tiers: int
    interval_length: int | None
    phase: int

    _FIELDS = (
        ("kind", "kind"),
        ("uom", "uom"),
        ("flow_direction", "flowDirection"),
        ("accumulation", "accumulationBehaviour"),
        ("data_qualifier", "dataQualifier"),
        ("power_of_ten_multiplier", "powerOfTenMultiplier"),
        ("tou_tiers", "numberOfTouTiers"),
        ("phase", "phase"),
    )

    @classmethod
    def from_xml(cls, root: ET.Element) -> ReadingType:
        expect_root(root, "ReadingType")
        values: dict[str, int | None] = {attr: int_or_none(root, tag) or 0 for attr, tag in cls._FIELDS}
        values["power_of_ten_multiplier"] = int_in_range(root, "powerOfTenMultiplier", -128, 128) or 0  # Int8
        values["interval_length"] = int_in_range(root, "intervalLength", 0, UINT32)
        return cls(**values)  # type: ignore[arg-type]

    @property
    def unit(self) -> str:
        return UNIT_SYMBOLS.get(Uom(self.uom), "")

    def scale(self, raw: int | None) -> float | None:
        """Apply powerOfTenMultiplier exactly (918 x 10^-3 is 0.918, not
        0.9180000000000001)."""
        if raw is None:
            return None
        p = self.power_of_ten_multiplier
        return float(raw * 10**p) if p >= 0 else raw / 10 ** (-p)

    def to_dict(self) -> dict[str, int | None]:
        d: dict[str, int | None] = {tag: getattr(self, attr) for attr, tag in self._FIELDS}
        d["intervalLength"] = self.interval_length
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, int | None]) -> ReadingType:
        """Restore :meth:`to_dict` output, checked like :meth:`from_xml`;
        ``ProfileError`` if it is not (a cached profile from elsewhere)."""

        def field(tag: str, lo: int, hi: int, default: int | None = 0) -> int | None:
            value = d.get(tag)
            if value is None:
                return default
            if not isinstance(value, int) or isinstance(value, bool) or not lo <= value < hi:
                raise ProfileError(f"cached ReadingType has a bad {tag}: {short(value)}")
            return value

        values: dict[str, int | None] = {
            attr: field(tag, -128, 128) if attr == "power_of_ten_multiplier" else field(tag, 0, UINT32)
            for attr, tag in cls._FIELDS
        }
        values["interval_length"] = field("intervalLength", 0, UINT32, None)
        return cls(**values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class Reading:
    """One Reading. ``raw_value`` is unscaled; ``None`` when the agent omits it."""

    href: str | None
    raw_value: int | None
    start: datetime | None
    duration: int | None
    tou_tier: int | None
    quality: QualityFlags | None
    local_id: int | None

    @classmethod
    def from_xml(cls, elem: ET.Element) -> Reading:
        expect_root(elem, "Reading")
        period = child(elem, "timePeriod")
        start = duration = None
        if period is not None:
            start = int_or_none(period, "start")
            duration = int_in_range(period, "duration", 0, UINT32)
        quality = hex_or_none(text(elem, "qualityFlags"), "qualityFlags", 4)
        return cls(
            href=elem.get("href"),
            raw_value=int_in_range(elem, "value", -INT48, INT48),
            start=epoch(start),
            duration=duration,
            tou_tier=int_in_range(elem, "touTier", 0, 256),  # UInt8
            quality=QualityFlags(quality) if quality is not None else None,
            # localID is HexBinary16 in the schema ("2F" for slot 47).
            local_id=hex_or_none(text(elem, "localID"), "localID", 4),
        )


@dataclass(frozen=True, slots=True)
class ReadingSetInfo:
    href: str
    description: str | None
    start: datetime | None
    duration: int | None
    reading_list_href: str | None
    reading_count: int | None  # unreliable on Kitu-based agents until the list is fetched once

    @classmethod
    def from_xml(cls, elem: ET.Element) -> ReadingSetInfo:
        expect_root(elem, "ReadingSet")
        period = child(elem, "timePeriod")
        start = duration = None
        if period is not None:
            start = int_or_none(period, "start")
            duration = int_in_range(period, "duration", 0, UINT32)
        rl = child(elem, "ReadingListLink")
        return cls(
            href=elem.get("href", ""),
            description=text(elem, "description"),
            start=epoch(start),
            duration=duration,
            reading_list_href=rl.get("href") if rl is not None else None,
            reading_count=int_attr(rl, "all") if rl is not None and rl.get("all") else None,
        )


# -- scaled values handed to consumers ----------------------------------------


@dataclass(frozen=True, slots=True)
class Measurement:
    """A scaled reading, ready to publish."""

    value: float | None
    unit: str
    start: datetime | None
    duration: int | None
    tou_tier: int | None = None
    uom: int = 0
    quality: QualityFlags | None = None

    @classmethod
    def of(cls, reading: Reading, reading_type: ReadingType) -> Measurement:
        return cls(
            value=reading_type.scale(reading.raw_value),
            unit=reading_type.unit,
            start=reading.start,
            duration=reading.duration,
            tou_tier=reading.tou_tier,
            uom=reading_type.uom,
            quality=reading.quality,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe (e.g. for test fixtures or diagnostics)."""
        return {
            "value": self.value,
            "unit": self.unit,
            "start": _iso(self.start),
            "duration": self.duration,
            "tou_tier": self.tou_tier,
            "uom": self.uom,
            "quality": None if self.quality is None else int(self.quality),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Measurement:
        return cls(
            value=d["value"],
            unit=d["unit"],
            start=_from_iso(d.get("start")),
            duration=d.get("duration"),
            tou_tier=d.get("tou_tier"),
            uom=d.get("uom", 0),
            quality=None if d.get("quality") is None else QualityFlags(d["quality"]),
        )


@dataclass(frozen=True, slots=True)
class IntervalValue:
    """One interval's energy: [start, end)."""

    start: datetime
    end: datetime
    value: float | None
    unit: str
    uom: int = 0
    quality: QualityFlags | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": _iso(self.start),
            "end": _iso(self.end),
            "value": self.value,
            "unit": self.unit,
            "uom": self.uom,
            "quality": None if self.quality is None else int(self.quality),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> IntervalValue:
        start, end = _from_iso(d["start"]), _from_iso(d["end"])
        if start is None or end is None:
            raise ValueError("an interval needs a start and an end")
        return cls(
            start=start,
            end=end,
            value=d["value"],
            unit=d["unit"],
            uom=d.get("uom", 0),
            quality=None if d.get("quality") is None else QualityFlags(d["quality"]),
        )


def interval_values(
    reading_set: ReadingSetInfo, readings: list[Reading], reading_type: ReadingType
) -> list[IntervalValue]:
    """Expand a ReadingSet's readings into timestamped intervals.

    A Reading's own timePeriod start wins when present. Otherwise -- the
    Itron case, where interval Readings carry no timePeriod -- slot N
    (localID, hexBinary) starts at set.start + N * intervalLength; gaps in
    localID are missing intervals (outages).
    """
    if reading_set.start is None:
        raise MeterProtocolError(f"{reading_set.href} has no timePeriod start")
    length = reading_type.interval_length
    if not length:
        raise MeterProtocolError("interval ReadingType has no intervalLength")
    set_end = add_seconds(reading_set.start, reading_set.duration) if reading_set.duration else None
    out = []
    for r in readings:
        if r.start is not None:
            start = r.start
        elif r.local_id is not None:
            start = add_seconds(reading_set.start, r.local_id * length)
        else:
            continue
        # A slot outside its own set (an agent numbering localID globally, a
        # bad value) would land data at the wrong time: drop it.
        if start < reading_set.start or (set_end is not None and start >= set_end):
            continue
        out.append(
            IntervalValue(
                start=start,
                end=add_seconds(start, r.duration or length),
                value=reading_type.scale(r.raw_value),
                unit=reading_type.unit,
                uom=reading_type.uom,
                quality=r.quality,
            )
        )
    out.sort(key=lambda v: v.start)
    return out


class TouRegister(Mapping[int, Measurement]):
    """A time-of-use summation register: ``{tier: Measurement}``.

    Tier 0 is the register's total; tiers 1..n are the rate periods (which
    period a tier is, the meter does not say). Behaves as a read-only dict.
    """

    __slots__ = ("_tiers",)

    def __init__(self, tiers: Mapping[int, Measurement]) -> None:
        self._tiers = dict(sorted(tiers.items()))

    def __getitem__(self, tier: int) -> Measurement:
        return self._tiers[tier]

    def __iter__(self) -> Iterator[int]:
        return iter(self._tiers)

    def __len__(self) -> int:
        return len(self._tiers)

    def __repr__(self) -> str:
        return f"TouRegister({self._tiers!r})"

    @property
    def total(self) -> Measurement | None:
        return self._tiers.get(0)

    @property
    def tiers(self) -> dict[int, Measurement]:
        """The rate-period tiers (1..n) that hold a value."""
        return {t: m for t, m in self._tiers.items() if t > 0 and m.value is not None}

    def to_dict(self) -> dict[str, Any]:
        return {str(t): m.to_dict() for t, m in self._tiers.items()}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> TouRegister:
        return cls({int(t): Measurement.from_dict(m) for t, m in d.items()})


@dataclass(frozen=True, slots=True)
class HourlyEnergy:
    """The energy of one clock hour (UTC), summed from intervals."""

    start: datetime
    value: float
    unit: str
    covered: int  # seconds of the hour that intervals covered (3600 when complete)
    estimated: bool  # any interval flagged estimated by the meter

    @property
    def end(self) -> datetime:
        return self.start + timedelta(hours=1)

    @property
    def complete(self) -> bool:
        return self.covered == 3600


def hourly_energy(values: Iterable[IntervalValue], *, complete_only: bool = True) -> list[HourlyEnergy]:
    """Sum interval energy into clock hours (UTC), oldest first -- the shape
    long-term statistics want.

    Every interval must lie within one clock hour (2030.5 intervals are
    aligned; 15 minutes on an Itron) and share one unit; overlapping
    intervals are an error. Exact duplicates count once. Intervals without a
    value or flagged questionable are left out, which leaves their hour
    incomplete; ``complete_only`` drops such hours. Raises ``ValueError``.
    """
    unit: str | None = None
    by_hour: dict[datetime, dict[tuple[datetime, datetime], IntervalValue]] = {}
    for v in values:
        if v.value is None or (v.quality is not None and v.quality & QualityFlags.QUESTIONABLE):
            continue
        if unit is None:
            unit = v.unit
        elif v.unit != unit:
            raise ValueError(f"intervals mix units: {unit} and {v.unit}")
        start, end = v.start.astimezone(UTC), v.end.astimezone(UTC)
        hour = start.replace(minute=0, second=0, microsecond=0)
        if end <= start or end > hour + timedelta(hours=1):
            raise ValueError(f"interval {start:%Y-%m-%d %H:%M}-{end:%H:%M} is not within one clock hour")
        by_hour.setdefault(hour, {}).setdefault((start, end), v)
    out = []
    for hour, intervals in sorted(by_hour.items()):
        spans = sorted(intervals)
        for (_, prev_end), (next_start, _) in itertools.pairwise(spans):
            if next_start < prev_end:
                raise ValueError(f"overlapping intervals in the hour from {hour:%Y-%m-%d %H:%M} UTC")
        total = sum(v.value or 0.0 for v in intervals.values())
        covered = sum(int((e - s_).total_seconds()) for s_, e in spans)
        estimated = any(v.quality is not None and v.quality.is_estimated for v in intervals.values())
        out.append(HourlyEnergy(hour, round(total, 9), unit or "", covered, estimated))
    return [h for h in out if h.complete] if complete_only else out


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _from_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp without a timezone: {value!r}")
    return parsed


def _sfdi(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    if not value.strip().isascii() or not value.strip().isdigit():
        raise MeterProtocolError(f"sFDI is not a number: {value!r}")
    return str(int(value))  # agents may zero-pad it


# DeviceInformation.mfID is the vendor's IANA Private Enterprise Number.
MANUFACTURERS: dict[int, str] = {1233: "Itron"}


def manufacturer_name(manufacturer_id: int | None) -> str | None:
    """The vendor behind an mfID, when known."""
    return MANUFACTURERS.get(manufacturer_id) if manufacturer_id is not None else None
