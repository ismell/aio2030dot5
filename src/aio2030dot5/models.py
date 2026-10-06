"""IEEE 2030.5 metering resources as plain, frozen dataclasses.

Only the subset a HAN metering client needs: DeviceCapability, Time,
DeviceInformation, UsagePoint, MeterReading, ReadingType, Reading and
ReadingSet. Parsing is namespace-agnostic and tolerant: absent elements
become ``None`` rather than errors, because real agents omit fields freely
(an Itron agent returns ``<Reading/>`` with no value for an unused phase).
"""

from __future__ import annotations

import enum
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .exceptions import MeterProtocolError


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
    NET = 4  # delivered minus received
    RECEIVED = 19  # customer -> utility (export)

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


def parse_xml(body: bytes | str) -> ET.Element:
    try:
        return ET.fromstring(body)
    except ET.ParseError as err:
        raise MeterProtocolError(f"malformed XML from meter: {err}") from err


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
    c = child(elem, name)
    if c is None or c.text is None:
        return None
    t = c.text.strip()
    return t or None


def int_or_none(elem: ET.Element, name: str) -> int | None:
    t = text(elem, name)
    if t is None:
        return None
    try:
        return int(t)
    except ValueError as err:
        raise MeterProtocolError(f"<{name}> is not an integer: {t!r}") from err


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
        raise MeterProtocolError(f"attribute {name}={raw!r} is not an integer") from err


def hex_or_none(value: str | None, what: str) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 16)
    except ValueError as err:
        raise MeterProtocolError(f"{what} {value!r} is not hexBinary") from err


# -- resources ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ListPage:
    """Paging attributes common to every 2030.5 *List resource."""

    all: int
    results: int

    @classmethod
    def of(cls, elem: ET.Element) -> ListPage:
        return cls(all=int_attr(elem, "all"), results=int_attr(elem, "results"))


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


@dataclass(frozen=True, slots=True)
class SelfDevice:
    sfdi: str | None
    lfdi: str | None
    device_information_href: str | None

    @classmethod
    def from_xml(cls, root: ET.Element) -> SelfDevice:
        expect_root(root, "SelfDevice")
        return cls(
            sfdi=text(root, "sFDI"),
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


@dataclass(frozen=True, slots=True)
class UsagePoint:
    href: str
    description: str | None
    service_category: int | None
    status: int | None
    meter_reading_list_href: str | None

    @classmethod
    def from_xml(cls, elem: ET.Element) -> UsagePoint:
        expect_root(elem, "UsagePoint")
        return cls(
            href=elem.get("href", ""),
            description=text(elem, "description"),
            service_category=int_or_none(elem, "serviceCategoryKind"),
            status=int_or_none(elem, "status"),
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


@dataclass(frozen=True, slots=True)
class ReadingType:
    kind: Kind
    uom: Uom
    raw_uom: int | None
    flow_direction: FlowDirection
    accumulation: Accumulation
    data_qualifier: DataQualifier
    power_of_ten_multiplier: int
    tou_tiers: int
    interval_length: int | None
    phase: int

    @classmethod
    def from_xml(cls, root: ET.Element) -> ReadingType:
        expect_root(root, "ReadingType")
        raw_uom = int_or_none(root, "uom")
        return cls(
            kind=Kind(int_or_none(root, "kind") or 0),
            uom=Uom(raw_uom or 0),
            raw_uom=raw_uom,
            flow_direction=FlowDirection(int_or_none(root, "flowDirection") or 0),
            accumulation=Accumulation(int_or_none(root, "accumulationBehaviour") or 0),
            data_qualifier=DataQualifier(int_or_none(root, "dataQualifier") or 0),
            power_of_ten_multiplier=int_or_none(root, "powerOfTenMultiplier") or 0,
            tou_tiers=int_or_none(root, "numberOfTouTiers") or 0,
            interval_length=int_or_none(root, "intervalLength"),
            phase=int_or_none(root, "phase") or 0,
        )

    @property
    def unit(self) -> str:
        return UNIT_SYMBOLS.get(self.uom, "")

    def scale(self, raw: int | None) -> float | None:
        if raw is None:
            return None
        return raw * (10.0**self.power_of_ten_multiplier)

    def to_dict(self) -> dict[str, int | None]:
        return {
            "kind": int(self.kind),
            "uom": self.raw_uom,
            "flowDirection": int(self.flow_direction),
            "accumulationBehaviour": int(self.accumulation),
            "dataQualifier": int(self.data_qualifier),
            "powerOfTenMultiplier": self.power_of_ten_multiplier,
            "numberOfTouTiers": self.tou_tiers,
            "intervalLength": self.interval_length,
            "phase": self.phase,
        }

    @classmethod
    def from_dict(cls, d: dict[str, int | None]) -> ReadingType:
        return cls(
            kind=Kind(d.get("kind") or 0),
            uom=Uom(d.get("uom") or 0),
            raw_uom=d.get("uom"),
            flow_direction=FlowDirection(d.get("flowDirection") or 0),
            accumulation=Accumulation(d.get("accumulationBehaviour") or 0),
            data_qualifier=DataQualifier(d.get("dataQualifier") or 0),
            power_of_ten_multiplier=d.get("powerOfTenMultiplier") or 0,
            tou_tiers=d.get("numberOfTouTiers") or 0,
            interval_length=d.get("intervalLength"),
            phase=d.get("phase") or 0,
        )


@dataclass(frozen=True, slots=True)
class Reading:
    """One Reading. ``raw_value`` is unscaled; ``None`` when the agent omits it."""

    href: str | None
    raw_value: int | None
    start: datetime | None
    duration: int | None
    tou_tier: int | None
    quality_flags: str | None
    local_id: int | None

    @classmethod
    def from_xml(cls, elem: ET.Element) -> Reading:
        expect_root(elem, "Reading")
        period = child(elem, "timePeriod")
        start = duration = None
        if period is not None:
            start = int_or_none(period, "start")
            duration = int_or_none(period, "duration")
        local_id = text(elem, "localID")
        return cls(
            href=elem.get("href"),
            raw_value=int_or_none(elem, "value"),
            start=epoch(start),
            duration=duration,
            tou_tier=int_or_none(elem, "touTier"),
            quality_flags=text(elem, "qualityFlags"),
            # localID is hexBinary in the schema ("2F" for slot 47).
            local_id=hex_or_none(local_id, "localID"),
        )


@dataclass(frozen=True, slots=True)
class ReadingSetInfo:
    href: str
    description: str | None
    start: datetime | None
    duration: int | None
    reading_list_href: str | None
    reading_count: int | None

    @classmethod
    def from_xml(cls, elem: ET.Element) -> ReadingSetInfo:
        expect_root(elem, "ReadingSet")
        period = child(elem, "timePeriod")
        start = duration = None
        if period is not None:
            start = int_or_none(period, "start")
            duration = int_or_none(period, "duration")
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

    @classmethod
    def of(cls, reading: Reading, reading_type: ReadingType) -> Measurement:
        return cls(
            value=reading_type.scale(reading.raw_value),
            unit=reading_type.unit,
            start=reading.start,
            duration=reading.duration,
            tou_tier=reading.tou_tier,
        )


@dataclass(frozen=True, slots=True)
class IntervalValue:
    """One interval's energy: [start, end)."""

    start: datetime
    end: datetime
    value: float | None
    unit: str


def interval_values(
    reading_set: ReadingSetInfo, readings: list[Reading], reading_type: ReadingType
) -> list[IntervalValue]:
    """Expand a ReadingSet's readings into timestamped intervals.

    Interval Readings carry no timePeriod of their own; slot N (localID) starts
    at set.start + N * intervalLength.
    """
    if reading_set.start is None:
        raise MeterProtocolError(f"{reading_set.href} has no timePeriod start")
    length = reading_type.interval_length
    if not length:
        raise MeterProtocolError("interval ReadingType has no intervalLength")
    out = []
    for r in readings:
        if r.local_id is None:
            continue
        start = reading_set.start + timedelta(seconds=r.local_id * length)
        out.append(
            IntervalValue(
                start=start,
                end=start + timedelta(seconds=length),
                value=reading_type.scale(r.raw_value),
                unit=reading_type.unit,
            )
        )
    out.sort(key=lambda v: v.start)
    return out
