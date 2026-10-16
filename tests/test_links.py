"""Links, usage points, numbers and quality flags as meters send them."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aio2030dot5 import (
    MeterProtocolError,
    QualityFlags,
)
from aio2030dot5.models import (
    Reading,
    ReadingSetInfo,
    RoleFlags,
    UsagePoint,
    interval_values,
    parse_xml,
)
from aio2030dot5.profile import _rank_usage_point, resolve_href

from .helpers import NS, rt

# -- links, usage points, quality --------------------------------------------------------


@pytest.mark.parametrize(
    ("base", "href", "expected"),
    [
        ("/upt/1/mr", "/upt/1/mr/3/r", "/upt/1/mr/3/r"),
        ("/upt/1/mr/3", "r", "/upt/1/mr/r"),
        ("/dcap", "https://192.0.2.19:8081/upt?x=1", "/upt?x=1"),
    ],
)
def test_links_resolve_to_the_meter(base: str, href: str, expected: str) -> None:
    assert resolve_href(base, href, "192.0.2.19", 8081) == expected


@pytest.mark.parametrize("href", ["https://evil.example/upt", "https://192.0.2.19:9999/upt", "ftp://192.0.2.19/x"])
def test_links_elsewhere_are_refused(href: str) -> None:
    with pytest.raises(MeterProtocolError):
        resolve_href("/dcap", href, "192.0.2.19", 8081)


def test_real_usage_point_beats_a_mirror() -> None:
    def up(flags: int, status: int = 1) -> UsagePoint:
        return UsagePoint("/u", None, 0, status, RoleFlags(flags), "/u/mr")

    ranked = sorted(
        [up(RoleFlags.IS_MIRROR), up(0, status=0), up(RoleFlags.IS_PREMISES_AGGREGATION_POINT)], key=_rank_usage_point
    )
    assert ranked[0].role_flags == RoleFlags.IS_PREMISES_AGGREGATION_POINT
    assert ranked[-1].role_flags == RoleFlags.IS_MIRROR


def test_quality_flags() -> None:
    r = Reading.from_xml(parse_xml(f'<Reading xmlns="{NS}"><qualityFlags>10</qualityFlags><value>1</value></Reading>'))
    assert r.quality == QualityFlags.QUESTIONABLE
    r = Reading.from_xml(parse_xml(f'<Reading xmlns="{NS}"><qualityFlags>0C</qualityFlags></Reading>'))
    assert r.quality is not None and r.quality.is_estimated


# -- links, numbers, intervals -----------------------------------------------------------


def test_ipv6_meter_links() -> None:
    assert resolve_href("/", "/dcap", "fd00::5", 8081) == "/dcap"
    assert resolve_href("/dcap", "https://[fd00::5]:8081/upt", "[fd00::5]", 8081) == "/upt"


@pytest.mark.parametrize("href", ["https://192.0.2.19:99999/x", "https://192.0.2.19:abc/x", "http://[::1/x"])
def test_malformed_links_are_protocol_errors(href: str) -> None:
    with pytest.raises(MeterProtocolError):
        resolve_href("/dcap", href, "192.0.2.19", 8081)


@pytest.mark.parametrize(
    "xml",
    [
        f'<Reading xmlns="{NS}"><qualityFlags>0x01</qualityFlags></Reading>',
        f'<Reading xmlns="{NS}"><localID>-1</localID></Reading>',
        f'<Reading xmlns="{NS}"><value>{2**60}</value></Reading>',
    ],
)
def test_out_of_range_numbers_are_protocol_errors(xml: str) -> None:
    with pytest.raises(MeterProtocolError):
        Reading.from_xml(parse_xml(xml))


def test_multiplier_out_of_range_is_a_protocol_error() -> None:
    with pytest.raises(MeterProtocolError):
        rt(powerOfTenMultiplier=400)


def test_interval_slots_outside_their_set_are_dropped() -> None:
    start = datetime(2026, 10, 6, tzinfo=UTC)
    rs = ReadingSetInfo("/s", None, start, 3600, "/s/r", None)  # 4 slots
    readings = [Reading(None, 1, None, None, None, None, slot) for slot in (0, 3, 4, 200)]
    values = interval_values(rs, readings, rt(uom=72, accumulationBehaviour=4, intervalLength=900))
    assert [v.start for v in values] == [start, start.replace(minute=45)]
