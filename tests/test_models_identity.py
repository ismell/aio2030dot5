from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from aio2030dot5.exceptions import MeterProtocolError
from aio2030dot5.identity import (
    check_identity,
    generate_identity,
    lfdi_from_pem,
    sfdi_from_lfdi,
)
from aio2030dot5.models import (
    Accumulation,
    DeviceCapability,
    DeviceInformation,
    FlowDirection,
    Measurement,
    MeterTime,
    Reading,
    ReadingSetInfo,
    ReadingType,
    Uom,
    children,
    interval_values,
    parse_xml,
)

from .meter_server import FIXTURES

RESP = json.loads(FIXTURES.read_text())["responses"]
META = json.loads(FIXTURES.read_text())["_meta"]


def body(path: str) -> str:
    return RESP[path]["body"]


def test_device_capability_links() -> None:
    dcap = DeviceCapability.from_xml(parse_xml(body("/dcap")))
    assert (dcap.time_href, dcap.usage_point_list_href, dcap.self_device_href) == ("/tm", "/upt", "/sdev")
    assert dcap.end_device_list_href is None


def test_device_information_and_time() -> None:
    info = DeviceInformation.from_xml(parse_xml(body("/sdev/sdi")))
    assert info.software_version == "3.2.50"
    assert info.manufacturer_id == 1233
    assert info.lfdi == META["lfdi"]
    assert info.model is None  # <mfModel></mfModel> is empty on the real agent
    t = MeterTime.from_xml(parse_xml(body("/tm")))
    assert t.current_time.tzinfo is UTC and t.tz_offset == 0


def test_reading_type_scaling_power_factor() -> None:
    rt = ReadingType.from_xml(parse_xml(body("/rt/19")))
    assert rt.uom == Uom.POWER_FACTOR and rt.power_of_ten_multiplier == -3 and rt.phase == 224
    r = Reading.from_xml(parse_xml(body("/upt/1/mr/19/r")))
    assert Measurement.of(r, rt).value == pytest.approx(0.918)


def test_instantaneous_demand() -> None:
    rt = ReadingType.from_xml(parse_xml(body("/rt/1")))
    assert (rt.uom, rt.flow_direction, rt.accumulation) == (
        Uom.WATT,
        FlowDirection.DELIVERED,
        Accumulation.INSTANTANEOUS,
    )
    m = Measurement.of(Reading.from_xml(parse_xml(body("/upt/1/mr/1/r"))), rt)
    assert m.unit == "W" and m.value == 2439 and m.duration == 1


def test_empty_reading_has_no_value() -> None:
    # Phase A power factor on a single-phase service: <Reading href=".."/> only.
    r = Reading.from_xml(parse_xml(body("/upt/1/mr/20/r")))
    assert r.raw_value is None and r.start is None


def test_tou_tiers_sum_to_total() -> None:
    root = parse_xml(RESP["/upt/1/mr/9/rs/1/r?s=0&l=25"]["body"])
    readings = [Reading.from_xml(e) for e in children(root, "Reading")]
    by_tier = {r.tou_tier: r.raw_value for r in readings}
    assert set(by_tier) == set(range(9))
    assert abs(by_tier[0] - (by_tier[1] + by_tier[2] + by_tier[3])) <= 5
    assert by_tier[4] is None


def test_interval_set_expansion() -> None:
    sets = parse_xml(RESP["/upt/1/mr/12/rs?s=0&l=25"]["body"])
    newest = ReadingSetInfo.from_xml(children(sets, "ReadingSet")[0])
    assert newest.start == datetime(2026, 10, 6, tzinfo=UTC)
    rl = parse_xml(RESP["/upt/1/mr/12/rs/123/r?s=0&l=25"]["body"])
    rt = ReadingType.from_xml(parse_xml(body("/rt/12")))
    values = interval_values(newest, [Reading.from_xml(e) for e in children(rl, "Reading")], rt)
    assert len(values) == 18
    assert values[0].start == newest.start and values[0].end - values[0].start == timedelta(minutes=15)
    # localID is hexBinary: "10" is slot 16, "11" slot 17.
    assert values[16].start == newest.start + timedelta(minutes=15 * 16)
    assert values[0].value == 986 and values[0].unit == "Wh"


def test_wrong_root_is_protocol_error() -> None:
    with pytest.raises(MeterProtocolError):
        DeviceCapability.from_xml(parse_xml(body("/tm")))
    with pytest.raises(MeterProtocolError):
        parse_xml("<not-xml")


# -- identity -------------------------------------------------------------------


def test_sfdi_matches_ieee_2030_5_example() -> None:
    # Worked example from IEEE 2030.5-2018 section 6.3.3.
    assert sfdi_from_lfdi("3E4F45AB31EDFE5B67E343E5E4562E31984E23E5") == "167261211391"


def test_sfdi_matches_real_agent() -> None:
    # The meter's own sdev reports an sFDI derived from its lFDI the same way.
    sdev = parse_xml(body("/sdev"))
    sfdi = next(c.text for c in sdev if c.tag.endswith("sFDI"))
    assert sfdi_from_lfdi(META["lfdi"]) == sfdi == META["sfdi"]


def test_generated_identity_is_valid() -> None:
    ident = generate_identity()
    check = check_identity(ident.cert_pem, ident.key_pem)
    assert check.ok, check.problems
    assert check.lfdi == ident.lfdi == lfdi_from_pem(ident.cert_pem)
    assert len(ident.lfdi) == 40 and check.sfdi == ident.sfdi
    assert 1090 <= check.days_remaining() <= 1094


def test_identity_problems_are_reported() -> None:
    a, b = generate_identity(), generate_identity()
    check = check_identity(a.cert_pem, b.key_pem, now=datetime.now(UTC) + timedelta(days=2000))
    assert "private key does not match the certificate" in check.problems
    assert any(p.startswith("certificate expired") for p in check.problems)
