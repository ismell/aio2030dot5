"""Interop with other IEEE 2030.5 servers (found against GRIDAPPSD's Go server)."""

from __future__ import annotations

import logging

import pytest

from aio2030dot5 import (
    MeterHttpError,
    MeterNotFound,
    MeterProtocolError,
    is_valid_sfdi,
    parse_advertisement,
)
from aio2030dot5.identity import canonical_sfdi
from aio2030dot5.models import SelfDevice, parse_xml
from aio2030dot5.profile import classify, resolve_href

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree
from .test_round2 import NS, PINNED_KEYS_3_2_50, rt


class ReadingListTree(FixtureTree):
    """Answers a ReadingLink with a ReadingList (an older and a newer Reading)."""

    def respond(self, target: str) -> tuple[int, str]:
        status, body = super().respond(target)
        if target == "/upt/1/mr/1/r":
            return 200, (
                f'<ReadingList xmlns="{NS}" all="2" results="2">'
                "<Reading><timePeriod><duration>1</duration><start>1000</start></timePeriod>"
                "<value>11</value></Reading>"
                "<Reading><timePeriod><duration>1</duration><start>2000</start></timePeriod>"
                "<value>22</value></Reading></ReadingList>"
            )
        return status, body


async def test_a_reading_list_where_a_reading_belongs(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=ReadingListTree()) as fm:
        meter = make_meter(pki, fm.port)
        profile = await meter.discover()
        snap = await meter.read(profile, [c for c in profile.channels if c.key == "power"])
    assert snap.values["power"].value == 22  # the newest


class BrokenTree(FixtureTree):
    def __init__(self, broken: dict[str, int]) -> None:
        super().__init__()
        self.broken = broken

    def respond(self, target: str) -> tuple[int, str]:
        for prefix, status in self.broken.items():
            if target.startswith(prefix):
                return status, "broken"
        return super().respond(target)


@pytest.mark.parametrize(("status", "error"), [(500, MeterHttpError), (404, MeterNotFound)])
async def test_a_partial_read_isolates_one_bad_channel(pki: Pki, status: int, error: type[Exception]) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=BrokenTree({"/upt/1/mr/1/r": status})) as fm:
        meter = make_meter(pki, fm.port)
        profile = await meter.discover()
        snap = await meter.read(profile, profile.channels, partial=True)
        with pytest.raises(error):
            await meter.read(profile, profile.channels)  # the default stays all-or-nothing
    assert isinstance(snap.errors["power"], error)
    assert "power" not in snap.values and snap.values["energy_summation_delivered"].value == 42239863
    assert snap.tou["energy_tou_summation_delivered"].tiers
    assert "power" in snap.to_dict()["errors"]


async def test_an_unreadable_tou_tier_list_does_not_sink_discovery(pki: Pki, caplog: pytest.LogCaptureFixture) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as fm:
        profile = await make_meter(pki, fm.port).discover()
    tou = profile.channel("energy_tou_summation_delivered")
    assert tou is not None and tou.reading_set_list_href
    tree = BrokenTree({tou.reading_set_list_href: 404})
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=tree) as fm:
        caplog.set_level(logging.WARNING)
        profile = await make_meter(pki, fm.port).discover()
    keys = [c.key for c in profile.channels]
    assert len(keys) == len(PINNED_KEYS_3_2_50) and "energy_tou_summation_delivered" not in keys
    assert "treating it as a plain register" in caplog.text


class EmptyTree(FixtureTree):
    def respond(self, target: str) -> tuple[int, str]:
        if target.startswith("/upt/1/mr?"):
            return 200, f'<MeterReadingList xmlns="{NS}" all="0" results="0"/>'
        return super().respond(target)


async def test_a_meter_with_nothing_to_read_is_an_error(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=EmptyTree()) as fm:
        with pytest.raises(MeterProtocolError, match="nothing to read"):
            await make_meter(pki, fm.port).discover()


class NotItronTree(FixtureTree):
    def respond(self, target: str) -> tuple[int, str]:
        status, body = super().respond(target)
        return status, body.replace("<mfID>1233</mfID>", "<mfID>99999</mfID>")


async def test_agent_3_2_50_needs_no_description_quirks(pki: Pki) -> None:
    """Classified from ReadingTypes and data alone, the keys are the same."""
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=NotItronTree()) as fm:
        profile = await make_meter(pki, fm.port).discover()
    assert profile.manufacturer_id == 99999
    assert [c.key for c in profile.channels] == PINNED_KEYS_3_2_50


def test_descriptions_are_only_read_for_itron() -> None:
    avg = {"uom": 38, "kind": 8, "accumulationBehaviour": 12, "dataQualifier": 2}
    assert classify(rt(**avg), "Max Demand Delivered", itron=False)[1].value == "instantaneous"
    assert classify(rt(**avg), "Max Demand Delivered")[1].value == "maximum"
    net = {"uom": 72, "accumulationBehaviour": 4, "intervalLength": 900, "flowDirection": 1}
    assert classify(rt(**net), "Energy imported (net meter site)", itron=False)[2].value == "delivered"


@pytest.mark.parametrize(
    "href",
    [
        "https://meter.local:8081/upt/1",  # the server's own name
        "https://192.0.2.7:8081/upt/1",  # another of its addresses
        "/upt/1",
    ],
)
def test_absolute_links_may_name_the_server_differently(href: str) -> None:
    assert resolve_href("/dcap", href, "127.0.0.1", 8081) == "/upt/1"


def test_a_link_to_another_port_is_refused() -> None:
    with pytest.raises(MeterProtocolError, match="another server"):
        resolve_href("/dcap", "https://127.0.0.1:443/upt/1", "127.0.0.1", 8081)


def test_sfdis_compare_in_one_form() -> None:
    padded = "060044366894"
    assert is_valid_sfdi(padded) and canonical_sfdi(padded) == "60044366894"
    sdev = SelfDevice.from_xml(parse_xml(f'<SelfDevice xmlns="{NS}"><sFDI>{padded}</sFDI></SelfDevice>'))
    assert sdev.sfdi == "60044366894"
    adv = parse_advertisement(f"itrondnsserver-{padded}", "h", 8081, {"txtvers": "1"})
    assert adv.sfdi == "60044366894"
    with pytest.raises(ValueError):
        canonical_sfdi("12a")
    with pytest.raises(MeterProtocolError):
        SelfDevice.from_xml(parse_xml(f'<SelfDevice xmlns="{NS}"><sFDI>x1</sFDI></SelfDevice>'))


def test_txt_path_is_a_fallback_for_dcap() -> None:
    assert parse_advertisement("srv", "h", 8081, {"txtvers": "1", "path": "/sep2/dcap"}).dcap_path == "/sep2/dcap"
    both = {"txtvers": "1", "path": "/other", "dcap": "/sep2/dcap"}
    assert parse_advertisement("srv", "h", 8081, both).dcap_path == "/sep2/dcap"


async def test_interval_channel_without_sets_says_so(pki: Pki, fake_meter: FakeMeter) -> None:
    import dataclasses

    profile = await make_meter(pki, fake_meter.port).discover()
    ch = profile.channel("energy_interval_delivered")
    assert ch is not None
    with pytest.raises(ValueError, match="links no ReadingSets"):
        await make_meter(pki, fake_meter.port).read_latest_intervals(
            dataclasses.replace(ch, reading_set_list_href=None)
        )
