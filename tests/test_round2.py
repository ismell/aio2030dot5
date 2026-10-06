"""Correctness fixes from the 2026-10-06 review: classification and keys,
interval set boundaries, auth classification, shared pacing, links, quality."""

from __future__ import annotations

import asyncio
import json
import ssl
import xml.etree.ElementTree as ET
from datetime import timedelta

import pytest

from aio2030dot5 import (
    Direction,
    MeterAuthError,
    MeterBusy,
    MeterProfile,
    MeterProtocolError,
    ProfileError,
    QualityFlags,
    Quantity,
    Statistic,
)
from aio2030dot5 import transport as T
from aio2030dot5.models import Reading, ReadingSetInfo, ReadingType, RoleFlags, UsagePoint, parse_xml
from aio2030dot5.profile import _rank_usage_point, classify, resolve_href

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree

NS = "urn:ieee:std:2030.5:ns"


def rt(**fields: int) -> ReadingType:
    body = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return ReadingType.from_xml(parse_xml(f'<ReadingType xmlns="{NS}">{body}</ReadingType>'))


# -- classification -----------------------------------------------------------


def test_older_agent_net_interval_is_net_not_delivered() -> None:
    # Older v3 agents publish "WH Net (Interval)" with flowDirection 1, exactly
    # like "WH Delivered (Interval)" (seen in Xcel's Launchpad SDK samples).
    same = {
        "accumulationBehaviour": 4,
        "dataQualifier": 2,
        "flowDirection": 1,
        "intervalLength": 900,
        "kind": 12,
        "uom": 72,
    }
    assert classify(rt(**same), "WH Net (Interval)") == (Quantity.ENERGY, Statistic.INTERVAL, Direction.NET)
    assert classify(rt(**same), "WH Delivered (Interval)") == (Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)


def test_pre_3_2_50_tou_and_summation_split_by_description() -> None:
    # Before 3.2.50 the ToU and plain summation ReadingTypes are identical.
    same = {"accumulationBehaviour": 9, "flowDirection": 1, "kind": 12, "uom": 72, "numberOfTouTiers": 8}
    assert classify(rt(**same), "Current Summation Delivered")[1] == Statistic.SUMMATION
    assert classify(rt(**same), "TOU WH Delivered")[1] == Statistic.TOU_SUMMATION


def test_more_quantities_and_statistics() -> None:
    assert classify(rt(uom=29, accumulationBehaviour=12, phase=129))[0] == Quantity.VOLTAGE
    assert classify(rt(uom=38, kind=8, accumulationBehaviour=12, dataQualifier=9))[1] == Statistic.MINIMUM
    assert classify(rt(uom=38, kind=8, accumulationBehaviour=3))[1] == Statistic.CUMULATIVE


def test_unknown_codes_survive_a_cache_round_trip() -> None:
    t = rt(uom=999, flowDirection=20, kind=77, accumulationBehaviour=12)
    again = ReadingType.from_dict(json.loads(json.dumps(t.to_dict())))
    assert again == t and again.uom == 999 and again.kind == 77
    assert classify(t)[2] == Direction.TOTAL


def test_scaling_is_exact() -> None:
    assert rt(powerOfTenMultiplier=-3).scale(953) == 0.953
    assert rt(powerOfTenMultiplier=3).scale(7) == 7000.0


# -- keys ----------------------------------------------------------------------

PINNED_KEYS_3_2_50 = [
    "power",
    "energy_summation_received",
    "energy_summation_delivered",
    "apparent_energy_summation_received",
    "apparent_energy_summation_delivered",
    "reactive_energy_summation_received",
    "reactive_energy_summation_delivered",
    "energy_tou_summation_received",
    "energy_tou_summation_delivered",
    "energy_interval_net",
    "energy_interval_received",
    "energy_interval_delivered",
    "apparent_energy_interval_received",
    "apparent_energy_interval_delivered",
    "reactive_energy_interval_received",
    "reactive_energy_interval_delivered",
    "power_maximum_received",
    "power_maximum_delivered",
    "power_factor",
    "power_factor_phase_a",
    "power_factor_phase_b",
    "power_factor_phase_c",
]


async def test_channel_keys_are_pinned(pki: Pki, fake_meter: FakeMeter) -> None:
    """Keys become entity IDs: changing one is a breaking change."""
    profile = await make_meter(pki, fake_meter.port).discover()
    assert [c.key for c in profile.channels] == PINNED_KEYS_3_2_50
    assert all(c.mrid and c.mrid.endswith("04D1") for c in profile.channels)
    tou = profile.channel("energy_tou_summation_delivered")
    assert tou is not None and tou.tou_tiers == (0, 1, 2, 3)


async def test_old_profiles_are_rejected_for_rediscovery() -> None:
    with pytest.raises(ProfileError):
        MeterProfile.from_dict({"version": 1, "host": "x", "port": 1, "usage_point_href": "/upt/1", "channels": []})
    with pytest.raises(ProfileError):
        MeterProfile.from_dict({"version": 2, "channels": "nonsense"})


# -- intervals ----------------------------------------------------------------


class BoundaryTree(FixtureTree):
    """Just after a 12 h set boundary: the newest set exists but is empty,
    and the previous one is complete."""

    def __init__(self) -> None:
        super().__init__()
        proto, sets = self.lists["/upt/1/mr/12/rs"]
        prev = sets[0]  # the newest captured set, /upt/1/mr/12/rs/123
        prev.find(f"{{{NS}}}timePeriod/{{{NS}}}duration").text = "43200"  # type: ignore[union-attr]
        start = int(prev.find(f"{{{NS}}}timePeriod/{{{NS}}}start").text)  # type: ignore[union-attr,arg-type]
        new = ET.fromstring(
            f'<ReadingSet xmlns="{NS}" href="/upt/1/mr/12/rs/124"><timePeriod><duration>300</duration>'
            f'<start>{start + 43200}</start></timePeriod><ReadingListLink href="/upt/1/mr/12/rs/124/r" all="0"/>'
            "</ReadingSet>"
        )
        self.lists["/upt/1/mr/12/rs"] = (proto, [new, *sets])
        empty = ET.fromstring(f'<ReadingList xmlns="{NS}" href="/upt/1/mr/12/rs/124/r" all="0" results="0"/>')
        self.lists["/upt/1/mr/12/rs/124/r"] = (empty, [])


async def test_latest_intervals_survive_a_set_boundary(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=BoundaryTree()) as fm:
        meter = make_meter(pki, fm.port)
        profile = await meter.discover()
        ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
        assert ch is not None
        values = await meter.read_latest_intervals(ch)
    assert values, "the newest set is empty; the previous set's intervals must still be returned"
    assert len(values) == 18 and values[-1].end - values[0].start == timedelta(minutes=15 * 18)


async def test_interval_sets_listing_and_since(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    sets = await meter.list_interval_sets(ch)
    assert len(sets) == 60 and sets[0].start > sets[-1].start  # newest first
    newest = sets[0]
    values = await meter.read_intervals_since(ch, newest.start + timedelta(hours=2))
    assert values and all(v.end > newest.start + timedelta(hours=2) for v in values)


async def test_a_set_that_rolled_off_is_skipped(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    profile = await meter.discover()
    ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    gone = ReadingSetInfo("/upt/1/mr/12/rs/1", None, None, None, "/upt/1/mr/12/rs/1/r", None)
    assert await meter.read_interval_sets(ch, [gone]) == []


# -- auth and HTTP status ----------------------------------------------------------


class _FakeSSL:
    def __init__(self, err: ssl.SSLError) -> None:
        self.err = err

    def read(self, n: int) -> bytes:
        raise self.err


async def test_bad_certificate_alert_after_handshake_is_auth_error() -> None:
    """How an Itron meter rejects an unregistered LFDI: the handshake
    completes, then a bad_certificate alert arrives on the first read."""
    err = ssl.SSLError(1, "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate")
    conn = T._TlsConnection.__new__(T._TlsConnection)
    conn._ssl = _FakeSSL(err)  # type: ignore[assignment]
    with pytest.raises(MeterAuthError) as exc:
        await conn._recv_some()
    assert exc.value.reason == "certificate_rejected"


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("SSLV3_ALERT_CERTIFICATE_EXPIRED", "certificate_expired"),
        ("TLSV1_ALERT_UNKNOWN_CA", "certificate_rejected"),
        ("TLSV1_ALERT_ACCESS_DENIED", "access_denied"),
    ],
)
def test_auth_alert_reasons(name: str, reason: str) -> None:
    err = T._classify_ssl_error(ssl.SSLError(1, f"[SSL: {name}] x"))
    assert isinstance(err, MeterAuthError) and err.reason == reason


class StatusTree(FixtureTree):
    def __init__(self, status: int) -> None:
        super().__init__()
        self.status = status

    def respond(self, target: str) -> tuple[int, str]:
        return (self.status, "") if target.startswith("/tm") else super().respond(target)


@pytest.mark.parametrize(("status", "exc_type"), [(403, MeterAuthError), (401, MeterAuthError), (503, MeterBusy)])
async def test_http_status_classification(pki: Pki, status: int, exc_type: type[Exception]) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=StatusTree(status)) as fm:
        with pytest.raises(exc_type):
            await make_meter(pki, fm.port).transport.get("/tm")


# -- one connection across Meter objects ------------------------------------------


async def test_two_meter_objects_share_one_connection_slot(pki: Pki, fake_meter: FakeMeter) -> None:
    a, b = make_meter(pki, fake_meter.port), make_meter(pki, fake_meter.port)
    profile = await a.discover()
    await asyncio.gather(*(m.read(profile, profile.channels[:4]) for m in (a, b, a, b)))
    assert fake_meter.log.max_concurrent == 1


async def test_connects_are_spaced_from_the_last_close(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, min_connect_interval=0.4)
    loop = asyncio.get_running_loop()
    await meter.transport.get("/dcap")
    t0 = loop.time()
    await meter.transport.get("/tm")
    assert loop.time() - t0 >= 0.35


# -- links, usage points, quality ------------------------------------------------


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
