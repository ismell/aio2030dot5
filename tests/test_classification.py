"""Classifying MeterReadings, and their stable channel keys."""

from __future__ import annotations

import json

import pytest

from aio2030dot5 import (
    Direction,
    MeterProfile,
    ProfileError,
    Quantity,
    Statistic,
)
from aio2030dot5.models import (
    MeterReadingInfo,
    ReadingType,
)
from aio2030dot5.profile import assign_keys, classify

from .conftest import Pki, make_meter
from .helpers import PINNED_KEYS_3_2_50, rt
from .meter_server import FakeMeter, FixtureTree

# -- classification ----------------------------------------------------------------------


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


# -- keys --------------------------------------------------------------------------------


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


# -- classification and keys -------------------------------------------------------------


def test_net_does_not_override_an_explicit_direction() -> None:
    assert classify(rt(uom=72, accumulationBehaviour=9, flowDirection=19), "Net Received")[2] == Direction.RECEIVED
    assert classify(rt(uom=72, accumulationBehaviour=9, flowDirection=1), "Net Metering Delivered")[2] == (
        Direction.DELIVERED
    )


def test_max_and_min_demand_from_the_description() -> None:
    avg = {"uom": 38, "kind": 8, "accumulationBehaviour": 12, "dataQualifier": 2}  # v1/v2 agents
    assert classify(rt(**avg), "Max Demand Delivered")[1] == Statistic.MAXIMUM
    assert classify(rt(**avg), "Instantaneous Demand")[1] == Statistic.INSTANTANEOUS


def test_instantaneous_total_keeps_its_direction_in_the_key() -> None:
    mr = MeterReadingInfo("/upt/1/mr/1", "A", None, None, None, None)
    t = rt(uom=38, kind=8, accumulationBehaviour=12, flowDirection=20)
    q, s, d = classify(t)
    assert assign_keys([(mr, q, s, d, 0)]) == [("power_total", False)]


def test_identical_channels_are_flagged_ambiguous() -> None:
    a = MeterReadingInfo("/upt/1/mr/1", "BBBB01", None, None, None, None)
    b = MeterReadingInfo("/upt/1/mr/2", "BBBB02", None, None, None, None)
    keys = assign_keys(
        [
            (b, Quantity.POWER, Statistic.INSTANTANEOUS, Direction.NONE, 0),
            (a, Quantity.POWER, Statistic.INSTANTANEOUS, Direction.NONE, 0),
        ]
    )
    assert keys == [("power_2", True), ("power", True)]


class TieredVAhTree(FixtureTree):
    """VAh Delivered claims ToU tiers in its ReadingType but its readings carry none."""

    def respond(self, target: str) -> tuple[int, str]:
        status, body = super().respond(target)
        if target == "/rt/5":
            body = body.replace("<numberOfTouTiers>0</numberOfTouTiers>", "<numberOfTouTiers>8</numberOfTouTiers>")
        return status, body


async def test_tou_is_confirmed_by_the_data(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=TieredVAhTree()) as fm:
        profile = await make_meter(pki, fm.port).discover()
    vah = next(c for c in profile.channels if c.meter_reading_href == "/upt/1/mr/5")
    assert vah.statistic == Statistic.SUMMATION and vah.key == "apparent_energy_summation_delivered"


async def test_pinned_keys_survive_the_cache_and_classification_is_not_recomputed(
    pki: Pki, fake_meter: FakeMeter, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    cached = json.loads(json.dumps(profile.to_dict()))
    # Even if classify() changed after an upgrade, a cached channel keeps its meaning.
    monkeypatch.setattr(
        "aio2030dot5.profile.classify", lambda *a, **k: (Quantity.OTHER, Statistic.OTHER, Direction.NONE)
    )
    again = MeterProfile.from_dict(cached)
    assert [c.key for c in again.channels] == PINNED_KEYS_3_2_50
    assert again.channel("energy_summation_delivered").statistic == Statistic.SUMMATION  # type: ignore[union-attr]
    cached["key_scheme"] = 0
    with pytest.raises(ProfileError):
        MeterProfile.from_dict(cached)
