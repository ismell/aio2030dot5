"""Interval data: set boundaries, slots, and hourly energy."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

import pytest

from aio2030dot5 import (
    Direction,
    IntervalValue,
    Quantity,
    Statistic,
    hourly_energy,
)
from aio2030dot5.models import ReadingSetInfo

from .conftest import Pki, make_meter
from .helpers import NS
from .meter_server import FakeMeter, FixtureTree

# -- intervals ---------------------------------------------------------------------------


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


# -- hourly energy refuses data it cannot place ------------------------------------------


def _iv(start: datetime, minutes: int, unit: str = "Wh") -> IntervalValue:
    return IntervalValue(start, start + timedelta(minutes=minutes), 1.0, unit)


T0 = datetime(2026, 10, 6, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    "values",
    [
        [_iv(T0, 120)],  # longer than an hour
        [_iv(T0 + timedelta(minutes=5), 60)],  # not aligned: crosses the hour
        [_iv(T0, 60), _iv(T0, 15)],  # overlapping
        [_iv(T0, 15), _iv(T0 + timedelta(hours=1), 15, "VAh")],  # units differ across hours
    ],
)
def test_hourly_energy_refuses_what_it_cannot_place(values: list[IntervalValue]) -> None:
    with pytest.raises(ValueError):
        hourly_energy(values)
