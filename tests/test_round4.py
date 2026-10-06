"""Round 4: what the Home Assistant integration review moved into the library."""

from __future__ import annotations

import asyncio
import json
import logging
import re

import pytest

from aio2030dot5 import MeterProfile, ProfileError, ReadingGuard, format_lfdi, manufacturer_name

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree
from .test_robustness import SlowTree

HOUR = 3600.0

# -- the reading guard ----------------------------------------------------------------


def test_power_beyond_a_residential_service_is_dropped() -> None:
    guard = ReadingGuard()
    assert guard.power("power", -12_000.0) == -12_000.0
    assert guard.power("power", 4e6) is None
    assert guard.power("power", None) is None
    assert guard.rejected == 1


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        pytest.param(1_000_000.0, True, id="unchanged"),
        pytest.param(1_049_000.0, True, id="a-full-hour-at-49-kW"),
        pytest.param(1_100_000.0, False, id="faster-than-50-kW"),
        pytest.param(999_999.0, False, id="backwards"),
    ],
)
def test_register_growth_is_bounded(value: float, accepted: bool) -> None:
    guard = ReadingGuard()
    assert guard.register("r", 1_000_000.0, 0.0) == 1_000_000.0
    assert (guard.register("r", value, HOUR) == value) is accepted


def test_a_consistent_new_series_above_is_adopted_without_a_reset() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    assert guard.register("r", 9e9, 60.0) is None
    assert guard.register("r", 9e9 + 10, 120.0) is None
    assert guard.register("r", 9e9 + 20, 180.0) == 9e9 + 20
    assert guard.resets == {}


def test_a_drop_needs_many_reads_and_is_recorded_as_a_reset() -> None:
    """A register reset starts a new cycle instead of a negative change."""
    guard = ReadingGuard()
    guard.register("r", 1_000_000.0, 0.0)
    results = [guard.register("r", float(i), 60.0 * (i + 1)) for i in range(12)]
    assert results[:11] == [None] * 11 and results[11] == 11.0
    assert guard.resets == {"r": 720.0}


def test_an_inconsistent_run_starts_over() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    for i, spike in enumerate((9e9, 5e9, 9e9, 5e9, 9e9)):
        assert guard.register("r", spike, 60.0 * (i + 1)) is None
    assert guard.register("r", 1_010.0, 400.0) == 1_010.0
    assert guard.register("r", None, 460.0) is None


def test_a_run_of_rejections_is_logged_once(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="aio2030dot5")
    guard = ReadingGuard()
    for _ in range(5):
        guard.power("power", 9e9)
    guard.power("power", 1.0)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "plausible again" in caplog.text


def test_the_state_survives_a_restart() -> None:
    guard = ReadingGuard()
    guard.register("r", 1_000.0, 0.0)
    guard.resets["r"] = 5.0
    restarted = ReadingGuard()
    data = guard.as_dict()
    data["registers"]["bad"] = "x"
    data["resets"]["worse"] = "y"
    restarted.load(data)
    assert restarted.registers == {"r": (1_000.0, 0.0)} and restarted.resets == {"r": 5.0}
    assert restarted.register("r", 9e9, 60.0) is None
    for junk in (None, [1], {"registers": [1], "resets": 3}):
        restarted.load(junk)
    assert restarted.registers == {"r": (1_000.0, 0.0)}


# -- one meter, one connection, whatever it is called --------------------------------


async def test_two_names_for_one_meter_share_one_connection_slot(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        by_name, by_ip = make_meter(pki, fm.port), make_meter(pki, fm.port)
        by_name.transport.host = by_name.host = "localhost"
        await asyncio.gather(
            by_name.transport.get("/dcap?slow=1"), by_ip.transport.get("/tm?slow=1"), by_name.transport.get("/tm")
        )
        assert fm.log.max_concurrent == 1
        async with by_ip.transport.batch():
            with pytest.raises(RuntimeError):  # the same meter: nesting would deadlock
                await by_name.transport.get("/dcap")


async def test_an_unresolvable_name_is_its_own_key(pki: Pki) -> None:
    meter = make_meter(pki, 9)
    meter.transport.host = "no-such-host.invalid"
    state = await meter.transport._resolve()
    assert state is meter.transport._state()


# -- helpers ---------------------------------------------------------------------------


def test_lfdi_as_portals_show_it() -> None:
    assert format_lfdi("F289A6F0493D756E057A2B5B59538112697B5A15") == (
        "F289-A6F0-493D-756E-057A-2B5B-5953-8112-697B-5A15"
    )


def test_manufacturers() -> None:
    assert manufacturer_name(1233) == "Itron"
    assert manufacturer_name(4) is None and manufacturer_name(None) is None


# -- device information ---------------------------------------------------------------


class DescribedTree(FixtureTree):
    """A meter that fills in its DeviceInformation (Itron's is empty)."""

    def __init__(self) -> None:
        super().__init__()
        status, body = self.exact["/sdev/sdi"]
        for tag, value in (("mfModel", "Model X"), ("mfSerNum", "SN-1"), ("mfHwVer", "HW 2")):
            body = re.sub(rf"<{tag}>[^<]*</{tag}>", f"<{tag}>{value}</{tag}>", body)
        self.exact["/sdev/sdi"] = (status, body)


async def test_the_profile_keeps_what_the_meter_says_it_is(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=DescribedTree()) as fm:
        profile = await make_meter(pki, fm.port).discover()
    assert (profile.model, profile.serial_number, profile.hardware_version) == ("Model X", "SN-1", "HW 2")
    assert MeterProfile.from_dict(json.loads(json.dumps(profile.to_dict()))) == profile

    older = profile.to_dict()  # cached before these fields existed
    for key in ("model", "serial_number", "hardware_version"):
        del older[key]
    assert MeterProfile.from_dict(older).model is None
    with pytest.raises(ProfileError):
        MeterProfile.from_dict({**profile.to_dict(), "model": 5})


async def test_an_empty_device_information_is_none(pki: Pki, fake_meter: FakeMeter) -> None:
    profile = await make_meter(pki, fake_meter.port).discover()
    assert (profile.model, profile.serial_number, profile.hardware_version) == (None, None, None)
