"""One connection per meter: pacing, sessions, deadlines, reconnects and framing."""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import UTC, datetime, timedelta

import pytest

from aio2030dot5 import (
    Direction,
    MeterConnectionError,
    MeterHttpError,
    MeterProtocolError,
    MeterTimeout,
    Quantity,
    Statistic,
    Timeouts,
)

from .conftest import Pki, make_meter
from .meter_server import FakeMeter
from .scripted_server import Server, read_request, rst, server_ctx
from .test_robustness import SlowTree

# -- one connection across Meter objects -------------------------------------------------


async def test_two_meter_objects_share_one_connection_slot(pki: Pki, fake_meter: FakeMeter) -> None:
    a, b = make_meter(pki, fake_meter.port), make_meter(pki, fake_meter.port)
    profile = await a.discover()
    await asyncio.gather(*(m.read(profile, profile.channels[:4]) for m in (a, b, a, b)))
    assert fake_meter.log.max_concurrent == 1


async def test_connects_are_spaced_from_the_last_close(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, min_connect_interval=0.4)
    loop = asyncio.get_running_loop()
    await meter._transport.get("/dcap")
    t0 = loop.time()
    await meter._transport.get("/tm")
    assert loop.time() - t0 >= 0.35


# -- transport ---------------------------------------------------------------------------


async def test_request_in_flight_when_its_batch_ends_cannot_connect(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        meter = make_meter(pki, fm.port)
        async with meter._transport.batch() as b:
            await b.get("/dcap")
            # A second request on the now-reused connection, left running past
            # the batch (e.g. by gather()). The batch's exit kills its
            # connection; the reused-connection retry must not reconnect.
            stray = asyncio.create_task(b.get("/tm?slow=1"))
            await asyncio.sleep(0.1)
        with pytest.raises((RuntimeError, MeterConnectionError)):
            await stray
        await asyncio.sleep(0.6)
        assert fm.log.connections == 1


async def test_a_failed_handshake_still_spaces_the_next_connect(pki: Pki) -> None:
    accepts: list[float] = []

    def handler(raw):  # type: ignore[no-untyped-def]
        accepts.append(time.monotonic())
        raw.recv(4096)
        time.sleep(0.5)  # a slow, clamping meter...
        rst(raw)  # ...that then resets

    with Server(handler) as srv:
        meter = make_meter(pki, srv.port, min_connect_interval=0.4)
        for _ in range(2):
            with pytest.raises(MeterConnectionError):
                await meter._transport.get("/dcap")
    assert accepts[1] - accepts[0] >= 0.85  # 0.5 s handshake + 0.4 s spacing from its end


async def test_session_survives_a_network_failure(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    await meter._transport.get("/dcap")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    meter._transport.port = dead  # the meter "drops off the network"
    with pytest.raises(MeterConnectionError):
        await meter._transport.get("/dcap")
    meter._transport.port = fake_meter.port
    await meter._transport.get("/tm")
    assert fake_meter.log.resumed == 1  # the first connect after the outage resumed


async def test_nested_batch_on_the_same_meter_raises_instead_of_hanging(pki: Pki, fake_meter: FakeMeter) -> None:
    a, b = make_meter(pki, fake_meter.port), make_meter(pki, fake_meter.port)
    async with a._transport.batch():
        with pytest.raises(RuntimeError):
            async with asyncio.timeout(2):
                await b._transport.get("/dcap")


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\nok",
    ],
)
async def test_odd_framing_is_a_protocol_error(pki: Pki, response: bytes) -> None:
    sctx = server_ctx(pki)

    def handler(raw):  # type: ignore[no-untyped-def]
        tls = sctx.wrap_socket(raw, server_side=True)
        read_request(tls)
        tls.sendall(response)
        time.sleep(0.5)

    with Server(handler) as srv:
        with pytest.raises(MeterProtocolError) as exc:
            await make_meter(pki, srv.port)._transport.get("/x")
    # A framing error, not an HTTP status surfacing as one.
    assert not isinstance(exc.value, MeterHttpError)


async def test_since_must_be_timezone_aware(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    ch = (await meter.discover()).find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    with pytest.raises(ValueError):
        await meter.read_intervals_since(ch, datetime(2026, 10, 6))


# -- the batch deadline ------------------------------------------------------------------


async def test_a_call_past_its_deadline_is_a_meter_timeout(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        meter = make_meter(pki, fm.port, timeouts=Timeouts(2, 2, 2, batch=0.2))
        with pytest.raises(MeterTimeout):
            await meter._transport.get("/tm?slow=1")


async def test_waiting_for_the_lock_does_not_count_against_the_deadline(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        slow = make_meter(pki, fm.port)
        quick = make_meter(pki, fm.port, timeouts=Timeouts(2, 2, 2, batch=0.4))
        backfill = asyncio.create_task(slow._transport.get("/tm?slow=1"))  # holds the meter ~0.5 s
        await asyncio.sleep(0.05)
        assert await quick._transport.get("/dcap")  # queued ~0.5 s, then quick
        await backfill


# -- one connection, one task ------------------------------------------------------------


async def test_batch_connect_from_another_task_never_connects(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port)
    async with meter._transport.batch() as b:
        results = await asyncio.gather(b.connect(), b.get("/dcap"), return_exceptions=True)
        stray = asyncio.create_task(b.connect())
        await asyncio.sleep(0)
    assert all(isinstance(r, RuntimeError) for r in results)
    with pytest.raises(RuntimeError):
        await stray
    await asyncio.sleep(0.2)
    assert fake_meter.log.connections == 0


# -- pacing does not spend the deadline --------------------------------------------------


async def test_connection_pacing_does_not_count_against_the_deadline(pki: Pki, fake_meter: FakeMeter) -> None:
    meter = make_meter(pki, fake_meter.port, min_connect_interval=1.0, timeouts=Timeouts(2, 2, 2, batch=0.8))
    await meter._transport.get("/dcap")
    await meter._transport.get("/tm")  # waits ~1 s for pacing, within a 0.8 s deadline
    profile = await meter.discover()
    ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
    assert ch is not None
    meter._transport.timeouts = Timeouts(2, 2, 2, batch=3.0)
    await meter.read_intervals_since(ch, datetime.now(UTC) - timedelta(days=1))  # two batches, paced


# -- one meter, one connection, whatever it is called ------------------------------------


async def test_two_names_for_one_meter_share_one_connection_slot(pki: Pki) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=SlowTree()) as fm:
        by_name, by_ip = make_meter(pki, fm.port, host="localhost"), make_meter(pki, fm.port)
        await asyncio.gather(
            by_name._transport.get("/dcap?slow=1"), by_ip._transport.get("/tm?slow=1"), by_name._transport.get("/tm")
        )
        assert fm.log.max_concurrent == 1
        async with by_ip._transport.batch():
            with pytest.raises(RuntimeError):  # the same meter: nesting would deadlock
                await by_name._transport.get("/dcap")


async def test_an_unresolvable_name_is_its_own_key(pki: Pki) -> None:
    meter = make_meter(pki, 9, host="no-such-host.invalid")
    state = await meter._transport._resolve()
    assert state is meter._transport._state()
