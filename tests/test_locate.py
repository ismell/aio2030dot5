"""Finding meters by mDNS, against real python-zeroconf responders on loopback."""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

pytest.importorskip("zeroconf")

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

from aio2030dot5.dnssd import SERVICE_TYPE
from aio2030dot5.locate import async_browse, async_locate

# One event loop for the module, so the responders are registered (and probed) once.
pytestmark = pytest.mark.asyncio(loop_scope="module")

OURS, NEIGHBOUR = "651057190448", "123456789014"


def service(sfdi: str, port: int, **txt: str) -> ServiceInfo:
    props = {"txtvers": "1", "dcap": "/dcap", "level": "-S0", "https": str(port)} | txt
    return ServiceInfo(
        SERVICE_TYPE,
        f"itrondnsserver-{sfdi}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=port,
        properties=props,
        server=f"itrondnsserver-{sfdi}.local.",
    )


def loopback() -> AsyncZeroconf:
    return AsyncZeroconf(interfaces=["127.0.0.1"], ip_version=IPVersion.V4Only)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def meters() -> AsyncIterator[None]:
    zc = loopback()
    infos = (service(OURS, 8081), service(NEIGHBOUR, 8082), service("123", 8083, txtvers="9"))
    await asyncio.gather(*[await zc.async_register_service(i) for i in infos])  # probe concurrently
    yield
    await zc.async_unregister_all_services()
    await zc.async_close()


@pytest_asyncio.fixture(loop_scope="module")
async def client() -> AsyncIterator[AsyncZeroconf]:
    zc = loopback()
    yield zc
    await zc.async_close()


async def test_locate_finds_the_meter_by_sfdi(meters: None, client: AsyncZeroconf) -> None:
    adv = await async_locate(client, OURS, listen=5)
    assert adv is not None
    assert (adv.sfdi, adv.host, adv.port, adv.dcap_path) == (OURS, "127.0.0.1", 8081, "/dcap")


async def test_locate_returns_as_soon_as_it_is_found(meters: None, client: AsyncZeroconf) -> None:
    t0 = time.monotonic()
    assert await async_locate(client, NEIGHBOUR, listen=10) is not None
    assert time.monotonic() - t0 < 5


async def test_locate_gives_up_on_an_absent_meter(meters: None, client: AsyncZeroconf) -> None:
    t0 = time.monotonic()
    assert await async_locate(client, "999999999990", listen=1.5) is None
    assert time.monotonic() - t0 < 3


async def test_browse_lists_usable_servers_only(meters: None, client: AsyncZeroconf) -> None:
    found = await async_browse(client, listen=2)
    assert sorted((a.sfdi, a.port) for a in found) == [(NEIGHBOUR, 8082), (OURS, 8081)]  # not txtvers=9
