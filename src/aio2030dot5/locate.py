"""Find meters on the network by mDNS, with python-zeroconf (the ``zeroconf`` extra).

A meter's address is not its identity -- DHCP can move it. Store the meter's
SFDI (or LFDI) and find its current address when needed::

    adv = await async_locate(aiozc, "123456789014")
    if adv:
        meter = Meter(adv.host, ctx, adv.port, expected_lfdi=lfdi)

The SFDI in an advertisement is only a hint; ``expected_lfdi`` makes the
connection prove it. Lookup by SFDI relies on the Itron convention of naming
the instance ``itrondnsserver-<SFDI>``; for other servers, ``async_browse``
and probe each candidate (``Meter.probe_tls``) for the meter's LFDI.

Pass the application's shared ``AsyncZeroconf`` (Home Assistant:
``await zeroconf.async_get_async_instance(hass)``) rather than creating one
per lookup. Across subnets, mDNS needs a repeater or reflector.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from .dnssd import SERVICE_TYPE, Advertisement, parse_advertisement
from .exceptions import MeterProtocolError

_LOGGER = logging.getLogger(__name__)

RESOLVE_TIMEOUT = 3.0


async def async_browse(aiozc: AsyncZeroconf, *, listen: float = 5.0) -> list[Advertisement]:
    """Every ``_smartenergy._tcp`` server heard within ``listen`` seconds."""
    return await _browse(aiozc, listen, None)


async def async_locate(aiozc: AsyncZeroconf, sfdi: str, *, listen: float = 5.0) -> Advertisement | None:
    """The advertisement whose instance name carries ``sfdi``, or None if it
    is not heard within ``listen`` seconds. Returns as soon as it is found."""
    found = await _browse(aiozc, listen, str(int(str(sfdi))))
    return found[0] if found else None


async def _browse(aiozc: AsyncZeroconf, listen: float, want: str | None) -> list[Advertisement]:
    loop = asyncio.get_running_loop()
    names: asyncio.Queue[str] = asyncio.Queue()

    def on_change(zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        if state_change is not ServiceStateChange.Removed:
            loop.call_soon_threadsafe(names.put_nowait, name)

    found: dict[str, Advertisement] = {}
    browser = AsyncServiceBrowser(aiozc.zeroconf, SERVICE_TYPE, handlers=[on_change])
    try:
        with suppress(TimeoutError):
            async with asyncio.timeout(listen):
                while True:
                    name = await names.get()
                    if name in found:
                        continue
                    adv = await _resolve(aiozc, name)
                    if adv is None:
                        continue
                    found[name] = adv
                    if want is not None and adv.sfdi == want:
                        return [adv]
    finally:
        await browser.async_cancel()
    return [] if want is not None else list(found.values())


async def _resolve(aiozc: AsyncZeroconf, name: str) -> Advertisement | None:
    info = AsyncServiceInfo(SERVICE_TYPE, name)
    if not await info.async_request(aiozc.zeroconf, int(RESOLVE_TIMEOUT * 1000)):
        _LOGGER.debug("%s did not resolve", name)
        return None
    # Prefer IPv4: the meters seen so far have no routable IPv6 address.
    addresses = info.parsed_scoped_addresses(IPVersion.V4Only) or info.parsed_scoped_addresses()
    if not addresses or info.port is None:
        _LOGGER.debug("%s has no address or port", name)
        return None
    try:
        return parse_advertisement(name, addresses[0], info.port, info.properties)
    except MeterProtocolError as err:
        _LOGGER.debug("ignoring %s: %s", name, err)
        return None
