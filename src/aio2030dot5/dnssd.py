"""DNS-SD (mDNS) advertisements of IEEE 2030.5 servers.

A 2030.5 server advertises the ``_smartenergy._tcp`` service. This module
turns one advertisement (as a zeroconf library resolved it) into where and
how to connect; it does no network I/O and needs no zeroconf package.

Observed on an Itron Gen5 Riva (agent 3.2.50):

* instance ``itrondnsserver-<SFDI>``, SRV port 8081, A record = the meter;
* TXT ``txtvers=1 dcap=/dcap level=-S0 https=8081``;
* every record has a 120 s TTL and no cache-flush bit;
* it answers ``_smartenergy._tcp`` PTR queries but not the ``_upt._sub``
  subtype, sends no unsolicited announcements, and ignores unicast queries
  from off-link sources (so across subnets it needs an mDNS repeater);
* some firmware answered from a UDP source port other than 5353, which strict
  resolvers drop (fixed by the utility in 2025; python-zeroconf accepts it).

The meter's SFDI in the instance name identifies it before any connection --
and before the client's certificate is registered -- so it suits a config
entry's unique ID. It is a hint: confirm it against the TLS peer certificate.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .exceptions import MeterProtocolError

SERVICE_TYPE = "_smartenergy._tcp.local."

_SFDI_MAX_DIGITS = 12  # 36 bits is at most 11 decimal digits, plus the check digit
_INSTANCE_SFDI = re.compile(rf"-(\d{{2,{_SFDI_MAX_DIGITS}}})$")


def is_valid_sfdi(sfdi: str | int) -> bool:
    """True if ``sfdi`` is a well-formed short-form device identifier:
    a 36-bit number followed by a check digit that makes the digit sum a
    multiple of 10."""
    s = str(sfdi)
    if not s.isascii() or not s.isdigit() or not 2 <= len(s) <= _SFDI_MAX_DIGITS:
        return False
    return int(s[:-1]) < 2**36 and sum(int(d) for d in s) % 10 == 0


@dataclass(frozen=True, slots=True)
class Advertisement:
    """One resolved ``_smartenergy._tcp`` service instance."""

    instance: str  # the instance label, e.g. "itrondnsserver-123456789014"
    host: str
    port: int  # the HTTPS port: TXT ``https`` if given, else the SRV port
    dcap_path: str  # where discovery starts; pass to ``Meter.discover(dcap_path=)``
    sfdi: str | None  # from the instance name, when it carries a valid one
    level: str | None
    txt: Mapping[str, str] = field(default_factory=dict)


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError as err:
            raise MeterProtocolError(f"TXT value is not UTF-8: {value!r}") from err
    return value


def _port(value: str, what: str) -> int:
    if not value.isascii() or not value.isdigit() or not 0 < int(value) < 65536:
        raise MeterProtocolError(f"{what} is not a port: {value!r}")
    return int(value)


def parse_advertisement(
    name: str,
    host: str,
    port: int,
    properties: Mapping[str, str | None] | Mapping[bytes, bytes | None],
) -> Advertisement:
    """Read an advertisement from what a zeroconf library resolved.

    ``name`` is the service instance name (with or without the
    ``._smartenergy._tcp.local.`` suffix), ``host`` its address, ``port``
    the SRV port and ``properties`` the TXT record. Keys and values may be
    ``bytes`` (python-zeroconf) or ``str`` (Home Assistant's
    ``ZeroconfServiceInfo``); keys are case-insensitive. Raises
    ``MeterProtocolError`` for an advertisement that is not a usable
    2030.5 server.
    """
    instance = name.removesuffix(".").removesuffix("." + SERVICE_TYPE.removesuffix("."))
    txt: dict[str, str] = {}
    for key, value in properties.items():
        k = _text(key).lower()
        if k and k not in txt:  # RFC 6763 6.4: the first occurrence wins
            txt[k] = _text(value)

    if txt.get("txtvers", "1") != "1":
        raise MeterProtocolError(f"unsupported txtvers {txt['txtvers']!r}")
    # "dcap" per IEEE 2030.5; some servers publish the path as "path" instead.
    dcap = txt.get("dcap") or txt.get("path") or "/dcap"
    if not dcap.startswith("/") or dcap.startswith("//") or any(c.isspace() for c in dcap) or not dcap.isascii():
        raise MeterProtocolError(f"dcap is not a server path: {dcap!r}")
    https = _port(txt["https"], "TXT https") if txt.get("https") else _port(str(port), "SRV port")
    if not host:
        raise MeterProtocolError("advertisement has no address")

    m = _INSTANCE_SFDI.search(instance)
    sfdi = str(int(m.group(1))) if m and is_valid_sfdi(m.group(1)) else None
    return Advertisement(
        instance=instance,
        host=host,
        port=https,
        dcap_path=dcap,
        sfdi=sfdi,
        level=txt.get("level") or None,
        txt=txt,
    )
