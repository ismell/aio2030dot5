"""DNS-SD advertisements, shaped like a live Itron Gen5 Riva answer (identifiers anonymised)."""

from __future__ import annotations

import pytest

from aio2030dot5 import MeterProtocolError, is_valid_sfdi, parse_advertisement, sfdi_from_lfdi
from aio2030dot5.dnssd import SERVICE_TYPE

FAKE_LFDI = "F289A6F0493D756E057A2B5B59538112697B5A15"  # the anonymised fixture meter
FAKE_SFDI = "651057190448"
NAME = f"itrondnsserver-{FAKE_SFDI}.{SERVICE_TYPE}"
# python-zeroconf hands TXT over as bytes; Home Assistant's ZeroconfServiceInfo as str.
TXT_BYTES = {b"txtvers": b"1", b"dcap": b"/dcap", b"level": b"-S0", b"https": b"8081"}
TXT_STR = {k.decode(): v.decode() for k, v in TXT_BYTES.items()}


@pytest.mark.parametrize("txt", [TXT_BYTES, TXT_STR])
def test_itron_riva_advertisement(txt: dict) -> None:  # type: ignore[type-arg]
    adv = parse_advertisement(NAME, "192.0.2.19", 8081, txt)
    assert adv.instance == f"itrondnsserver-{FAKE_SFDI}"
    assert (adv.host, adv.port, adv.dcap_path, adv.level) == ("192.0.2.19", 8081, "/dcap", "-S0")
    assert adv.sfdi == FAKE_SFDI == sfdi_from_lfdi(FAKE_LFDI)


@pytest.mark.parametrize("name", [NAME, NAME.rstrip("."), f"itrondnsserver-{FAKE_SFDI}"])
def test_instance_name_with_or_without_the_service_suffix(name: str) -> None:
    assert parse_advertisement(name, "192.0.2.19", 8081, TXT_STR).sfdi == FAKE_SFDI


def test_txt_https_port_wins_over_srv_and_keys_are_case_insensitive() -> None:
    adv = parse_advertisement(NAME, "fd00::5", 443, {"TxtVers": "1", "DCAP": "/sep2/dcap", "HTTPS": "8443"})
    assert (adv.port, adv.dcap_path) == (8443, "/sep2/dcap")
    assert parse_advertisement(NAME, "h", 8081, {"txtvers": "1"}).dcap_path == "/dcap"
    assert parse_advertisement(NAME, "h", 8081, {"txtvers": "1"}).port == 8081


@pytest.mark.parametrize("instance", ["meter", "itrondnsserver-651057190449", "x-1", "itrondnsserver-1234567890123"])
def test_no_sfdi_unless_the_name_carries_a_valid_one(instance: str) -> None:
    assert parse_advertisement(instance, "h", 8081, TXT_STR).sfdi is None


@pytest.mark.parametrize(
    "txt",
    [
        {"txtvers": "2", "dcap": "/dcap"},
        {"dcap": "dcap"},
        {"dcap": "//evil.example/dcap"},
        {"dcap": "/d cap"},
        {"https": "0"},
        {"https": "65536"},
        {"https": "\uff18\uff10\uff18\uff11"},  # full-width "8081" passes str.isdigit()
        {b"dcap": b"\xff"},
    ],
)
def test_unusable_advertisements_are_protocol_errors(txt: dict) -> None:  # type: ignore[type-arg]
    with pytest.raises(MeterProtocolError):
        parse_advertisement(NAME, "192.0.2.19", 8081, txt)


def test_no_address_is_a_protocol_error() -> None:
    with pytest.raises(MeterProtocolError):
        parse_advertisement(NAME, "", 8081, TXT_STR)


def test_valueless_txt_keys() -> None:
    adv = parse_advertisement(NAME, "h", 8081, {b"txtvers": b"1", b"level": None})
    assert adv.level is None and adv.txt["level"] == ""


@pytest.mark.parametrize("sfdi", [FAKE_SFDI, int(FAKE_SFDI), "00", sfdi_from_lfdi("F" * 40)])
def test_valid_sfdis(sfdi: str | int) -> None:
    assert is_valid_sfdi(sfdi)


@pytest.mark.parametrize("sfdi", ["651057190449", "", "5", "1234567890123", "\uff16\uff15", "-10", "687194767366"])
def test_invalid_sfdis(sfdi: str) -> None:
    # 687194767366 has a good check digit, but its prefix is 2**36: wider than 36 bits.
    assert not is_valid_sfdi(sfdi)


def test_the_first_of_duplicate_keys_wins() -> None:
    # RFC 6763 6.4: keys are case-insensitive and only the first occurrence counts.
    assert parse_advertisement(NAME, "h", 8081, {"DCAP": "/first", "dcap": "/second"}).dcap_path == "/first"
