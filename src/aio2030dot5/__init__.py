"""Async client for IEEE 2030.5 (SEP 2.0) HAN meters.

Built for, and tested against, the Itron Gen5 Riva meters Xcel Energy
deploys with local "Launchpad" access, but nothing here is Xcel-specific.
"""

from .client import REDACT_KEYS, Meter, MeterSnapshot, PeerInfo
from .dnssd import SERVICE_TYPE, Advertisement, is_valid_sfdi, parse_advertisement
from .exceptions import (
    InvalidIdentity,
    MeterAuthError,
    MeterBusy,
    MeterConnectionError,
    MeterError,
    MeterHttpError,
    MeterIdentityMismatch,
    MeterNotFound,
    MeterProtocolError,
    MeterTimeout,
    ProfileError,
)
from .guard import ReadingGuard
from .identity import (
    Identity,
    IdentityCheck,
    canonical_sfdi,
    check_identity,
    format_lfdi,
    generate_identity,
    lfdi_from_der,
    lfdi_from_pem,
    load_identity,
    sfdi_from_lfdi,
)
from .models import (
    DeviceInformation,
    HourlyEnergy,
    IntervalValue,
    Measurement,
    MeterTime,
    QualityFlags,
    ReadingSetInfo,
    ReadingType,
    TouRegister,
    Uom,
    hourly_energy,
    manufacturer_name,
)
from .profile import Channel, Direction, MeterInfo, MeterProfile, Quantity, Statistic
from .transport import (
    PeerCertificate,
    Timeouts,
    TransportStats,
    async_build_ssl_context,
    build_ssl_context,
    build_ssl_context_from_pem,
)

__version__ = "0.3.1"

__all__ = [
    "REDACT_KEYS",
    "SERVICE_TYPE",
    "Advertisement",
    "Channel",
    "DeviceInformation",
    "Direction",
    "HourlyEnergy",
    "Identity",
    "IdentityCheck",
    "IntervalValue",
    "InvalidIdentity",
    "Measurement",
    "Meter",
    "MeterAuthError",
    "MeterBusy",
    "MeterConnectionError",
    "MeterError",
    "MeterHttpError",
    "MeterIdentityMismatch",
    "MeterInfo",
    "MeterNotFound",
    "MeterProfile",
    "MeterProtocolError",
    "MeterSnapshot",
    "MeterTime",
    "MeterTimeout",
    "PeerCertificate",
    "PeerInfo",
    "ProfileError",
    "QualityFlags",
    "Quantity",
    "ReadingGuard",
    "ReadingSetInfo",
    "ReadingType",
    "Statistic",
    "Timeouts",
    "TouRegister",
    "TransportStats",
    "Uom",
    "async_build_ssl_context",
    "build_ssl_context",
    "build_ssl_context_from_pem",
    "canonical_sfdi",
    "check_identity",
    "format_lfdi",
    "generate_identity",
    "hourly_energy",
    "is_valid_sfdi",
    "lfdi_from_der",
    "lfdi_from_pem",
    "load_identity",
    "manufacturer_name",
    "parse_advertisement",
    "sfdi_from_lfdi",
]
