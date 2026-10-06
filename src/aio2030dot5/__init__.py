"""Async client for IEEE 2030.5 (SEP 2.0) HAN smart meters.

Built for, and tested against, the Itron Gen5 Riva meters Xcel Energy
deploys with local "Launchpad" access, but nothing here is Xcel-specific.
"""

from .client import Meter, MeterSnapshot, PeerInfo
from .dnssd import Advertisement, is_valid_sfdi, parse_advertisement
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
from .identity import lfdi_from_der, lfdi_from_pem, sfdi_from_lfdi
from .models import IntervalValue, Measurement, MeterTime, QualityFlags, ReadingSetInfo, ReadingType, Uom
from .profile import Channel, Direction, MeterProfile, Quantity, Statistic
from .transport import PeerCertificate, Timeouts, TransportStats, build_ssl_context

__version__ = "0.1.0"

__all__ = [
    "Advertisement",
    "Channel",
    "Direction",
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
    "ReadingSetInfo",
    "ReadingType",
    "Statistic",
    "Timeouts",
    "TransportStats",
    "Uom",
    "build_ssl_context",
    "is_valid_sfdi",
    "lfdi_from_der",
    "lfdi_from_pem",
    "parse_advertisement",
    "sfdi_from_lfdi",
]
