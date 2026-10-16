"""Exceptions. Consumers decide policy (backoff, rediscovery, user alerts) from these.

::

    MeterError
    ├── MeterConnectionError        back off and retry
    │   ├── MeterTimeout
    │   └── MeterBusy
    ├── MeterIdentityMismatch       another device at this address: locate the meter again
    ├── MeterAuthError              our certificate is refused: the user must act
    ├── MeterProtocolError          the meter answered something we cannot use
    │   └── MeterHttpError
    │       └── MeterNotFound       a cached path is gone: rediscover
    ├── ProfileError                a cached profile is unusable: rediscover
    └── InvalidIdentity             a certificate/key we cannot use
"""

from typing import Literal

__all__ = [
    "AuthReason",
    "InvalidIdentity",
    "MeterAuthError",
    "MeterBusy",
    "MeterConnectionError",
    "MeterError",
    "MeterHttpError",
    "MeterIdentityMismatch",
    "MeterNotFound",
    "MeterProtocolError",
    "MeterTimeout",
    "ProfileError",
]


def short_lfdi(lfdi: str | None) -> str:
    """An LFDI for logs and messages: its last six hex digits. Users paste logs
    into public issues; the suffix tells two certificates apart without
    revealing the device (the SFDI comes from the LFDI's first digits)."""
    return f"...{lfdi[-6:]}" if lfdi else "none"


# Why the meter refused our certificate: the values of MeterAuthError.reason.
AuthReason = Literal[
    "certificate_rejected",
    "certificate_expired",
    "certificate_revoked",
    "access_denied",
    "http_401",
    "http_403",
]


class MeterError(Exception):
    """Base class for every error raised by this library."""


class MeterConnectionError(MeterError):
    """The meter could not be reached, or dropped the connection.

    The usual sign of a meter that is down or "clamped": back off.
    """


class MeterTimeout(MeterConnectionError):
    """A connect, handshake or response phase exceeded its timeout."""


class MeterBusy(MeterConnectionError):
    """The meter answered 429/503: it is overloaded. Back off like for an outage."""


class MeterIdentityMismatch(MeterError):
    """The device at this address is not the expected meter: its certificate's
    LFDI differs (or it presented none). The meter moved -- e.g. a new DHCP
    lease -- or another device took its address. Locate the meter again (by
    mDNS, matching its SFDI) rather than retrying the same address. No request
    was sent to the device.
    """

    def __init__(self, host: str, expected: str, actual: str | None) -> None:
        # The message shortens the LFDIs (logs get pasted into public issues);
        # the attributes keep them whole.
        who = f"LFDI {short_lfdi(actual)}" if actual else "a device that did not prove its identity"
        super().__init__(f"{host} is not the expected meter: {who}, expected LFDI {short_lfdi(expected)}")
        self.host = host
        self.expected = expected
        self.actual = actual

    def __reduce__(self) -> tuple[type, tuple[str, str, str | None], dict[str, object]]:
        return type(self), (self.host, self.expected, self.actual), self.__dict__


class MeterAuthError(MeterError):
    """The meter rejected our client certificate.

    Actionable by the user: the certificate's LFDI is not (or no longer)
    registered with the utility, or the certificate expired. Retrying will
    not help. ``reason`` is one of:

    * ``"certificate_rejected"`` -- TLS ``bad_certificate``/``unknown_ca``/
      ``certificate_unknown``. An Itron Gen5 Riva (agent 3.2.50) sends
      ``bad_certificate`` in place of its Finished message; agents that send it
      after the handshake make this surface on the first request instead.
    * ``"certificate_expired"``, ``"certificate_revoked"``, ``"access_denied"``
    * ``"http_401"``, ``"http_403"`` -- servers that authorise at the HTTP layer.
    """

    def __init__(self, message: str, reason: AuthReason = "certificate_rejected") -> None:
        super().__init__(message)
        self.reason: AuthReason = reason

    def __reduce__(self) -> tuple[type, tuple[str, AuthReason], dict[str, object]]:
        return type(self), (str(self), self.reason), self.__dict__


class MeterProtocolError(MeterError):
    """The meter answered, but not with something we understand."""


class InvalidIdentity(MeterError):
    """A client certificate/key that cannot be used: unparsable, mismatched,
    expired, or not in the profile a meter accepts. ``problems`` lists why."""

    def __init__(self, message: str, problems: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.problems = problems

    def __reduce__(self) -> tuple[type, tuple[str, tuple[str, ...]], dict[str, object]]:
        return type(self), (str(self), self.problems), self.__dict__


class ProfileError(MeterError):
    """A cached MeterProfile is from another library version or malformed:
    discover the meter again."""


class MeterHttpError(MeterProtocolError):
    """A non-2xx HTTP status."""

    def __init__(self, path: str, status: int, reason_phrase: str = "") -> None:
        super().__init__(f"GET {path} -> HTTP {status} {reason_phrase}".rstrip())
        self.path = path
        self.status = status
        self.reason_phrase = reason_phrase

    def __reduce__(self) -> tuple[type, tuple[str, int, str], dict[str, object]]:
        return type(self), (self.path, self.status, self.reason_phrase), self.__dict__


class MeterNotFound(MeterHttpError):
    """HTTP 404/410: a cached path is gone, so the profile should be rediscovered."""
