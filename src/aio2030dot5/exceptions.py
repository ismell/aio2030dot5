"""Exceptions. Consumers decide policy (backoff, rediscovery, user alerts) from these."""


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


class MeterAuthError(MeterError):
    """The meter rejected our client certificate.

    Actionable by the user: the certificate's LFDI is not (or no longer)
    registered with the utility, or the certificate expired. Retrying will
    not help. ``reason`` is one of:

    * ``"certificate_rejected"`` -- TLS ``bad_certificate``/``unknown_ca``/
      ``certificate_unknown``. An Itron Gen5 Riva completes the handshake with
      an unregistered certificate and sends ``bad_certificate`` ~0.5 s later,
      so this can surface on the first request rather than the handshake.
    * ``"certificate_expired"``, ``"certificate_revoked"``, ``"access_denied"``
    * ``"http_401"``, ``"http_403"`` -- servers that authorise at the HTTP layer.
    """

    def __init__(self, message: str, reason: str = "certificate_rejected") -> None:
        super().__init__(message)
        self.reason = reason


class MeterProtocolError(MeterError):
    """The meter answered, but not with something we understand."""


class ProfileError(MeterError):
    """A cached MeterProfile is from another library version or malformed:
    discover the meter again."""


class MeterHttpError(MeterProtocolError):
    """A non-2xx HTTP status."""

    def __init__(self, path: str, status: int, reason: str = "") -> None:
        super().__init__(f"GET {path} -> HTTP {status} {reason}".rstrip())
        self.path = path
        self.status = status


class MeterNotFound(MeterHttpError):
    """HTTP 404/410: a cached path is gone, so the profile should be rediscovered."""
