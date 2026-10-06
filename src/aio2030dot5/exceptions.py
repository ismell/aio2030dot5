"""Exceptions. Consumers decide policy (backoff, rediscovery, user alerts) from these."""


class MeterError(Exception):
    """Base class for every error raised by this library."""


class MeterConnectionError(MeterError):
    """The meter could not be reached, or dropped the connection.

    The usual sign of a meter that is down or "clamped": back off.
    """


class MeterTimeout(MeterConnectionError):
    """A connect, handshake or response phase exceeded its timeout."""


class MeterAuthError(MeterError):
    """The meter rejected our client certificate.

    Actionable by the user: the certificate's LFDI is not (or no longer)
    registered with the utility, or the certificate expired. Retrying will not help.
    """


class MeterProtocolError(MeterError):
    """The meter answered, but not with something we understand."""


class MeterHttpError(MeterProtocolError):
    """A non-2xx HTTP status."""

    def __init__(self, path: str, status: int, reason: str = "") -> None:
        super().__init__(f"GET {path} -> HTTP {status} {reason}".rstrip())
        self.path = path
        self.status = status


class MeterNotFound(MeterHttpError):
    """HTTP 404/410: a cached path is gone, so the profile should be rediscovered."""
