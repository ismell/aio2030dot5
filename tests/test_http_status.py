"""Authentication failures and HTTP status codes become typed errors."""

from __future__ import annotations

import ssl

import pytest

from aio2030dot5 import (
    MeterAuthError,
    MeterBusy,
)
from aio2030dot5 import transport as T

from .conftest import Pki, make_meter
from .meter_server import FakeMeter, FixtureTree

# -- auth and HTTP status ----------------------------------------------------------------


class _FakeSSL:
    def __init__(self, err: ssl.SSLError) -> None:
        self.err = err

    def read(self, n: int) -> bytes:
        raise self.err


async def test_bad_certificate_alert_after_handshake_is_auth_error() -> None:
    """How an Itron meter rejects an unregistered LFDI: the handshake
    completes, then a bad_certificate alert arrives on the first read."""
    err = ssl.SSLError(1, "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] ssl/tls alert bad certificate")
    conn = T._TlsConnection.__new__(T._TlsConnection)
    conn._ssl = _FakeSSL(err)  # type: ignore[assignment]
    with pytest.raises(MeterAuthError) as exc:
        await conn._recv_some()
    assert exc.value.reason == "certificate_rejected"


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("SSLV3_ALERT_CERTIFICATE_EXPIRED", "certificate_expired"),
        ("TLSV1_ALERT_UNKNOWN_CA", "certificate_rejected"),
        ("TLSV1_ALERT_ACCESS_DENIED", "access_denied"),
    ],
)
def test_auth_alert_reasons(name: str, reason: str) -> None:
    err = T._classify_ssl_error(ssl.SSLError(1, f"[SSL: {name}] x"))
    assert isinstance(err, MeterAuthError) and err.reason == reason


class StatusTree(FixtureTree):
    def __init__(self, status: int) -> None:
        super().__init__()
        self.status = status

    def respond(self, target: str) -> tuple[int, str]:
        return (self.status, "") if target.startswith("/tm") else super().respond(target)


@pytest.mark.parametrize(("status", "exc_type"), [(403, MeterAuthError), (401, MeterAuthError), (503, MeterBusy)])
async def test_http_status_classification(pki: Pki, status: int, exc_type: type[Exception]) -> None:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert, tree=StatusTree(status)) as fm:
        with pytest.raises(exc_type):
            await make_meter(pki, fm.port)._transport.get("/tm")
