from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aio2030dot5 import Meter, Timeouts, build_ssl_context
from aio2030dot5.identity import generate_identity

from .meter_server import FakeMeter


@dataclass(frozen=True)
class Pki:
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    other_client_cert: Path
    other_client_key: Path


def _server_identity(directory: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake meter")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    c, k = directory / "server.pem", directory / "server.key"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return c, k


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    d = tmp_path_factory.mktemp("pki")
    sc, sk = _server_identity(d)
    paths = []
    for name in ("client", "other"):
        ident = generate_identity()
        c, k = d / f"{name}.pem", d / f"{name}.key"
        c.write_text(ident.cert_pem)
        k.write_text(ident.key_pem)
        paths += [c, k]
    return Pki(sc, sk, *paths)


@pytest.fixture
def fake_meter(pki: Pki) -> Iterator[FakeMeter]:
    with FakeMeter(pki.server_cert, pki.server_key, pki.client_cert) as m:
        yield m


FAST = Timeouts(connect=2.0, handshake=2.0, response=2.0)


def make_meter(pki: Pki, port: int, **kwargs: object) -> Meter:
    ctx = build_ssl_context(str(pki.client_cert), str(pki.client_key))
    kwargs.setdefault("timeouts", FAST)
    kwargs.setdefault("min_connect_interval", 0.0)
    kwargs.setdefault("request_spacing", 0.0)
    return Meter("127.0.0.1", ctx, port, **kwargs)  # type: ignore[arg-type]
