"""Client identity for IEEE 2030.5 HAN access: certificates, LFDI and SFDI.

A HAN meter admits a client whose self-signed certificate's LFDI has been
registered with the utility (for Xcel Energy, in the Launchpad portal). The
profile generated here mirrors a certificate an Itron Gen5 Riva meter is
known to accept: P-256 / ECDSA-SHA256, CN=MeterReaderHanClient, critical
basicConstraints CA:TRUE, critical keyUsage digitalSignature, and the
critical IEEE 2030.5 self-signed-client policy OID.

Requires the ``cryptography`` package (an optional dependency of this library).
"""

from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

IEEE_2030_5_SELF_SIGNED_POLICY = "1.3.6.1.4.1.40732.2.2"
DEFAULT_COMMON_NAME = "MeterReaderHanClient"
DEFAULT_VALID_DAYS = 1094  # utilities document a 3-year life for these certs


def lfdi_from_der(der: bytes) -> str:
    """Long-form device identifier: the leftmost 160 bits of SHA-256(cert DER), hex."""
    return hashlib.sha256(der).hexdigest()[:40].upper()


def lfdi_from_pem(pem: str | bytes) -> str:
    text = pem.decode("ascii") if isinstance(pem, bytes) else pem
    return lfdi_from_der(ssl.PEM_cert_to_DER_cert(text))


def sfdi_from_lfdi(lfdi: str) -> str:
    """Short-form device identifier: leftmost 36 bits of the LFDI as decimal,
    plus a check digit making the digit sum a multiple of 10."""
    digits = str(int(lfdi[:9], 16))
    check = (10 - sum(int(d) for d in digits) % 10) % 10
    return f"{digits}{check}"


@dataclass(frozen=True, slots=True)
class Identity:
    cert_pem: bytes
    key_pem: bytes
    lfdi: str
    sfdi: str
    not_after: datetime


@dataclass(frozen=True, slots=True)
class IdentityCheck:
    lfdi: str
    sfdi: str
    not_after: datetime
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.problems

    def days_remaining(self, now: datetime | None = None) -> int:
        return (self.not_after - (now or datetime.now(UTC))).days


def generate_identity(*, common_name: str = DEFAULT_COMMON_NAME, valid_days: int = DEFAULT_VALID_DAYS) -> Identity:
    """A new P-256 key and self-signed 2030.5 client certificate (PEM)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier(IEEE_2030_5_SELF_SIGNED_POLICY), None)]),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    lfdi = lfdi_from_der(der)
    return Identity(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        lfdi=lfdi,
        sfdi=sfdi_from_lfdi(lfdi),
        not_after=cert.not_valid_after_utc,
    )


def check_identity(cert_pem: bytes, key_pem: bytes | None = None, *, now: datetime | None = None) -> IdentityCheck:
    """Validate a certificate (and optionally its key) against what a meter
    requires. Returns every problem found instead of raising on the first."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    cert = x509.load_pem_x509_certificate(cert_pem)
    lfdi = lfdi_from_der(cert.public_bytes(serialization.Encoding.DER))
    problems: list[str] = []
    now = now or datetime.now(UTC)
    if cert.not_valid_after_utc <= now:
        problems.append(f"certificate expired {cert.not_valid_after_utc:%Y-%m-%d}")
    if cert.not_valid_before_utc > now:
        problems.append("certificate is not valid yet")
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        problems.append("key is not ECDSA P-256")
    if cert.issuer != cert.subject:
        problems.append("certificate is not self-signed")
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
        oids = {p.policy_identifier.dotted_string for p in policies.value}
        if IEEE_2030_5_SELF_SIGNED_POLICY not in oids:
            problems.append("missing IEEE 2030.5 self-signed client policy OID")
        elif not policies.critical:
            problems.append("certificatePolicies extension is not critical")
    except x509.ExtensionNotFound:
        problems.append("missing certificatePolicies extension")
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not usage.value.digital_signature:
            problems.append("keyUsage lacks digitalSignature")
    except x509.ExtensionNotFound:
        problems.append("missing keyUsage extension")
    if key_pem is not None:
        key = serialization.load_pem_private_key(key_pem, password=None)
        fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if key.public_key().public_bytes(*fmt) != pub.public_bytes(*fmt):
            problems.append("private key does not match the certificate")
    return IdentityCheck(
        lfdi=lfdi, sfdi=sfdi_from_lfdi(lfdi), not_after=cert.not_valid_after_utc, problems=tuple(problems)
    )
