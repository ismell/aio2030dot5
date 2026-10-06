"""Client identity for IEEE 2030.5 HAN access: certificates, LFDI and SFDI.

A HAN meter admits a client whose self-signed certificate's LFDI has been
registered with the utility (for Xcel Energy, in the Launchpad portal). The
profile generated here mirrors a certificate an Itron Gen5 Riva meter is
known to accept: P-256 / ECDSA-SHA256, CN=MeterReaderHanClient, critical
basicConstraints CA:TRUE, critical keyUsage digitalSignature, and the
critical IEEE 2030.5 self-signed-client policy OID.

Identities are plain PEM text, so they can live in a config entry:
``Identity.to_dict()`` / ``Identity.from_dict()``. The private key never
appears in a repr or a log message.
"""

from __future__ import annotations

import hashlib
import re
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .exceptions import InvalidIdentity

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
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", lfdi):
        raise ValueError(f"an LFDI is 40 hex digits, got {lfdi!r}")
    digits = str(int(lfdi[:9], 16))
    check = (10 - sum(int(d) for d in digits) % 10) % 10
    return f"{digits}{check}"


@dataclass(frozen=True, slots=True)
class Identity:
    """A client certificate and its private key, as PEM text.

    Build one with :func:`generate_identity` or :func:`load_identity`. Only
    ``cert_pem`` and ``key_pem`` are stored by :meth:`to_dict`; the rest is
    derived from the certificate.
    """

    cert_pem: str
    key_pem: str = field(repr=False)
    lfdi: str
    sfdi: str
    not_after: datetime
    problems: tuple[str, ...] = ()  # what check_identity() found when loaded

    def days_remaining(self, now: datetime | None = None) -> int:
        return (self.not_after - (now or datetime.now(UTC))).days

    def expired(self, now: datetime | None = None) -> bool:
        return self.not_after <= (now or datetime.now(UTC))

    def to_dict(self) -> dict[str, str]:
        """Secret: holds the private key. Redact with ``REDACT_KEYS``."""
        return {"cert_pem": self.cert_pem, "key_pem": self.key_pem}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Identity:
        """Reload a stored identity. Tolerates expiry and profile problems
        (they are in ``problems``); raises :class:`InvalidIdentity` only if it
        cannot be used at all."""
        try:
            cert, key = data["cert_pem"], data["key_pem"]
        except (KeyError, TypeError) as err:
            raise InvalidIdentity("not a stored identity", ("missing cert_pem or key_pem",)) from err
        return load_identity(cert, key, strict=False)


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
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode("ascii"),
        lfdi=lfdi,
        sfdi=sfdi_from_lfdi(lfdi),
        not_after=cert.not_valid_after_utc,
    )


# Problems that make an identity unusable, as opposed to one a meter may
# refuse (wrong profile) or that has merely expired.
_FATAL = ("private key does not match the certificate",)


def load_identity(
    cert_pem: str | bytes, key_pem: str | bytes, *, strict: bool = True, now: datetime | None = None
) -> Identity:
    """An :class:`Identity` from PEM text, e.g. pasted into a setup form.

    ``strict`` (for importing): any problem :func:`check_identity` finds --
    expired, wrong key type, missing 2030.5 policy -- raises
    :class:`InvalidIdentity` listing them all. ``strict=False`` (for
    reloading one already in use): only an unusable pair raises, and the
    rest are kept in ``Identity.problems``.
    """
    cert_b = cert_pem.encode("ascii", "replace") if isinstance(cert_pem, str) else cert_pem
    key_b = key_pem.encode("ascii", "replace") if isinstance(key_pem, str) else key_pem
    check = check_identity(cert_b, key_b, now=now)
    fatal = [p for p in check.problems if p in _FATAL]
    if fatal or (strict and check.problems):
        raise InvalidIdentity("identity cannot be used: " + "; ".join(check.problems), check.problems)
    try:
        cert_text, key_text = cert_b.decode("ascii").strip() + "\n", key_b.decode("ascii").strip() + "\n"
    except UnicodeDecodeError as err:
        raise InvalidIdentity("PEM text must be ASCII", ("PEM text must be ASCII",)) from err
    return Identity(
        cert_pem=cert_text,
        key_pem=key_text,
        lfdi=check.lfdi,
        sfdi=check.sfdi,
        not_after=check.not_after,
        problems=check.problems,
    )


def check_identity(
    cert_pem: str | bytes, key_pem: str | bytes | None = None, *, now: datetime | None = None
) -> IdentityCheck:
    """Validate a certificate (and optionally its key) against what a meter
    requires. Returns every problem found instead of raising on the first;
    raises :class:`InvalidIdentity` only when the input cannot be parsed."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("ascii", "replace")
    if isinstance(key_pem, str):
        key_pem = key_pem.encode("ascii", "replace")
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as err:
        raise InvalidIdentity("not a PEM certificate", ("certificate is not valid PEM",)) from err
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
    else:
        try:
            cert.verify_directly_issued_by(cert)
        except (InvalidSignature, ValueError, TypeError):
            problems.append("certificate's self-signature does not verify")
    if not isinstance(cert.signature_hash_algorithm, hashes.SHA256):
        problems.append("certificate is not signed with SHA-256")
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
        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (ValueError, TypeError) as err:
            # TypeError: the key is encrypted.
            raise InvalidIdentity("unusable private key", (f"private key: {err}",)) from err
        fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if key.public_key().public_bytes(*fmt) != pub.public_bytes(*fmt):
            problems.append("private key does not match the certificate")
    return IdentityCheck(
        lfdi=lfdi, sfdi=sfdi_from_lfdi(lfdi), not_after=cert.not_valid_after_utc, problems=tuple(problems)
    )
