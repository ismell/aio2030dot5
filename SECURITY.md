# Security policy

aio2030dot5 handles a client certificate and its private key, and talks TLS to a
meter on your local network. Please report security problems privately, not in a
public issue: use GitHub's "Report a vulnerability" (Security tab → Advisories),
or email raul@bestmail.us. Expect a first reply within a week.

Supported versions: the latest release.

## How the meter is authenticated

The meter's server certificate is not verified against a CA: meters present
self-signed or vendor certificates with no usable trust anchor. That relaxation
is scoped to the meter connection's own `SSLContext` and never affects other TLS
in your process.

Instead, the meter is authenticated by **pinning its LFDI**, which in IEEE 2030.5
is the SHA-256 of its certificate. Every connection compares the certificate the
device presents with `expected_lfdi` before any request is sent, and raises
`MeterIdentityMismatch` on a difference. Pass `expected_lfdi` when you know it.
If you do not, the first `discover()` pins whatever device answers (trust on
first use), and `probe_tls()` / `probe()` never pin. Before trusting a device you
found by mDNS, compare `probe_tls().sfdi` with the SFDI the meter advertises or
prints.

## Your private key

- It lives where you keep it: your files, or the PEM text you pass in.
  `Identity` leaves it out of `repr()`; use `REDACT_KEYS` when logging or
  exporting diagnostics.
- Python's `ssl` module can only load a key from a file. So building a TLS
  context from PEM text (`build_ssl_context_from_pem`, `async_build_ssl_context`)
  writes it briefly to a fresh private temporary directory (mode 0700, files
  0600). The directory is removed before the call returns.
- The command line writes a generated key, and any `--profile` cache (it names
  the meter), with mode 0600.
