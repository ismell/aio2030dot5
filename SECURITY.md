# Security policy

aio2030dot5 handles a client certificate and its private key, and talks TLS to a
meter on your local network. Please report security problems privately through
GitHub's "Report a vulnerability" (Security tab → Advisories) rather than in a
public issue. Expect a first reply within a week.

Supported versions: the latest release.

Notes for users:
- The private key lives where you keep it: your files, or the PEM text you pass
  in. `Identity` leaves it out of `repr()`; use `REDACT_KEYS` when logging or
  exporting diagnostics.
- Python's `ssl` module can only load a key from a file. So building a TLS
  context from PEM text (`build_ssl_context_from_pem`, `async_build_ssl_context`)
  writes it briefly to a fresh private temporary directory (mode 0700, files
  0600). The directory is removed before the call returns.
- The meter's server certificate is not verified (meters present self-signed or
  vendor certificates with no usable trust anchor). That relaxation is scoped to
  the meter connection's own `SSLContext` and never affects other TLS in your
  process.
