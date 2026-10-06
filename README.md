# aio2030dot5

An async Python client for **IEEE 2030.5 (Smart Energy Profile 2.0) smart meters on the
local network ("HAN" interface)**. It was built for, and tested against, the **Itron Gen5 Riva**
meters that Xcel Energy deploys with local "Launchpad" access, but it contains nothing
Xcel-specific.

## Why another client

These meters are fragile:
- They serve **one TLS connection at a time**.
- They close idle connections after **30 s**.
- They intermittently fail handshakes with **`BAD_SIGNATURE`**.
- They are reported to stop answering ("clamp down") when polled hard.

This library is designed around that:

- **One connection per batch, never two at once.** An `asyncio.Lock` serialises all access.
  Connections are spaced by a minimum interval, and every read in a batch shares one keep-alive connection.
- **TLS session resumption.** A full ECDHE-ECDSA handshake costs the meter ~330 ms; a resumed one
  ~60–160 ms. asyncio's TLS transport cannot resume sessions, so TLS runs through `ssl.MemoryBIO`.
- **Correct HTTP framing.** It reads by Content-Length or chunked framing and never waits for EOF.
- **Policy-free.** There is no polling loop. The only retries are transport-level and bounded:
  - one handshake retry after `BAD_SIGNATURE`;
  - one reconnect when the meter drops a kept-alive connection before answering (GET is idempotent).

  Exceptions say what happened, and the caller decides:
  - `MeterConnectionError`, `MeterTimeout` or `MeterBusy` → back off;
  - `MeterAuthError(reason=...)` → the certificate is not registered, or expired;
  - `MeterNotFound` → rediscover;
  - `ProfileError` → a cached profile is stale.

  One call can take a while on a struggling meter: pacing, connect, a handshake retry and the response add up to
  about 3 minutes with the default timeouts. Wrap calls in your own deadline if you need one.
- **One meter, one lock.** Every `Meter` object for the same meter on an event loop shares a lock and connection pacing,
  keyed by resolved address and port. "meter.local" and its IP are one meter. Batches are not re-entrant: starting one from inside
  another raises `RuntimeError` rather than deadlocking.
- **Discovery by meaning, not by path.** Each MeterReading is classified from its ReadingType
  (quantity, statistic, direction, phase), with its description breaking ties older agents leave. Callers ask for
  "energy delivered" rather than `/upt/1/mr/3`.
- **Stable channel keys.**
  - Keys are public API: `{quantity}[_{statistic}][_{direction}][_{phase}]`, e.g. `energy_summation_delivered`.
  - `power` is the signed instantaneous demand.
  - They are pinned by tests against real agent captures, and versioned by `KEY_SCHEME`: a cached profile from
    another scheme raises `ProfileError`.
  - Two readings that classify identically are numbered `_2`, `_3` in mRID order and flagged `ambiguous`.

- **Identified by certificate, not address.** In IEEE 2030.5 a device's LFDI is the SHA-256 of its certificate.
  - Every connection checks the meter's certificate against `expected_lfdi` before sending a request. Another device
    at the address raises `MeterIdentityMismatch`, e.g. after a DHCP change.
  - `discover()` pins the meter it finds, and a cached profile carries the pin.
  - `probe_tls()` reads the meter's identity even before our certificate is registered: the meter sends its
    certificate in the clear before it refuses ours.
- **Found by mDNS.** Meters advertise `_smartenergy._tcp` with their SFDI in the instance name.
  - `parse_advertisement()` reads an advertisement that a zeroconf library resolved.
  - With the `zeroconf` extra, `aio2030dot5.locate.async_locate(aiozc, sfdi)` finds the meter's current address.

## Usage

```python
from aio2030dot5 import Meter, Quantity, Statistic, Direction

meter = await Meter.from_files("192.0.2.19", "cert.pem", "key.pem")
profile = await meter.discover()            # ~30 GETs on ONE connection; cache profile.to_dict()

snap = await meter.read(profile, profile.channels, include_time=True)
snap.values["power"].value                  # W, signed (negative while exporting)
snap.values["energy_summation_delivered"]   # Wh imported
snap.tou["energy_tou_summation_delivered"]  # {tier: Measurement}; tier 0 is the total

ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
await meter.read_latest_intervals(ch)       # completed 15-minute intervals of the newest set
```

Without a fixed address (the `zeroconf` extra):

```python
from zeroconf.asyncio import AsyncZeroconf
from aio2030dot5.locate import async_locate

adv = await async_locate(AsyncZeroconf(), "123456789014")   # the meter's SFDI
meter = Meter(adv.host, ctx, adv.port, expected_lfdi=lfdi)  # the connection proves it is that meter
profile = await meter.discover(dcap_path=adv.dcap_path)
```

From the command line:

```
python -m aio2030dot5 identity --cert cert.pem --key key.pem [--generate]   # LFDI to register with the utility
python -m aio2030dot5 read --host 192.0.2.19 --cert cert.pem --key key.pem --profile profile.json
```

## For a Home Assistant integration

Everything a config flow and coordinator need, without files:

```python
from aio2030dot5 import Identity, Meter, MeterAuthError, generate_identity, load_identity, REDACT_KEYS

identity = await hass.async_add_executor_job(generate_identity)  # or load_identity(cert, key) from a form
entry_data = {"identity": identity.to_dict(), "sfdi": adv.sfdi}  # secret: redact with REDACT_KEYS

meter = await Meter.create(host, Identity.from_dict(entry_data["identity"]), dcap_path=adv.dcap_path)
peer = await meter.probe_tls()          # who is there, even before registration
if peer.client_accepted:
    info = await meter.probe()          # 1-3 GETs: lFDI/sFDI, manufacturer, software version
```

- **`Timeouts(batch=…)`** is a per-call deadline. It starts once the meter's lock is held, so time spent queued behind
  another reader never counts against it.
- **`TouRegister`** is a ToU register: a read-only `{tier: Measurement}` with `.total` and `.tiers`.
- **`ReadingGuard`** is an optional plausibility filter. It drops power beyond ±50 kW, and register decreases or rises
  faster than the service allows. It rebases on consistent new series, and records register resets in `.resets`.
- **`hourly_energy(intervals)`** sums 15-minute intervals into the hourly rows long-term statistics want.
- **`to_dict()` / `from_dict()`** exist on snapshots, measurements, intervals, `MeterInfo` and `Identity`, for test
  fixtures and diagnostics.

## Client identity

The meter admits a client whose self-signed certificate's **LFDI** has been registered with the utility.
`aio2030dot5.identity` can:
- generate a certificate in the profile an Itron meter accepts;
- compute the LFDI and SFDI;
- validate a certificate/key pair.

These certificates have a 3-year life.

## Tests

The tests run against **responses captured from a real meter** (agent 3.2.50, with its identifiers
anonymised), served by a fake meter that speaks the same TLS profile and models the idle timeout,
paging and session resumption.

```
pip install -e '.[zeroconf]' pytest pytest-asyncio && pytest
```
