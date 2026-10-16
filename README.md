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
- They can stop answering for hours while staying on the Wi-Fi (seen on the author's meter; a forced Wi-Fi
  reconnect brings it back).

This library is designed around that:

- **One connection per batch, never two at once.** An `asyncio.Lock` serialises all access.
  Connections are spaced by a minimum interval, and every read in a batch shares one keep-alive connection.
- **TLS session resumption.** A full ECDHE-ECDSA handshake costs the meter ~330 ms; a resumed one
  ~60–160 ms. asyncio's TLS transport cannot resume sessions, so TLS runs through `ssl.MemoryBIO`.
- **Correct HTTP framing.** It reads by Content-Length or chunked framing and never waits for EOF.
- **Policy-free.** There is no polling loop. The only retries are transport-level and bounded:
  - one handshake retry after `BAD_SIGNATURE`;
  - one reconnect when the meter drops a kept-alive connection before answering (GET is idempotent).

  Exceptions say what happened, and the caller decides. Everything the meter (or a device at its address) causes
  is a `MeterError`; mistakes in the calling code raise `ValueError` or `RuntimeError`.

  ```
  MeterError
  ├── MeterConnectionError        back off and retry (MeterTimeout, MeterBusy are kinds of it)
  ├── MeterIdentityMismatch       another device answers at this address: locate the meter again (mDNS)
  ├── MeterAuthError              our certificate is refused (.reason says why): the user must act
  ├── MeterProtocolError          the meter answered something unusable
  │   └── MeterHttpError
  │       └── MeterNotFound       a cached path is gone: rediscover
  ├── ProfileError                a cached profile is unusable: rediscover
  └── InvalidIdentity             a certificate/key that cannot be used
  ```

  Each request is bounded by `Timeouts` (by default connect 10 s, handshake 20 s, response 20 s, with one
  handshake retry and one reconnect), but one call makes several requests (`discover()` about 30). For a deadline
  on the whole call, set `Timeouts(batch=…)`; time spent waiting for the meter's lock or for connection pacing does
  not count against it.
- **One meter, one lock.** Every `Meter` object for the same meter on an event loop shares a lock and connection pacing,
  keyed by resolved address and port. "meter.local" and its IP are one meter. Batches are not re-entrant: starting one from inside
  another for the same meter raises `RuntimeError` rather than deadlocking.
- **Discovery by meaning, not by path.** Each MeterReading is classified from its ReadingType
  (quantity, statistic, direction, phase), with its description breaking ties older agents leave. Callers ask for
  "energy delivered" rather than `/upt/1/mr/3`.
- **Stable channel keys.**
  - Keys are public API: `{quantity}[_{statistic}][_{direction}][_{phase}]`, e.g. `energy_summation_delivered`.
  - `power` is the signed instantaneous demand.
  - They are pinned by tests against real agent captures, and versioned by `KEY_SCHEME`: a cached profile from
    another scheme raises `ProfileError`.
  - Two readings that classify identically are numbered `_2`, `_3` in mRID order and flagged `ambiguous`.

- **Identified by certificate, not address.** In IEEE 2030.5 a device's LFDI is the leftmost 160 bits of the
  SHA-256 of its certificate.
  - Every connection checks the meter's certificate against `expected_lfdi` before sending a request. Another device
    at the address raises `MeterIdentityMismatch`, e.g. after a DHCP change.
  - `discover()` pins the meter it finds. A cached profile carries the pin: `read()` takes it, and
    `meter.adopt(profile)` makes every call check it (the interval calls take a channel, not a profile). Simplest:
    store the meter's LFDI and pass `expected_lfdi=`.
  - `probe_tls()` reads the meter's identity even before our certificate is registered: the meter sends its
    certificate in the clear before it refuses ours.
- **Found by mDNS.** Meters advertise `_smartenergy._tcp` with their SFDI in the instance name.
  - `parse_advertisement()` reads an advertisement that a zeroconf library resolved.
  - With the `zeroconf` extra, `aio2030dot5.locate.async_locate(aiozc, sfdi)` finds the meter's current address.

## Install

```
pip install aio2030dot5               # or 'aio2030dot5[zeroconf]' for discovery
```

Python 3.12 or newer. The only required dependency is `cryptography`. The public API is what the package root
exports (`from aio2030dot5 import ...`, plus `aio2030dot5.locate` for discovery); submodules are internal.

## Usage

```python
from aio2030dot5 import Meter, Quantity, Statistic, Direction

meter = await Meter.from_files("192.0.2.19", "cert.pem", "key.pem")
profile = await meter.discover()  # ~30 GETs on ONE connection; cache profile.to_dict()

snap = await meter.read(profile, profile.channels, include_time=True)
snap.values["power"].value  # W, signed (negative while exporting)
snap.values["energy_summation_delivered"]  # Wh imported
snap.tou["energy_tou_summation_delivered"]  # {tier: Measurement}; tier 0 is the total

ch = profile.find(Quantity.ENERGY, Statistic.INTERVAL, Direction.DELIVERED)
await meter.read_latest_intervals(ch)  # completed 15-minute intervals of the newest two sets
```

Without a fixed address (the `zeroconf` extra):

```python
from zeroconf.asyncio import AsyncZeroconf
from aio2030dot5 import Meter, canonical_sfdi, load_identity
from aio2030dot5.locate import async_locate

identity = load_identity(cert_pem, key_pem)  # your certificate and key, as PEM text
sfdi = "123456789014"  # the meter's SFDI, as printed on it or shown by the utility's portal
async with AsyncZeroconf() as aiozc:  # or your application's shared instance
    adv = await async_locate(aiozc, sfdi)
if adv is None:
    raise SystemExit("meter not heard on the network")

# First contact: check that the device has the SFDI you expect, then pin its LFDI.
peer = await (await Meter.create(adv.host, identity, adv.port)).probe_tls()
if canonical_sfdi(peer.sfdi) != canonical_sfdi(sfdi):
    raise SystemExit("another device answered")
meter = await Meter.create(adv.host, identity, adv.port, expected_lfdi=peer.lfdi, dcap_path=adv.dcap_path)
profile = await meter.discover()  # every connection now proves it is that meter
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
probe = await Meter.create(adv.host, identity, adv.port)
peer = await probe.probe_tls()  # who is there, even before our certificate is registered
entry_data = {  # the identity is secret: redact with REDACT_KEYS
    "identity": identity.to_dict(),
    "meter_lfdi": peer.lfdi,  # pin it: every later connection must present this certificate
}

meter = await Meter.create(
    adv.host,
    Identity.from_dict(entry_data["identity"]),
    adv.port,
    expected_lfdi=entry_data["meter_lfdi"],
    dcap_path=adv.dcap_path,
)
if peer.client_accepted:
    info = await meter.probe()  # 1-3 GETs: lFDI/sFDI, manufacturer, model, serial, versions
```

- **`Timeouts(batch=…)`** is a per-call deadline. It starts once the meter's lock is held, and connection pacing does
  not count against it either.
- **`read(profile, channels, include_time=True, partial=True)`** suits a coordinator: a channel that fails is
  recorded in `snapshot.errors` (a failed clock read under `TIME_ERROR_KEY`) instead of failing the whole poll; a
  `MeterNotFound` there means the profile is stale.
- **`TouRegister`** is a ToU register: a read-only `{tier: Measurement}` with `.total` and `.tiers`.
- **`ReadingGuard`** is an optional plausibility filter. It drops power beyond ±50 kW, and register decreases or rises
  faster than the service allows since the register last changed (so a ToU tier the meter refreshes hourly may step
  by an hour's worth). A net register may move either way at that rate. It adopts a new series only once it has
  lasted: an hour and 3 reads upward, a day and 12 reads downward (a net register always uses the upward rule), with
  no gap over 30 minutes in the reads. All times are your clock, never the meter's. `.rebases` holds the time of each
  register's latest adoption and `.resets` that of its latest downward one, so a consumer can start a new
  accumulation cycle instead of booking the step.
  `guard.accept(snapshot, profile)` runs a whole snapshot through it, together with the meter's own "questionable"
  flags and failed reads, and returns `AcceptedReadings(values, tou)`. Persist `guard.to_dict()` and restore it with
  `ReadingGuard.from_dict(data)`.
- **`hourly_energy(intervals)`** sums 15-minute intervals into the hourly rows long-term statistics want.
- **`MeterProfile`** also keeps what the meter says it is (`model`, `serial_number`, `hardware_version`), None where the
  meter leaves them empty, as Itron does.
- **`to_dict()` / `from_dict()`** exist on snapshots, measurements, intervals, profiles, `MeterInfo`, `Identity` and
  `ReadingGuard`, for caches, test fixtures and diagnostics. `from_dict()` accepts any mapping and raises
  `ProfileError` for malformed data (`Identity`: `InvalidIdentity`); `ReadingGuard.from_dict()` ignores what it
  cannot use and starts fresh.

## Client identity

The meter admits a client whose self-signed certificate's **LFDI** has been registered with the utility.
The identity functions (`generate_identity`, `load_identity`, `check_identity`, `format_lfdi`, ...) can:
- generate a certificate in the profile an Itron meter accepts;
- compute the LFDI and SFDI;
- validate a certificate/key pair;
- show an LFDI for a person to register: `format_lfdi()` gives eight groups of five hex digits, the only grouping
  Xcel Energy's portal accepts besides none at all.

These certificates have a 3-year life.

## Tests

The tests run against **responses captured from a real meter**: the author's own Itron Gen5 Riva (agent 3.2.50),
with its device identifiers replaced; the readings are real. A fake meter serves them over the same TLS profile and
models the idle timeout, paging and session resumption.

```
uv run pytest            # or, with pip 25.1+: pip install -e . --group dev && pytest
uv run ruff check && uv run ruff format --check && uv run mypy src
```

## Provenance

Written from the IEEE 2030.5 standard, observations of the author's own meter, and facts learned from Xcel Energy's
Launchpad SDK, which the author was given access to. No code was copied from the SDK or from any vendor. This
project is not affiliated with or endorsed by Xcel Energy or Itron.

## Authorship

Written by Raul E Rangel with [Claude](https://claude.com/claude-code) (Anthropic) as a co-author; commits it helped
write carry a `Co-Authored-By: Claude` trailer. Licensed under the Apache License 2.0 (see LICENSE and NOTICE).
