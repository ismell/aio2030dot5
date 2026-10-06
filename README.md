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
- **Policy-free.** There is no polling loop and no retries beyond one `BAD_SIGNATURE` handshake retry. Exceptions say
  what happened (`MeterConnectionError`/`MeterTimeout` → back off; `MeterAuthError` → certificate not
  registered or expired; `MeterNotFound` → rediscover), and the caller decides.
- **Discovery by meaning, not by path.** Each MeterReading is classified from its ReadingType
  (quantity, statistic, direction, phase), so callers ask for "energy delivered" rather than `/upt/1/mr/3`.

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

From the command line:

```
python -m aio2030dot5 identity --cert cert.pem --key key.pem [--generate]   # LFDI to register with the utility
python -m aio2030dot5 read --host 192.0.2.19 --cert cert.pem --key key.pem --profile profile.json
```

## Client identity

The meter admits a client whose self-signed certificate's **LFDI** has been registered with the utility.
`aio2030dot5.identity` (needs the `identity` extra, i.e. `cryptography`) can:
- generate a certificate in the profile an Itron meter accepts;
- compute the LFDI and SFDI;
- validate a certificate/key pair.

These certificates have a 3-year life.

## Tests

The tests run against **responses captured from a real meter** (agent 3.2.50, with its identifiers
anonymised), served by a fake meter that speaks the same TLS profile and models the idle timeout,
paging and session resumption.

```
pip install -e '.[identity]' pytest pytest-asyncio && pytest
```
