# Changelog

## 0.4.0 (first release on PyPI)

Changes since the last pre-release (0.3.3).

### Breaking changes

- `ReadingGuard.as_dict()` / `load()` are now `to_dict()` / `ReadingGuard.from_dict()` (and `restore()`, in place);
  `TransportStats.as_dict()` is `to_dict()`. State saved by 0.3.x still loads.
- `MeterIdentityMismatch` derives from `MeterError`, no longer `MeterConnectionError`: a back-off handler must not
  swallow "another device is at this address".
- `Meter.transport` is private; `Meter.host`, `port` and `dcap_path` are read-only (a moved meter means a new
  `Meter`).
- `MeterAuthError.reason` (and `PeerInfo.auth_reason`) is typed `AuthReason`, a closed `Literal`.
- `snapshot.errors` may hold `TIME_ERROR_KEY` (`":time"`), which is not a channel key.
- `ReadingGuard` rules (below): rebases need time as well as reads, are all recorded, and registers are judged at the
  time the meter took them.
- Every `from_dict()` accepts any mapping and raises `ProfileError` for malformed data, where some raised
  `KeyError`/`TypeError`/`ValueError` before.
- A body without framing that ends without close_notify is a `MeterProtocolError`.

### Reading guard

- `ReadingGuard.accept(snapshot, profile, now=None)` filters a whole `MeterSnapshot`: readings the meter flags
  questionable and reads that failed become None, summation channels and ToU tiers (tier 0, the total, included)
  go through `register()`, power through `power()`. It returns `AcceptedReadings(values, tou)`.
  `questionable(measurement)` exposes the meter's own verdict on a reading.
- A new series is adopted only once it has lasted as well as repeated: `confirm` reads over `confirm_seconds`
  (3 reads, 1 h) upward, `confirm_decrease` over `confirm_decrease_seconds` (12 reads, 24 h) downward. A meter
  answering 0 for a while is not taken for a reset, however often it is polled. A run of reads survives a restart
  (it is part of `to_dict()`) and a stray reading (one per four consistent reads).
- Every adoption is recorded in `.rebases` (downward ones also in `.resets`). After any rebase the replaced baseline is
  kept for a day, and the guard returns to it at once if the meter does.
- A register is judged at the time the meter took the reading, so one it refreshes only hourly (ToU tiers on an
  Itron) is not mistaken for a spike. `register(..., monotonic=False)` guards a net register.

### Meter

- `read(partial=True, include_time=True)` is partial for the clock too: a failed Time read lands in
  `snapshot.errors[TIME_ERROR_KEY]`. The clock is read first, so `fetched_at` is when it answered.
- `read_intervals_since()` and `read_interval_history()` are one batch (one connection, one deadline).
- `Meter.adopt(profile)` pins a cached profile's meter for every call, the interval calls included.
- `Meter.from_files()` takes `create()`'s typed keyword arguments and `os.PathLike` paths.
- `discover()` pins the first device it reaches for the rest of its walk (a reconnect cannot mix two devices), and
  leaves no pin if the walk fails.
- A replayed snapshot keeps `MeterNotFound` and `MeterHttpError` as such, and replaying is idempotent.
- `KEY_SCHEME`, `PROFILE_VERSION`, `TIME_ERROR_KEY` and `Reading` are exported from the package root. Exceptions can be
  copied and pickled; `MeterIdentityMismatch`'s message shortens the LFDIs (its attributes keep them whole).

### Input a healthy meter never sends

Everything fails as a typed `MeterError`, quickly and within bounded memory:
- Chunked framing is bounded at every step (size line, declared size, body, trailers); sizes are hex, optionally
  zero-padded. `Content-Length` must be plain digits. Buffers grow in place.
- XML with a document type declaration, an encoding expat cannot read, or more than 100,000 elements is refused.
  Element text is clamped to 1024 characters, hrefs over 1024 are refused, and numbers too long for any 2030.5 type
  are errors rather than truncated.
- Durations and interval lengths are bounded to UInt32, `localID` to HexBinary16, `touTier` to UInt8, and date
  arithmetic past the calendar is an error. A discovered and a cached `ReadingType` are checked alike.
- Lists longer than 2000 items, needing over 200 pages or over 8 MiB are refused; repeated href-less items end the
  walk.
- Device text in error messages is truncated. `PeerCertificate` leaves the DER (which can hold a serial number) out
  of `repr()`. Non-ASCII PEM raises `InvalidIdentity` without carrying the key text in the exception's context.

### Command line, docs and packaging

- `discover` always walks the meter and rewrites `--profile`. `read` and `intervals` use the cache and discover
  again when it is corrupt, names a path the meter no longer has, or is another meter's. Mistakes give one line,
  not a traceback. The profile and a generated key are written with mode 0600. `identity` also prints the LFDI as
  utility portals accept it. Help texts, defaults and `--version`.
- The public API is the package root plus `aio2030dot5.locate`; every module declares `__all__`, and every public
  member has a docstring.
- Documentation: the exception hierarchy, the real per-request timeout bounds, runnable zeroconf and Home
  Assistant examples, how the meter is authenticated (LFDI pinning, trust on first use), provenance and authorship.
- Packaging: authors and project URLs, a `dev` dependency group (`uv run pytest`), NOTICE and SECURITY.md. CI on
  Python 3.12-3.14 plus the lowest allowed dependency versions; releases from `v*` tags run the full CI and publish
  through PyPI trusted publishing; a TestPyPI dry run publishes `<version>.devN`.

## Pre-releases

0.3.0 to 0.3.3 were tagged in git but never published.

### 0.3.3
- `format_lfdi()` accepts any grouping, case and surrounding whitespace, and raises `ValueError` unless 40 hex
  digits remain, instead of grouping whatever it was given.
- `MeterProfile.from_dict()` type-checks every optional string field (a malformed cache is a `ProfileError`) and
  treats blank strings as None.

### 0.3.2
- `format_lfdi()` groups an LFDI in fives (`431ED-86C1F-…`). Xcel Energy's portal rejects groups of four.

### 0.3.1
- `MeterProfile` keeps the meter's `model`, `serial_number` and `hardware_version` from DeviceInformation (None when
  empty). Profiles cached by older versions still load; `PROFILE_VERSION` is unchanged.

### 0.3.0
- `ReadingGuard`; the per-meter lock is keyed by resolved address; `format_lfdi()`; `manufacturer_name()`.

Earlier work: see the git history.
