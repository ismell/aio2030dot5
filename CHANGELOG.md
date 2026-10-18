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
- `ReadingGuard` rules (below): growth is bounded by when a value was first and last seen, and a new baseline needs
  a day of observation as well as reads, in both directions (it was 3 reads in 1 h upward). The constructor takes
  `max_power`, `confirm`, `confirm_seconds` and `max_refresh`. `ReadingGuard.registers` holds `(value, first seen)`, with `.last_seen`
  beside it; `ReadingGuard.pending` is a list of keys (the runs are internal). State saved by 0.3.x still loads.
- Every `from_dict()` accepts any mapping and raises `ProfileError` for malformed data (`Identity`:
  `InvalidIdentity`), where some raised `KeyError`/`TypeError`/`ValueError` before. `ReadingGuard.from_dict()`
  restores its own `to_dict()` output and 0.3.x state.
- `MeterHttpError(path, status, reason_phrase)` keeps the HTTP reason phrase as `.reason_phrase`; the keyword
  argument and attribute were `reason` (`MeterAuthError.reason` is the `AuthReason`).
- Bytes after a complete response close the connection instead of being read as the next response.

### Reading guard

- `ReadingGuard.accept(snapshot, profile, now=None)` filters a whole `MeterSnapshot`: readings the meter flags
  questionable and reads that failed become None, summation channels and ToU tiers (tier 0, the total, included)
  go through `register()`, power through `power()`. It returns `AcceptedReadings(values, tou, rebased)`.
  `questionable(measurement)` exposes the meter's own verdict on a reading.
- A register may grow by `max_power` times its allowance: the time since its value was first seen, but no more than
  `max_refresh` (90 min) past its latest accepted read. A ToU tier the meter refreshes hourly may step by what the
  time since its last change allows, a spike after a quiet weekend is still a spike, and time the consumer was
  down counts in full. A small decrease below an accepted value (one within the allowance) holds that value instead
  of being rejected, so a consumer's total stays right.
- A new baseline is adopted only after `confirm` consistent reads (12) over `confirm_seconds` (24 h) of observed
  time, in either direction; the gap before each read counts for at most 2 h, so no outage or restart confirms
  anything. A run survives a restart (it is part of `to_dict()`) and tolerates one stray read per four consistent
  ones.
- Every adoption is recorded in `.rebases` (downward ones also in `.resets`) and named in
  `AcceptedReadings.rebased`.
- All times are the consumer's clock, never the meter's; if it steps back, a register is allowed `max_refresh`.
  `register(..., monotonic=False)` guards a net register.

### Meter

- `read(partial=True, include_time=True)` is partial for the clock too: a failed Time read lands in
  `snapshot.errors[TIME_ERROR_KEY]`. The clock is read first, so `fetched_at` is when it answered.
- `read_intervals_since()` and `read_interval_history()` are one batch (one connection, one deadline).
- `Meter.adopt(profile)` pins a cached profile's meter for every call, the interval calls included.
- `Meter.from_files()` takes `create()`'s typed keyword arguments and `os.PathLike` paths.
- `discover()` pins the first device it reaches for the rest of its walk (a reconnect cannot mix two devices), and
  leaves no pin if the walk fails.
- A replayed snapshot keeps `MeterNotFound` and `MeterHttpError` as such, and replaying is idempotent.
- `KEY_SCHEME`, `PROFILE_VERSION`, `TIME_ERROR_KEY`, `Reading` and `short_lfdi` are exported from the package root.
  Messages and logs, debug logs included, show only the last six digits of an LFDI (`short_lfdi`) and the last three
  of an SFDI in an mDNS name, which tells devices apart without revealing them; attributes keep them whole. A host
  you pass appears as given, so pass an address rather than the meter's `itrondnsserver-<SFDI>.local` name if logs
  will be shared.

### Privacy

- `PeerCertificate` leaves the DER (which can hold a serial number) out of `repr()`. Non-ASCII PEM raises
  `InvalidIdentity` without carrying the key text in the exception's context.

### Command line, docs and packaging

- `discover` always walks the meter and rewrites `--profile`. `read` and `intervals` use the cache and discover
  again when it is corrupt, names a path the meter no longer has (through the same, pinned meter), or is another
  meter's. Mistakes give one line,
  not a traceback. The profile and a generated key are written with mode 0600. `identity` also prints the LFDI as
  utility portals accept it. Help texts, defaults and `--version`.
- The public API is the package root plus `aio2030dot5.locate`; every module declares `__all__`, and every public
  member has a docstring.
- Documentation: the exception hierarchy, the real per-request timeout bounds, runnable zeroconf and Home
  Assistant examples, how the meter is authenticated (LFDI pinning, trust on first use), provenance and authorship.
- Packaging: authors and project URLs, a `dev` dependency group (`uv run pytest`), NOTICE and SECURITY.md. CI on
  Python 3.12-3.14 plus the lowest allowed dependency versions; releases from `v*` tags run the full CI and publish
  through PyPI trusted publishing; a TestPyPI dry run publishes `<version>.devN`. RELEASING.md lists the repository
  settings releases rely on.

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
