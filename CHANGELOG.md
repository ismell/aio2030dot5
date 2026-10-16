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
- `ReadingGuard` rules (below): growth is bounded by when a value was first and last seen, rebases need observed time
  as well as reads and are all recorded. `ReadingGuard.registers` holds `(value, first seen)`, with `.last_seen`
  beside it; `ReadingGuard.pending` is a list of keys (the runs are internal). State saved by 0.3.x still loads.
- Every `from_dict()` accepts any mapping and raises `ProfileError` for malformed data, where some raised
  `KeyError`/`TypeError`/`ValueError` before.
- A body without framing that ends without close_notify is a `MeterProtocolError`.
- `MeterHttpError(path, status, reason_phrase)` keeps the HTTP reason phrase as `.reason_phrase`
  (`MeterAuthError.reason` is the `AuthReason`).
- Bytes after a complete response close the connection instead of being read as the next response.

### Reading guard

- `ReadingGuard.accept(snapshot, profile, now=None)` filters a whole `MeterSnapshot`: readings the meter flags
  questionable and reads that failed become None, summation channels and ToU tiers (tier 0, the total, included)
  go through `register()`, power through `power()`. It returns `AcceptedReadings(values, tou)`.
  `questionable(measurement)` exposes the meter's own verdict on a reading.
- A register may grow by `max_power` times the time since its value was first seen, but for no more than
  `max_refresh` (2 h) past its last read: a ToU tier the meter refreshes hourly may step by an hour's worth, a
  spike after a quiet weekend is still a spike, and growth while the consumer was down is allowed.
- A new series is adopted only once it has been observed long enough as well as repeated: `confirm` reads over
  `confirm_seconds` (3 reads, 1 h) upward, `confirm_decrease` over `confirm_decrease_seconds` (12 reads, 24 h)
  downward, with each gap between reads counting for at most `max_gap` (2 h). A meter answering 0 for a while is not
  taken for a reset, however often it is polled; a slow or flaky poller still confirms a real one. A run survives a
  restart (it is part of `to_dict()`) and tolerates one stray read per four consistent ones.
- Every adoption is recorded in `.rebases` (downward ones also in `.resets`). After any rebase the replaced baseline is
  kept for a day, and the guard returns to it at once if the meter does.
- All times are the consumer's clock, never the meter's. `register(..., monotonic=False)` guards a net register.
  `restore()` ignores malformed entries one by one.

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
  Exceptions can be copied and pickled with their state. Messages and logs, debug logs included, show only the last
  six digits of an LFDI (`short_lfdi`) and of an SFDI in an mDNS name, which tells devices apart without revealing
  them; attributes keep them whole. A cached profile's `poll_rate` is bounded like a discovered one.

### Input a healthy meter never sends

Everything fails as a typed `MeterError`, quickly and within bounded memory:
- Chunked framing is bounded at every step (size line, declared size, body, trailers); sizes are hex, optionally
  zero-padded. `Content-Length` must be plain digits. Buffers grow in place.
- XML with a document type declaration, an encoding expat cannot read, or more than 100,000 markup characters
  (`<` or `=`) is refused. Element text is clamped to 1024 characters, hrefs over 1024 are refused, and integers must be plain ASCII
  digits short enough for a 2030.5 type (never truncated). `pollRate` is bounded to UInt32.
- Durations and interval lengths are bounded to UInt32, `localID` to HexBinary16, `touTier` to UInt8, and date
  arithmetic past the calendar is an error. A discovered and a cached `ReadingType` are checked alike.
- Lists longer than 2000 items, needing over 200 pages or over 8 MiB are refused; repeated href-less items end the
  walk.
- Device text in error messages is truncated. `PeerCertificate` leaves the DER (which can hold a serial number) out
  of `repr()`. Non-ASCII PEM raises `InvalidIdentity` without carrying the key text in the exception's context.

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
