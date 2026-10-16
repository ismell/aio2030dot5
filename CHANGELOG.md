# Changelog

## 0.4.0
- `ReadingGuard.accept(snapshot, profile, now=None)` filters a whole `MeterSnapshot`: readings the meter flags
  questionable and reads that failed become None, summation channels and ToU tiers go through `register()`, power
  through `power()`. It returns `AcceptedReadings(values, tou)`. Consumers no longer re-implement this policy.
- `questionable(measurement)` exposes the meter's own verdict on a reading.
- `ReadingGuard` adopts a new series only once it has lasted (`confirm_seconds`, 1 h, upward; `confirm_decrease_seconds`,
  24 h, downward), not after a number of reads, so a meter answering 0 for a while is not taken for a reset however
  often it is polled. Every adoption is recorded in `.rebases`; after a downward one the earlier baseline is kept for a
  day and returned to if the meter comes back to it. `register(..., monotonic=False)` guards a net register.
- Renamed for consistency with every other type: `ReadingGuard.to_dict()` / `ReadingGuard.from_dict()` (plus
  `restore()`, in place) replace `as_dict()` / `load()`; `TransportStats.to_dict()` replaces `as_dict()`.
- `read(partial=True, include_time=True)` is partial for the clock too: a failed Time read lands in
  `snapshot.errors[TIME_ERROR_KEY]` instead of discarding the whole snapshot. The clock is read first, so
  `fetched_at` is when it answered and never later than the values.
- `read_intervals_since()` and `read_interval_history()` are one batch (one connection, one deadline), like every
  other call.
- `MeterIdentityMismatch` derives from `MeterError`, no longer `MeterConnectionError`: a back-off handler must not
  swallow "another device is at this address".
- `MeterAuthError.reason` (and `PeerInfo.auth_reason`) is typed `AuthReason`, a closed `Literal`.
- `Meter.from_files()` takes the same typed keyword arguments as `Meter.create()`. `Meter.host`, `port` and
  `dcap_path` are read-only (a moved meter means a new `Meter`), and the transport is private.
- `discover()` pins the first device it reaches for the rest of its walk, so a reconnect cannot mix two devices.
- A replayed snapshot (`MeterSnapshot.from_dict`) keeps `MeterNotFound` errors as such.
- `KEY_SCHEME`, `PROFILE_VERSION` and `TIME_ERROR_KEY` are exported from the package root.
- Packaging: authors and project URLs, a `dev` dependency group (`uv run pytest`), NOTICE and SECURITY.md.

## 0.3.3
- `format_lfdi()` accepts any grouping, case and surrounding whitespace, and raises `ValueError` unless 40 hex
  digits remain, instead of grouping whatever it was given.
- `MeterProfile.from_dict()` type-checks every optional string field (a malformed cache is a `ProfileError`) and
  treats blank strings as None.

## 0.3.2
- `format_lfdi()` groups an LFDI in fives (`431ED-86C1F-…`). Xcel Energy's portal rejects groups of four.

## 0.3.1
- `MeterProfile` keeps the meter's `model`, `serial_number` and `hardware_version` from DeviceInformation (None when
  empty). Profiles cached by older versions still load; `PROFILE_VERSION` is unchanged.

## 0.3.0
- `ReadingGuard`; the per-meter lock is keyed by resolved address; `format_lfdi()`; `manufacturer_name()`.

Earlier versions: see the git history.
