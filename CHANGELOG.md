# Changelog

## 0.4.0
- `ReadingGuard.accept(snapshot, profile, now=None)` filters a whole `MeterSnapshot`: readings the meter flags
  questionable and reads that failed become None, summation channels and ToU tiers go through `register()`, power
  through `power()`. It returns `AcceptedReadings(values, tou)`. Consumers no longer re-implement this policy.
- `questionable(measurement)` exposes the meter's own verdict on a reading.
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
