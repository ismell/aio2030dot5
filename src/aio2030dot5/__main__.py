"""Talk to an IEEE 2030.5 HAN meter from the command line.

Every command that talks to a meter opens at most one connection per batch and
prints transport counters at the end. Meters serve one client at a time: stop
any other client of the meter (e.g. Home Assistant) first.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from . import InvalidIdentity, Meter, MeterError, MeterNotFound, MeterProfile, ProfileError, Statistic, __version__
from .identity import check_identity, format_lfdi, generate_identity


class _UsageError(Exception):
    """A mistake in the command line or its files: one line on stderr, exit 2."""


def _meter_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", required=True, help="the meter's address")
    p.add_argument("--port", type=int, default=8081, help="the meter's HTTPS port (default: 8081)")
    p.add_argument("--cert", required=True, help="client certificate (PEM)")
    p.add_argument("--key", required=True, help="client private key (PEM)")
    p.add_argument(
        "--profile",
        help="profile cache file: discover writes it; read and intervals use it if it is valid",
    )


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to a new or existing file readable by the owner only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # an existing file keeps its old mode otherwise
    with os.fdopen(fd, "w") as f:
        f.write(text)


async def _profile(meter: Meter, path: str | None, *, refresh: bool) -> MeterProfile:
    if path and not refresh and Path(path).exists():
        try:
            return MeterProfile.from_dict(json.loads(Path(path).read_text()))
        except (ValueError, ProfileError) as err:  # JSONDecodeError is a ValueError
            print(f"{path}: {err}; discovering again", file=sys.stderr)
    profile = await meter.discover()
    if path:
        # It names the meter (its LFDI, SFDI, serial number): keep it private.
        _write_private(Path(path), json.dumps(profile.to_dict(), indent=1))
    return profile


def _identity(args: argparse.Namespace) -> int:
    cert, key = Path(args.cert), Path(args.key)
    if args.generate:
        existing = [str(p) for p in (cert, key) if p.exists()]
        if existing:
            raise _UsageError(f"refusing to overwrite {', '.join(existing)}")
        ident = generate_identity()
        cert.write_text(ident.cert_pem)  # first: a failure here leaves no orphan key behind
        try:
            _write_private(key, ident.key_pem)
        except OSError:
            cert.unlink(missing_ok=True)
            raise
    check = check_identity(cert.read_bytes(), key.read_bytes())
    print(
        f"LFDI       {check.lfdi}\n"
        f"           {format_lfdi(check.lfdi)}   (as utility portals accept it)\n"
        f"SFDI       {check.sfdi}\n"
        f"expires    {check.not_after:%Y-%m-%d} ({check.days_remaining()} days)"
    )
    for p in check.problems:
        print(f"PROBLEM    {p}")
    return 0 if check.ok else 1


async def _run(args: argparse.Namespace) -> int:
    if args.cmd == "identity":
        return _identity(args)
    for path in (args.cert, args.key):
        if not Path(path).is_file():  # ssl's own error does not name the file
            raise _UsageError(f"{path}: no such file")
    meter = await Meter.from_files(args.host, args.cert, args.key, args.port)
    try:
        profile = await _profile(meter, args.profile, refresh=args.cmd == "discover")
        if args.cmd == "discover":
            print(json.dumps(profile.to_dict(), indent=1))
            return 0
        try:
            return await _use(meter, profile, args)
        except (MeterNotFound, ProfileError) as err:
            if not args.profile:
                raise
            # A path the cached profile names is gone, or it is another meter's.
            print(f"{args.profile}: {err}; discovering again", file=sys.stderr)
            meter = await Meter.from_files(args.host, args.cert, args.key, args.port)
            return await _use(meter, await _profile(meter, args.profile, refresh=True), args)
    except MeterError as err:
        print(f"error: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    finally:
        print(f"transport: {meter.stats.to_dict()}", file=sys.stderr)


async def _use(meter: Meter, profile: MeterProfile, args: argparse.Namespace) -> int:
    """Run ``read`` or ``intervals`` with ``profile``."""
    meter.adopt(profile)
    if args.cmd == "read":
        snap = await meter.read(profile, profile.channels, include_time=True)
        for key, m in snap.values.items():
            print(
                f"{key:40} {m.value!s:>14} {m.unit:5} {m.start:%Y-%m-%dT%H:%M:%SZ}"
                if m.start
                else f"{key:40} {m.value!s:>14} {m.unit}"
            )
        for key, tiers in snap.tou.items():
            for tier, m in sorted(tiers.items()):
                print(f"{key + '[tier ' + str(tier) + ']':40} {m.value!s:>14} {m.unit}")
        if snap.clock_skew is not None:
            print(f"{'clock_skew':40} {snap.clock_skew.total_seconds():+14.1f} s")
    elif args.cmd == "intervals":
        ch = profile.channel(args.channel)
        if ch is None or ch.statistic != Statistic.INTERVAL:
            keys = [c.key for c in profile.channels if c.statistic == Statistic.INTERVAL]
            raise _UsageError(f"unknown interval channel {args.channel!r}; choose from {keys}")
        for v in await meter.read_latest_intervals(ch):
            print(f"{v.start:%Y-%m-%dT%H:%M}Z  {v.value} {v.unit}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m aio2030dot5",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"aio2030dot5 {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    ident = sub.add_parser("identity", help="show (or --generate) a client certificate's LFDI and SFDI")
    ident.add_argument("--cert", required=True, help="client certificate (PEM)")
    ident.add_argument("--key", required=True, help="client private key (PEM)")
    ident.add_argument(
        "--generate", action="store_true", help="create a new certificate and key; refuses if either file exists"
    )
    commands = (
        ("discover", "walk the meter and print its profile (writes --profile)"),
        ("read", "read every channel once"),
    )
    for name, help_ in commands:
        _meter_args(sub.add_parser(name, help=help_))
    iv = sub.add_parser("intervals", help="print the completed intervals of the newest two sets")
    _meter_args(iv)
    iv.add_argument(
        "--channel",
        default="energy_interval_delivered",
        help="an interval channel's key (default: energy_interval_delivered)",
    )
    args = p.parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except (_UsageError, InvalidIdentity, OSError) as err:
        where = f"{err.filename}: " if isinstance(err, OSError) and err.filename else ""
        reason = err.strerror if isinstance(err, OSError) and err.strerror else err
        print(f"error: {where}{reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
