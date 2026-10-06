"""Command line: ``python -m aio2030dot5 --help``.

Every command that talks to a meter opens at most one connection per
batch and prints transport counters at the end, so it is safe to run
against a meter that only tolerates one client (stop the other client first).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import Meter, MeterError, MeterProfile, Statistic
from .identity import check_identity, generate_identity


def _meter_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--profile", help="profile cache file (read if present, written after discovery)")


async def _profile(meter: Meter, path: str | None) -> MeterProfile:
    if path and Path(path).exists():
        return MeterProfile.from_dict(json.loads(Path(path).read_text()))
    profile = await meter.discover()
    if path:
        Path(path).write_text(json.dumps(profile.to_dict(), indent=1))
    return profile


async def _run(args: argparse.Namespace) -> int:
    if args.cmd == "identity":
        if args.generate:
            existing = [p for p in (args.cert, args.key) if Path(p).exists()]
            if existing:
                print(f"refusing to overwrite {', '.join(existing)}", file=sys.stderr)
                return 2
            ident = generate_identity()
            key_path = Path(args.key)
            key_path.touch(mode=0o600, exist_ok=False)
            key_path.write_bytes(ident.key_pem)
            Path(args.cert).write_bytes(ident.cert_pem)
        check = check_identity(Path(args.cert).read_bytes(), Path(args.key).read_bytes())
        print(
            f"LFDI       {check.lfdi}\nSFDI       {check.sfdi}\nexpires    {check.not_after:%Y-%m-%d} "
            f"({check.days_remaining()} days)"
        )
        for p in check.problems:
            print(f"PROBLEM    {p}")
        return 0 if check.ok else 1

    meter = await Meter.from_files(args.host, args.cert, args.key, args.port)
    try:
        profile = await _profile(meter, args.profile)
        if args.cmd == "discover":
            print(json.dumps(profile.to_dict(), indent=1))
        elif args.cmd == "read":
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
            ch = next((c for c in profile.channels if c.key == args.channel), None)
            if ch is None or ch.statistic != Statistic.INTERVAL:
                keys = [c.key for c in profile.channels if c.statistic == Statistic.INTERVAL]
                print(f"unknown interval channel; choose from {keys}", file=sys.stderr)
                return 2
            for v in await meter.read_latest_intervals(ch):
                print(f"{v.start:%Y-%m-%dT%H:%M}Z  {v.value} {v.unit}")
    except MeterError as err:
        print(f"error: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    finally:
        print(f"transport: {meter.stats.as_dict()}", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog="python -m aio2030dot5", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    ident = sub.add_parser("identity", help="show (or --generate) a client certificate's LFDI/SFDI")
    ident.add_argument("--cert", required=True)
    ident.add_argument("--key", required=True)
    ident.add_argument("--generate", action="store_true", help="create a new cert/key (refuses to overwrite the key)")
    for name, help_ in (("discover", "walk the meter and print its profile"), ("read", "read every channel once")):
        _meter_args(sub.add_parser(name, help=help_))
    iv = sub.add_parser("intervals", help="print the newest interval set of a channel")
    _meter_args(iv)
    iv.add_argument("--channel", default="energy_interval_delivered")
    return asyncio.run(_run(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
