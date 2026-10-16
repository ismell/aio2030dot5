"""The command line: identities, discovery with a cache, and one-line errors."""

from __future__ import annotations

import asyncio
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from aio2030dot5 import Meter
from aio2030dot5.__main__ import main

from .conftest import Pki
from .meter_server import FakeMeter


def _run(argv: list[str]) -> int:
    # main() runs its own event loop; keep it off pytest-asyncio's.
    return main(argv)


def test_generate_writes_a_private_key_and_shows_the_portal_lfdi(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    assert _run(["identity", "--cert", str(cert), "--key", str(key), "--generate"]) == 0
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert "as utility portals accept it" in out and out.count("-") >= 7
    assert _run(["identity", "--cert", str(cert), "--key", str(key), "--generate"]) == 2  # never overwrites


@pytest.mark.parametrize("missing", ["cert", "key"])
def test_a_missing_file_is_one_line_naming_it(
    tmp_path: Path, pki: Pki, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    files = {"cert": str(pki.client_cert), "key": str(pki.client_key), missing: str(tmp_path / "nope.pem")}
    assert _run(["read", "--host", "127.0.0.1", "--port", "1", "--cert", files["cert"], "--key", files["key"]]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "nope.pem" in err and "Traceback" not in err


def test_an_unusable_certificate_is_one_line(tmp_path: Path, pki: Pki, capsys: pytest.CaptureFixture[str]) -> None:
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate")
    assert _run(["identity", "--cert", str(junk), "--key", str(pki.client_key)]) == 2
    assert capsys.readouterr().err.startswith("error: ")


async def test_discover_always_walks_and_read_uses_the_cache(
    pki: Pki, fake_meter: FakeMeter, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = Meter.from_files

    async def fast(*args: Any, **kwargs: Any) -> Meter:  # the CLI's meter-friendly pacing, minus the waits
        return await real(*args, **kwargs, min_connect_interval=0.0, request_spacing=0.0)

    monkeypatch.setattr(Meter, "from_files", fast)
    profile = tmp_path / "profile.json"
    common = ["--host", "127.0.0.1", "--port", str(fake_meter.port)]
    common += ["--cert", str(pki.client_cert), "--key", str(pki.client_key), "--profile", str(profile)]
    loop = asyncio.get_running_loop()

    assert await loop.run_in_executor(None, _run, ["discover", *common]) == 0
    assert stat.S_IMODE(profile.stat().st_mode) == 0o600
    walked = len(fake_meter.log.requests)
    assert await loop.run_in_executor(None, _run, ["discover", *common]) == 0
    assert len(fake_meter.log.requests) >= 2 * walked  # walked again, not the cache

    before = len(fake_meter.log.requests)
    assert await loop.run_in_executor(None, _run, ["read", *common]) == 0
    reads = len(fake_meter.log.requests) - before
    assert reads < walked  # the cached profile, no discovery

    profile.write_text("{not json")
    assert await loop.run_in_executor(None, _run, ["read", *common]) == 0  # rediscovers
    assert json.loads(profile.read_text())["version"]
