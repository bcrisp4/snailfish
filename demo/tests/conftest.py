"""Shared fixtures: a relay process and the demo CLI as a child process."""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).resolve().parents[2]
RELAY = Path(os.environ.get("SNAILFISH_RELAY_BIN", ROOT / "target" / "debug" / "snailfish-relay"))
DEMO = Path(__file__).resolve().parents[1]


def free_port() -> int:
    """Return a TCP port that is free now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Relay:
    """A relay process and its data directory."""

    def __init__(self, data: Path) -> None:
        """Create one user and start the relay on a free port."""
        if not RELAY.exists():
            pytest.fail(f"{RELAY} is missing: run cargo build -p snailfish-relay")
        self.data = data
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.tenant = subprocess.run(
            [str(RELAY), "--data", str(data), "user", "add", "sam"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.proc: subprocess.Popen[bytes] | None = None
        self.start()

    def start(self) -> None:
        """Start the relay process and wait for the health route."""
        self.proc = subprocess.Popen(
            [
                str(RELAY),
                "serve",
                "--data",
                str(self.data),
                "--listen",
                f"127.0.0.1:{self.port}",
                "--authority",
                f"127.0.0.1:{self.port}",
            ]
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                conn.request("GET", "/v1/health")
                ok = conn.getresponse().status == 200
                conn.close()
                if ok:
                    return
            except OSError:
                time.sleep(0.05)
        pytest.fail("the relay did not start")

    def stop(self) -> None:
        """Stop the relay process."""
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None


@pytest.fixture
def relay(tmp_path: Path) -> Iterator[Relay]:
    """A running relay with one user."""
    r = Relay(tmp_path / "relay")
    yield r
    r.stop()


def demo(device: Path, *args: str, crash_at: int | None = None) -> subprocess.CompletedProcess[str]:
    """Run the demo CLI for one device as a child process."""
    env = dict(os.environ)
    env.pop("SNAILFISH_DEMO_CRASH_AT", None)
    if crash_at is not None:
        env["SNAILFISH_DEMO_CRASH_AT"] = str(crash_at)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "bindings" / "python" / "build"), str(DEMO / "src")]
    )
    return subprocess.run(
        [sys.executable, "-m", "snailfish_demo.cli", "--dir", str(device), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def setup(relay: Relay, a: Path, b: Path) -> None:
    """Create the space with devices A and B through the CLI."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "bindings" / "python" / "build"), str(DEMO / "src")]
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "snailfish_demo.cli",
            "setup",
            "--relay",
            relay.url,
            "--tenant",
            relay.tenant,
            str(a),
            str(b),
        ],
        env=env,
        check=True,
        capture_output=True,
        timeout=60,
    )


def dump(device: Path) -> dict[str, Any]:
    """Return the observable state of one device."""
    r = demo(device, "dump")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def sync_ok(device: Path) -> None:
    """Sync one device and require `ok`."""
    r = demo(device, "sync")
    assert r.returncode == 0, r.stdout + r.stderr
