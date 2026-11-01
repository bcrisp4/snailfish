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

    def __init__(self, data: Path, authority: str | None = None) -> None:
        """Create one user and start the relay on a free port.

        `authority` is the authority that request signatures cover. A test
        relay in front of this relay passes its own authority.
        """
        if not RELAY.exists():
            pytest.fail(f"{RELAY} is missing: run cargo build -p snailfish-relay")
        self.data = data
        self.port = free_port()
        self.authority = authority or f"127.0.0.1:{self.port}"
        self.url = f"http://{self.authority}"
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
                self.authority,
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

    def admin(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run a `snailfish-relay` operator command on the data directory."""
        return subprocess.run(
            [str(RELAY), "--data", str(self.data), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def backup(self, out: Path) -> None:
        """Take a backup while the relay runs."""
        r = self.admin("backup", str(out))
        assert r.returncode == 0, r.stderr

    def restore(self, backup: Path) -> None:
        """Stop the relay, restore the backup over the data, start again."""
        running = self.admin("restore", "--replace", str(backup))
        assert running.returncode != 0, "restore must refuse while the relay runs"
        self.stop()
        r = self.admin("restore", "--replace", str(backup))
        assert r.returncode == 0, r.stderr
        self.start()


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


def demo_env() -> dict[str, str]:
    """The environment of a demo CLI child process."""
    env = dict(os.environ)
    env.pop("SNAILFISH_DEMO_CRASH_AT", None)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "bindings" / "python" / "build"), str(DEMO / "src")]
    )
    return env


def cli(*args: str) -> list[str]:
    """The command line of the demo CLI."""
    return [sys.executable, "-m", "snailfish_demo.cli", *args]


def start(*args: str) -> subprocess.Popen[str]:
    """Start the demo CLI as a child process with pipes for a prompt."""
    return subprocess.Popen(
        cli(*args),
        env=demo_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def read_line(proc: subprocess.Popen[str], prefix: str) -> str:
    """Read stdout lines until one starts with `prefix`, and return the rest."""
    assert proc.stdout is not None
    while line := proc.stdout.readline():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    _, err = proc.communicate(timeout=10)
    pytest.fail(f"no {prefix!r} line: {err}")


def finish(proc: subprocess.Popen[str]) -> tuple[int, str]:
    """Wait for a child process and return its exit code and output."""
    out, err = proc.communicate(timeout=60)
    return proc.returncode, out + err


def enroll(
    relay: Relay,
    trusted: Path,
    new: Path,
    *,
    new_shows: bool = False,
    confirm: tuple[str, str] = ("yes", "yes"),
    extra: tuple[str, ...] = (),
) -> tuple[tuple[int, str], tuple[int, str]]:
    """Enroll `new` from `trusted` through two CLI processes ([ENR-1]).

    The device that shows the session prints its payload. The test passes
    it to the other process, as a user scans the QR code. Returns the exit
    code and the output of the trusted and the new process.
    """
    t_conf, n_conf = confirm
    if new_shows:
        n = start("join", "--relay", relay.url, "--confirm", n_conf, "--name", "B", str(new))
        payload = read_line(n, "payload: ")
        t = start("--dir", str(trusted), "invite", "--scan", payload, "--confirm", t_conf, *extra)
    else:
        t = start("--dir", str(trusted), "invite", "--confirm", t_conf, *extra)
        payload = read_line(t, "payload: ")
        n = start(
            "join",
            "--relay",
            relay.url,
            "--scan",
            payload,
            "--confirm",
            n_conf,
            "--name",
            "B",
            str(new),
        )
    return finish(t), finish(n)


def setup(relay: Relay, a: Path, b: Path) -> None:
    """Create the space with device A, then enroll device B from A."""
    subprocess.run(
        cli("setup", "--relay", relay.url, "--tenant", relay.tenant, str(a)),
        env=demo_env(),
        check=True,
        capture_output=True,
        timeout=60,
    )
    sync_ok(a)
    (tc, tout), (nc, nout) = enroll(relay, a, b)
    assert (tc, nc) == (0, 0), tout + nout


def dump(device: Path) -> dict[str, Any]:
    """Return the observable state of one device."""
    r = demo(device, "dump")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def sync_ok(device: Path) -> None:
    """Sync one device and require `ok`."""
    r = demo(device, "sync")
    assert r.returncode == 0, r.stdout + r.stderr
