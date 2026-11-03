"""M7: block, removal, recovery key replacement and full recovery through
the demo CLI, against a relay process (DESIGN.md S4 and S5, PROTOCOL.md
section 13).

Each test runs each device as its own CLI process, as a user does. The
software browser of `softbrowser.py` signs in to the user page.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import httpx
import snailfish as sf
from conftest import Relay, cli, demo, demo_env, dump, enroll, sync_ok

from snailfish_demo import app
from snailfish_demo.cli import SOFT_REDIRECT, Crasher, http_transport
from snailfish_demo.softbrowser import SoftBrowser

if TYPE_CHECKING:
    from pathlib import Path


def create_with_key(relay: Relay, a: Path) -> str:
    """Create the space with device A and return the recovery key that the
    CLI prints once."""
    r = subprocess.run(
        cli(
            "setup", "--relay", relay.url, "--browser", str(relay.browser), "--user", "sam", str(a)
        ),
        env=demo_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout.split("recovery key (write it down): ", 1)[1].strip()


def two_devices(relay: Relay, tmp_path: Path) -> tuple[Path, Path, str]:
    """A and B in one space, each with one synced edit."""
    a, b = tmp_path / "a", tmp_path / "b"
    key = create_with_key(relay, a)
    sync_ok(a)
    (tc, tout), (nc, nout) = enroll(relay, a, b)
    assert (tc, nc) == (0, 0), tout + nout
    sync_ok(b)
    assert demo(a, "edit", "t1", "title", "from A").returncode == 0
    sync_ok(a)
    assert demo(b, "edit", "t2", "title", "from B").returncode == 0
    sync_ok(b)
    sync_ok(a)
    return a, b, key


def devices(d: Path) -> dict[str, str]:
    """The active devices of the space as the CLI lists them: ID to name."""
    r = demo(d, "devices")
    assert r.returncode == 0, r.stderr
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        did, name = line.split(" ", 1)
        out[did] = name
    return out


def own_id(d: Path) -> str:
    """The device ID of the device in `d`."""
    return next(i for i, n in devices(d).items() if n.endswith("(this device)"))


def test_stolen_phone_is_blocked_then_removed(relay: Relay, tmp_path: Path) -> None:
    """S4, [STO-12], T8, `specs/spacelog/test.qnt::removalTest`: the user
    blocks the machine group of B on the user page, and B pauses at once.
    The page shows the block as an open security action. A shows the
    devices that stay, removes B and rotates the key. After an unblock the
    relay still refuses B as removed. A keeps working with the new key."""
    a, b, _ = two_devices(relay, tmp_path)
    b_id = own_id(b)
    br = SoftBrowser(relay.browser, relay.url)
    br.sign_in("sam")
    assert br.form("/u/groups", [("name", "Sam's phone")])[0] == 303
    assert br.form("/u/groups/members", [("group", "1"), ("device", b_id), ("op", "add")])[0] == 303
    assert br.form("/u/block", [("kind", "group"), ("id", "1")])[0] == 303
    r = demo(b, "sync")
    assert "Status.BLOCKED" in r.stdout, r.stdout + r.stderr
    page = br.page()
    assert "Open security actions" in page
    assert "is blocked" in page
    r = demo(a, "remove", "--confirm", "yes", b_id)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "devices that stay:" in r.stdout
    assert b_id not in devices(a)
    assert br.form("/u/unblock", [("kind", "group"), ("id", "1")])[0] == 303
    r = demo(b, "sync")
    assert "Status.REMOVED" in r.stdout, r.stdout + r.stderr
    assert demo(a, "edit", "t3", "title", "after removal").returncode == 0
    sync_ok(a)
    assert dump(a)["tasks"]["t3"]["title"] == "after removal"
    assert "is blocked" not in br.page()


def test_remove_needs_the_user_confirmation(relay: Relay, tmp_path: Path) -> None:
    """PROTOCOL.md 13.2 step 1: a `no` at the list of the devices that stay
    signs nothing."""
    a, b, _ = two_devices(relay, tmp_path)
    r = demo(a, "remove", "--confirm", "no", own_id(b))
    assert r.returncode == 0, r.stdout + r.stderr
    assert own_id(b) in devices(a)


def test_remove_after_another_device_removed_one_of_them(relay: Relay, tmp_path: Path) -> None:
    """[LOG-7], PROTOCOL.md 13.2: B removes C first. A asked to remove C
    and D on its older log, so the engine drops C and asks again for D.
    The CLI confirms D alone and removes it, and does not stop with "not an
    active device"."""
    a, b, _ = two_devices(relay, tmp_path)
    c, d = tmp_path / "c", tmp_path / "d"
    for n in (c, d):
        (tc, tout), (nc, nout) = enroll(relay, a, n)
        assert (tc, nc) == (0, 0), tout + nout
        sync_ok(n)
    sync_ok(a)
    sync_ok(b)
    c_id, d_id = own_id(c), own_id(d)
    r = demo(b, "remove", "--confirm", "yes", c_id)
    assert r.returncode == 0, r.stdout + r.stderr
    r = demo(a, "remove", "--confirm", "yes", c_id, d_id)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.count("devices that stay:") == 2, r.stdout
    left = devices(a)
    assert c_id not in left
    assert d_id not in left


def test_recovery_key_replacement(relay: Relay, tmp_path: Path) -> None:
    """T9, `specs/spacelog/test.qnt::recoveryReplaceTest`, PROTOCOL.md 13.3:
    the old key signs the recovery record, then A rotates the key. The old
    key cannot replace the key again, and the new key recovers the space."""
    a, _, old = two_devices(relay, tmp_path)
    new_key = subprocess.run(
        cli("--dir", str(a), "replace-recovery-key", "--current", old, "--new", "x"),
        env=demo_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert new_key.returncode != 0, "a key that does not parse is refused"
    new = sf.new_recovery_key()
    r = demo(a, "replace-recovery-key", "--current", old, "--new", new)
    assert r.returncode == 0, r.stdout + r.stderr
    again = demo(a, "replace-recovery-key", "--current", old, "--new", sf.new_recovery_key())
    assert again.returncode != 0
    assert "not the current recovery key" in again.stderr
    n = tmp_path / "n"
    r = recover(relay, n, old)
    assert r.returncode != 0, "the old key recovers nothing"
    r = recover(relay, tmp_path / "m", new)
    assert r.returncode == 0, r.stdout + r.stderr


def recover(relay: Relay, d: Path, key: str) -> subprocess.CompletedProcess[str]:
    """Run `recover` on a new device with the software browser of sam."""
    return subprocess.run(
        cli(
            "recover",
            "--relay",
            relay.url,
            "--recovery-key",
            key,
            "--browser",
            str(relay.browser),
            "--user",
            "sam",
            "--name",
            "N",
            str(d),
        ),
        env=demo_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_all_devices_lost_full_recovery(relay: Relay, tmp_path: Path) -> None:
    """S5, `specs/spacelog/test.qnt::fullRecoveryTest`, PROTOCOL.md 13.4: A
    and B are lost. A new device signs in, finds the space, and recovers it
    with the paper recovery key. It reads the tasks of A and B, removes
    both, and edits with the new key. A setup that finds the space refuses
    to make a second one."""
    a, b, key = two_devices(relay, tmp_path)
    second = subprocess.run(
        cli(
            "setup",
            "--relay",
            relay.url,
            "--browser",
            str(relay.browser),
            "--user",
            "sam",
            str(tmp_path / "second"),
        ),
        env=demo_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert second.returncode != 0
    assert "SpaceExistsError" in second.stderr
    # A mistyped key fails with a message and leaves no device. A key that
    # is not the key of the space fails at the relay.
    n = tmp_path / "n"
    r = recover(relay, n, key[:-1])
    assert r.returncode != 0
    assert "Traceback" not in r.stderr, r.stderr
    assert not (n / "space.json").exists()
    r = recover(relay, tmp_path / "other", sf.new_recovery_key())
    assert r.returncode != 0
    assert "not the current recovery key" in r.stdout + r.stderr
    r = recover(relay, n, key)
    assert r.returncode == 0, r.stdout + r.stderr
    sync_ok(n)
    tasks = dump(n)["tasks"]
    assert (tasks["t1"]["title"], tasks["t2"]["title"]) == ("from A", "from B")
    lost = [i for i, name in devices(n).items() if not name.endswith("(this device)")]
    assert len(lost) == 2
    r = demo(n, "remove", "--confirm", "yes", *lost)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(devices(n)) == 1
    assert demo(n, "edit", "t4", "title", "after recovery").returncode == 0
    sync_ok(n)
    for old in (a, b):
        r = demo(old, "sync")
        assert "Status.REMOVED" in r.stdout, r.stdout + r.stderr


def test_sign_in_again_after_setup_failed(relay: Relay, tmp_path: Path) -> None:
    """M6 open item, PROTOCOL.md 10.5: the relay refuses to create the space
    with a setup token of another device (`stopped: setup failed`). The demo
    signs in again with the keys of the engine, and the next sync creates the
    same space, so the recovery key on paper stays valid."""
    a = tmp_path / "a"
    key = create_with_key(relay, a)
    br = SoftBrowser(relay.browser, relay.url)
    with httpx.Client(timeout=30) as client:
        send = http_transport(client, Crasher())
        other = app.sign_in(
            relay.url,
            sf.new_device_keys(),
            SOFT_REDIRECT,
            lambda authorize_url: br.approve(authorize_url, "sam"),
            send,
        )
    dev = app.Device(a)
    dev.engine.set_setup_token(other.token)
    dev.close()
    del dev
    r = demo(a, "sync")
    assert "SETUP_FAILED" in r.stdout, r.stdout + r.stderr
    r = demo(a, "sign-in-again", "--browser", str(relay.browser), "--user", "sam")
    assert r.returncode == 0, r.stdout + r.stderr
    sync_ok(a)
    r = recover(relay, tmp_path / "n", key)
    assert r.returncode == 0, r.stdout + r.stderr
