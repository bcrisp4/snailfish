"""M9: fork repair, a move to another relay and a restore from the export
file, through the demo CLI and relay processes (DESIGN.md "Fork repair",
"Data retention", PROTOCOL.md 10.12, 10.13 and section 15).

Each device runs as its own CLI process, as a user does. The model
scenarios are in `specs/forkrepair/test.qnt`.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from conftest import Relay, cli, demo, demo_env, dump, finish, read_line, setup, start, sync_ok
from test_integrity import cut_relay_log, edit

if TYPE_CHECKING:
    from pathlib import Path


def rejoin(source: Path, device: Path) -> tuple[tuple[int, str], tuple[int, str]]:
    """FRK-6: `device` enrolls again from `source`. The source shows the
    session, and the device scans its payload."""
    t = start("--dir", str(source), "invite", "--confirm", "yes")
    payload = read_line(t, "payload: ")
    n = start("rejoin", "--scan", payload, "--confirm", "yes", "--name", "A again", str(device))
    return finish(t), finish(n)


def sign_in_args(relay: Relay) -> list[str]:
    """The software browser arguments of a sign-in on `relay`."""
    return ["--browser", str(relay.browser), "--user", "sam"]


def test_fork_repair_restores_the_own_changes_of_each_device(relay: Relay, tmp_path: Path) -> None:
    """`specs/forkrepair/test.qnt::repairTest` ([FRK-1] to [FRK-8]): the
    relay loses A's change "a1" with no hold, and B writes "b1" at the same
    position. A stops with `fork`. B is the source: it deletes the space and
    imports its log. A enrolls again from B and sends "a1" again with its
    old change ID. Both devices end with both changes, each applied once."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    edit(a, "a1", "only on A")
    sync_ok(a)
    assert dump(a)["outbox"] == [], "a1 came back to A"
    relay.stop()
    cut_relay_log(relay, 2)
    relay.start()
    edit(b, "b1", "on B")
    sync_ok(b)
    r = demo(a, "sync")
    assert r.returncode != 0
    assert "fork" in r.stdout.lower(), r.stdout
    # FRK-4 and FRK-5 on the source.
    r = demo(b, "delete")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "deleted" in r.stdout.lower(), r.stdout
    r = demo(b, "import", *sign_in_args(relay))
    assert r.returncode == 0, r.stdout + r.stderr
    sync_ok(b)
    # FRK-6 to FRK-8 on A.
    (tc, tout), (nc, nout) = rejoin(b, a)
    assert (tc, nc) == (0, 0), tout + nout
    assert "recovered: 1 own changes" in nout, nout
    sync_ok(a)
    sync_ok(b)
    want = {"a1": {"title": "only on A"}, "b1": {"title": "on B"}}
    for d in (a, b):
        state = dump(d)
        assert state["tasks"] == want, d
        assert state["outbox"] == []
        assert len(state["handled"]) == len(set(state["handled"]))
    assert not (a / "engine-old").exists()


def test_deleted_space_stops_each_device(relay: Relay, tmp_path: Path) -> None:
    """`specs/forkrepair/test.qnt::deletedThenImportedTest` ([LOG-13]): after
    a deletion, B stops with `deleted` and keeps its edit in its outbox.
    After A imports the log, B syncs the edit."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    r = demo(a, "delete")
    assert r.returncode == 0, r.stdout + r.stderr
    edit(b, "t1", "while deleted")
    r = demo(b, "sync")
    assert r.returncode != 0
    assert "deleted" in r.stdout.lower(), r.stdout
    assert len(dump(b)["outbox"]) == 1
    r = demo(a, "import", *sign_in_args(relay))
    assert r.returncode == 0, r.stdout + r.stderr
    sync_ok(b)
    sync_ok(a)
    assert dump(a)["tasks"] == {"t1": {"title": "while deleted"}}


def test_space_moves_to_another_relay(relay: Relay, tmp_path: Path) -> None:
    """[FRK-5]: A imports the log into a second relay. B signs in there and
    keeps its state file. An edit on B reaches A through the new relay."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    edit(a, "t1", "before")
    sync_ok(a)
    sync_ok(b)
    new = Relay(tmp_path / "relay2")
    try:
        r = demo(a, "import", "--relay", new.url, *sign_in_args(new))
        assert r.returncode == 0, r.stdout + r.stderr
        r = demo(b, "switch-relay", "--relay", new.url, *sign_in_args(new))
        assert r.returncode == 0, r.stdout + r.stderr
        sync_ok(a)
        sync_ok(b)
        edit(b, "t2", "after")
        sync_ok(b)
        sync_ok(a)
        assert dump(a)["tasks"] == {"t1": {"title": "before"}, "t2": {"title": "after"}}
    finally:
        new.stop()


def test_export_file_restores_a_lost_space(relay: Relay, tmp_path: Path) -> None:
    """DESIGN.md "Data retention": A writes the export file. The relay loses
    the space and every device is gone. A new device imports the file and
    recovers the space with the paper recovery key."""
    a = tmp_path / "a"
    r = subprocess.run(
        cli("setup", "--relay", relay.url, *sign_in_args(relay), str(a)),
        env=demo_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    key = r.stdout.split("recovery key (write it down): ", 1)[1].strip()
    sync_ok(a)
    edit(a, "t1", "kept")
    sync_ok(a)
    file = tmp_path / "space.snailfish-export"
    assert demo(a, "export", str(file)).returncode == 0
    log = dump(a)["log_id"]
    deleted = relay.admin("space", "delete", "sam", log)
    assert deleted.returncode == 0, deleted.stderr
    c = tmp_path / "c"
    r = subprocess.run(
        cli(
            "restore",
            "--relay",
            relay.url,
            "--file",
            str(file),
            "--recovery-key",
            key,
            *sign_in_args(relay),
            str(c),
        ),
        env=demo_env(),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    sync_ok(c)
    assert dump(c)["tasks"] == {"t1": {"title": "kept"}}
