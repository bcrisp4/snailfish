"""M3 acceptance tests: log integrity (DESIGN.md "Milestones", M3).

Each test runs the demo CLI and the `snailfish-relay` operator commands as
child processes against a relay process, so each step is a real restart
from the files on disk.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from conftest import demo, dump, setup, sync_ok

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Relay


def edit(device: Path, task: str, value: str) -> None:
    """Edit the title of a task."""
    r = demo(device, "edit", task, "title", value)
    assert r.returncode == 0, r.stderr


def sync(device: Path) -> str:
    """Sync one device and return its output."""
    return demo(device, "sync").stdout


def assert_once(device: Path) -> None:
    """The device handled each change once and has nothing pending."""
    state = dump(device)
    assert state["outbox"] == []
    assert state["engine_outbox"] == 0
    assert len(state["handled"]) == len(set(state["handled"]))


def test_restore_repair_and_release(relay: Relay, tmp_path: Path) -> None:
    """S6 (`specs/delivery/test.qnt::relayRestoreRepairTest`, [LOG-10],
    [LOG-14], [LOG-15]): the operator takes a backup, A and B sync more
    changes, and the operator restores the backup. A repairs the log, B
    syncs, and the operator releases the hold. No change is lost or applied
    twice."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    edit(a, "t1", "first")
    sync_ok(a)
    sync_ok(b)
    relay.backup(tmp_path / "backup")
    edit(a, "t2", "after the backup on a")
    sync_ok(a)
    edit(b, "t3", "after the backup on b")
    sync_ok(b)
    sync_ok(a)
    want = {
        "t1": {"title": "first"},
        "t2": {"title": "after the backup on a"},
        "t3": {"title": "after the backup on b"},
    }
    assert dump(a)["tasks"] == want

    relay.restore(tmp_path / "backup")
    out = sync(a)
    assert "repair: the relay lost positions 4 to 5" in out, out
    assert "RESTORE_HOLD" in out.upper().replace(" ", "_"), out
    sync(b)
    log = dump(a)["log_id"]
    status = relay.admin("hold-status", "sam", log)
    assert status.returncode == 0, status.stderr
    assert status.stdout.count("(reported") == 2, status.stdout
    assert "NOT REPAIRED" not in status.stdout
    released = relay.admin("release-hold", "sam", log)
    assert released.returncode == 0, released.stderr
    for d in (a, b, a):
        sync_ok(d)
    for d in (a, b):
        assert dump(d)["tasks"] == want
        assert_once(d)


def test_change_during_hold_waits_in_the_outbox(relay: Relay, tmp_path: Path) -> None:
    """[LOG-14]: a change that A writes during the hold stays in its outbox
    (`paused: restore hold`) and reaches the log after the release."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    relay.backup(tmp_path / "backup")
    relay.restore(tmp_path / "backup")
    edit(a, "t1", "during the hold")
    r = demo(a, "sync")
    assert r.returncode != 0, r.stdout
    assert dump(a)["engine_outbox"] == 1
    sync(b)
    log = dump(a)["log_id"]
    assert relay.admin("release-hold", "sam", log).returncode == 0
    sync_ok(a)
    sync_ok(b)
    assert dump(b)["tasks"] == {"t1": {"title": "during the hold"}}
    for d in (a, b):
        assert_once(d)


def test_release_refuses_a_new_engine_state_file(relay: Relay, tmp_path: Path) -> None:
    """`specs/delivery/test.qnt::notRepairedMarkTest` ([LOG-15], F3): B loses
    its engine state file during the hold. `release-hold` refuses while B is
    "not repaired", and `--force` releases."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    relay.backup(tmp_path / "backup")
    relay.restore(tmp_path / "backup")
    sync(a)
    for f in (b / "engine").glob("engine.sqlite3*"):
        f.unlink()
    sync(b)
    log = dump(a)["log_id"]
    status = relay.admin("hold-status", "sam", log)
    assert "NOT REPAIRED" in status.stdout, status.stdout
    refused = relay.admin("release-hold", "sam", log)
    assert refused.returncode != 0
    assert "not repaired" in refused.stderr, refused.stderr
    assert relay.admin("release-hold", "sam", log, "--force").returncode == 0
    sync_ok(a)
    sync_ok(b)


def cut_relay_log(relay: Relay, keep: int) -> None:
    """A storage fault: the relay loses the log entries after `keep`, with
    no restore command and no hold. The relay must be stopped."""
    files = list((relay.data / "tenants").glob("*/spaces/*.db"))
    assert len(files) == 1
    c = sqlite3.connect(files[0])
    with c:
        c.execute("DELETE FROM entries WHERE position > ?", (keep,))
        c.execute("DELETE FROM devices WHERE position > ?", (keep,))
    c.close()


def test_record_with_a_foreign_base_stops_with_fork(relay: Relay, tmp_path: Path) -> None:
    """`specs/delivery/test.qnt::forkStopsTest` ([FRK-1], [LOG-6], T7): the
    relay loses A's change with no hold, and B appends two changes on the
    shorter log. The second change has a base that is not in A's log, so A
    stops with `stopped: fork`."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    edit(a, "t1", "lost")
    sync_ok(a)
    relay.stop()
    cut_relay_log(relay, 2)
    relay.start()
    edit(b, "t2", "first on b")
    sync_ok(b)
    edit(b, "t3", "second on b")
    sync_ok(b)
    r = demo(a, "sync")
    assert r.returncode != 0
    assert "fork" in r.stdout.lower(), r.stdout
    assert "bad_base" in r.stdout, r.stdout
    assert dump(a)["tasks"] == {"t1": {"title": "lost"}}
