"""The client crash test (DESIGN.md M2): stop the demo client at each crash
point of push and pull, then restart it, and check that no change is lost
or applied twice.

The crash points are before and after each HTTP request and around each app
transaction (`snailfish_demo.cli.Crasher`). A crash after a request models a
lost response: the relay processed the request, and the client did not see
the answer. `os._exit` leaves no chance for cleanup, as a kill does.
"""

from __future__ import annotations

import shutil
import sqlite3
from typing import TYPE_CHECKING

from conftest import demo, dump, setup, sync_ok

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Relay

# The crash points of one sync: info, create or fetch, append, fetch, and the
# pull transactions. The loop stops at the first run that does not crash.
MAX_POINTS = 40


def crash_every_point(device: Path, other: Path | None = None) -> int:
    """Sync `device` once for each crash point N, with a crash at point N.

    Before each crash run, `other` makes a new edit and syncs, so that each
    run of `device` has a change to pull. Returns the number of crash runs.
    """
    for point in range(1, MAX_POINTS + 1):
        if other is not None:
            assert demo(other, "edit", f"o{point}", "title", f"v{point}").returncode == 0
            sync_ok(other)
        r = demo(device, "sync", crash_at=point)
        if r.returncode != 137:
            assert r.returncode == 0, r.stdout + r.stderr
            return point - 1
    raise AssertionError("a sync has more than MAX_POINTS crash points")


def check_converged(a: Path, b: Path, edits: int) -> None:
    """Both devices show the same tasks, the outboxes are empty, and each
    change was handled exactly once on each device."""
    sync_ok(a)
    sync_ok(b)
    sync_ok(a)
    da, db = dump(a), dump(b)
    assert da["tasks"] == db["tasks"]
    assert len(da["tasks"]) == edits
    for d in (da, db):
        assert d["outbox"] == []
        assert d["engine_outbox"] == 0
        assert len(d["handled"]) == len(set(d["handled"])) == edits


def test_crash_at_each_step_of_push(relay: Relay, tmp_path: Path) -> None:
    """A crash at each step of a push from A loses no change and applies none twice."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    edits = 0
    runs = 0
    for point in range(1, MAX_POINTS + 1):
        assert demo(a, "edit", f"a{point}", "title", f"v{point}").returncode == 0
        edits += 1
        r = demo(a, "sync", crash_at=point)
        if r.returncode != 137:
            assert r.returncode == 0, r.stdout + r.stderr
            break
        runs += 1
    print(f"push: {runs} crash points")
    assert runs >= 5, f"only {runs} crash points in a push"
    check_converged(a, b, edits)


def test_crash_at_each_step_of_pull(relay: Relay, tmp_path: Path) -> None:
    """A crash at each step of a pull by B loses no change and applies none twice."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    runs = crash_every_point(b, other=a)
    print(f"pull: {runs} crash points")
    assert runs >= 5, f"only {runs} crash points in a pull"
    check_converged(a, b, runs + 1)


def test_crash_at_each_step_of_the_first_sync(relay: Relay, tmp_path: Path) -> None:
    """A crash at each step of the first sync of A, which creates the space,
    leaves a space that both devices can use."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    assert demo(a, "edit", "t", "title", "first").returncode == 0
    runs = crash_every_point(a)
    print(f"first sync: {runs} crash points")
    assert runs >= 3
    check_converged(a, b, 1)


def test_app_database_restore_gives_back_own_edit(relay: Relay, tmp_path: Path) -> None:
    """`specs/delivery/test.qnt::restoredOwnEditReturnsTest` ([DLV-8],
    [DLV-11]): the app database comes back from a backup that is older than
    an own edit. The engine still holds the edit, so the next sync gives it
    back to the app once, and the app applies no change twice."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    assert demo(a, "edit", "t0", "title", "kept").returncode == 0
    sync_ok(a)
    backup = tmp_path / "backup.sqlite3"
    backup_app(a, backup)
    assert demo(a, "edit", "t1", "title", "after backup").returncode == 0
    sync_ok(a)
    restore_app(a, backup)
    assert "t1" not in dump(a)["tasks"]
    sync_ok(a)
    state = dump(a)
    assert state["tasks"] == {"t0": {"title": "kept"}, "t1": {"title": "after backup"}}
    assert len(state["handled"]) == len(set(state["handled"])) == 2
    check_converged(a, b, 2)


def test_app_database_restore_before_enqueue_of_a_pushed_edit(relay: Relay, tmp_path: Path) -> None:
    """The app database comes back with an outbox row whose change the
    relay already stores. The row returns from the log and the app deletes
    it, so the edit is not applied twice ([DLV-11])."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    assert demo(a, "edit", "t1", "title", "x").returncode == 0
    backup = tmp_path / "backup.sqlite3"
    backup_app(a, backup)
    sync_ok(a)
    restore_app(a, backup)
    assert len(dump(a)["outbox"]) == 1
    sync_ok(a)
    state = dump(a)
    assert state["outbox"] == []
    assert len(state["handled"]) == 1
    check_converged(a, b, 1)


def backup_app(device: Path, to: Path) -> None:
    """Copy the app database with the SQLite backup API."""
    src = sqlite3.connect(device / "app.sqlite3")
    dst = sqlite3.connect(to)
    src.backup(dst)
    dst.close()
    src.close()


def restore_app(device: Path, backup: Path) -> None:
    """Replace the app database with the backup. The engine state stays."""
    for suffix in ("", "-wal", "-shm"):
        (device / f"app.sqlite3{suffix}").unlink(missing_ok=True)
    shutil.copyfile(backup, device / "app.sqlite3")
