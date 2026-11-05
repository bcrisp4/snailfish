"""M8: log compaction through the demo CLI against a relay process
(DESIGN.md "Log compaction", "Milestones" M8, `specs/compaction/test.qnt`).

Each device runs as its own CLI process. The app writes a snapshot when
`snapshot_due` says so, or on the `snapshot` command.
"""

from __future__ import annotations

import shutil
import time
from typing import TYPE_CHECKING

from conftest import demo, dump, enroll, sync_ok
from test_removal import devices, recover, two_devices

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Relay


def space_status(relay: Relay, log_id: str) -> dict[str, int]:
    """The `space-status` operator output: used bytes, stubs, frontier."""
    r = relay.admin("space-status", "sam", log_id)
    assert r.returncode == 0, r.stderr
    out: dict[str, int] = {}
    for line in r.stdout.splitlines():
        key, value = line.split(": ", 1)
        out[key] = int(value.split(" ", 1)[0])
    return out


def space_file_bytes(relay: Relay) -> int:
    """The size of the space file and its WAL on the relay."""
    spaces = next((relay.data / "tenants").iterdir()) / "spaces"
    return sum(p.stat().st_size for p in spaces.iterdir() if p.name.endswith((".db", ".db-wal")))


def accept_on(*devs: Path) -> None:
    """Two rounds of sync: each device pushes its snapshot or accept record,
    and fetches the records of the others ([CMP-5])."""
    for _ in range(2):
        for d in devs:
            sync_ok(d)


def test_snapshot_of_10000_changes_drops_relay_storage(relay: Relay, tmp_path: Path) -> None:
    """M8 demo, `compactTest` and `newDeviceTest` ([CMP-5], [CMP-6],
    [CMP-12], [CMP-16], [CMP-19]): A writes 10,000 changes. `snapshot_due`
    makes A write a snapshot. After both devices accept it, the relay
    replaces the changes with stubs, and the usage and the space file drop.
    A new device C imports the snapshot and shows every task."""
    a, b, _ = two_devices(relay, tmp_path)
    log_id = dump(a)["log_id"]
    t0 = time.monotonic()
    r = demo(a, "edit-many", "10000")
    assert r.returncode == 0, r.stderr
    sync_ok(a)
    before = space_status(relay, log_id)
    size_before = space_file_bytes(relay)
    assert before["stubs"] == 0
    accept_on(a, b)
    sync_ok(a)
    after = space_status(relay, log_id)
    print(f"10000 changes, snapshot and accepts: {time.monotonic() - t0:.1f} s")
    print(f"usage {before['used']} -> {after['used']} bytes, stubs {after['stubs']}")
    assert after["stubs"] >= 10_000
    assert after["used"] < before["used"] // 4
    assert space_file_bytes(relay) < size_before
    assert dump(a)["snapshot"] is not None
    c = tmp_path / "c"
    (tc, tout), (nc, nout) = enroll(relay, a, c)
    assert (tc, nc) == (0, 0), tout + nout
    t1 = time.monotonic()
    sync_ok(c)
    print(f"first sync of C from the snapshot: {time.monotonic() - t1:.1f} s")
    tasks = dump(c)["tasks"]
    assert len(tasks) == 10_002
    assert tasks == dump(a)["tasks"]


def test_all_devices_lost_with_a_snapshot(relay: Relay, tmp_path: Path) -> None:
    """S5 with a snapshot (M8 demo, `newDeviceTest`, [CMP-20]): after the
    stubs, A and B are lost. A new device recovers the space with the paper
    recovery key, imports the usable snapshot, removes A and B, and edits."""
    a, b, key = two_devices(relay, tmp_path)
    assert demo(a, "edit", "t3", "title", "before the snapshot").returncode == 0
    sync_ok(a)
    sync_ok(b)
    assert demo(a, "snapshot").returncode == 0
    accept_on(a, b)
    sync_ok(a)
    log_id = dump(a)["log_id"]
    assert space_status(relay, log_id)["stubs"] >= 3
    n = tmp_path / "n"
    r = recover(relay, n, key)
    assert r.returncode == 0, r.stdout + r.stderr
    sync_ok(n)
    tasks = dump(n)["tasks"]
    assert tasks == dump(a)["tasks"]
    assert tasks["t3"]["title"] == "before the snapshot"
    lost = [i for i, name in devices(n).items() if not name.endswith("(this device)")]
    r = demo(n, "remove", "--confirm", "yes", *lost)
    assert r.returncode == 0, r.stdout + r.stderr
    assert demo(n, "edit", "t4", "title", "after recovery").returncode == 0
    sync_ok(n)
    assert dump(n)["tasks"]["t4"]["title"] == "after recovery"


def test_offline_device_imports_the_snapshot_and_keeps_its_edits(
    relay: Relay, tmp_path: Path
) -> None:
    """M8 demo, `offlineResetTest` ([CMP-14], [DLV-11], [DLV-12], decision
    D10): B goes offline with an app DB backup from before its edit reached
    the relay. While B is offline the relay makes stubs. B restores the
    backup and edits again. Its sync imports the snapshot, drops the covered
    outbox row and keeps the new edit."""
    a, b, _ = two_devices(relay, tmp_path)
    assert demo(b, "edit", "t5", "title", "offline 1").returncode == 0
    backup = tmp_path / "b-app"
    backup.mkdir()
    for f in b.glob("app.sqlite3*"):
        shutil.copy2(f, backup / f.name)
    sync_ok(b)
    sync_ok(a)
    assert demo(a, "snapshot").returncode == 0
    accept_on(a, b)
    sync_ok(a)
    log_id = dump(a)["log_id"]
    assert space_status(relay, log_id)["stubs"] >= 3
    for f in b.glob("app.sqlite3*"):
        f.unlink()
    for f in backup.iterdir():
        shutil.copy2(f, b / f.name)
    assert len(dump(b)["outbox"]) == 1
    assert demo(b, "edit", "t6", "title", "offline 2").returncode == 0
    sync_ok(b)
    sync_ok(b)
    state = dump(b)
    assert state["outbox"] == []
    assert state["tasks"]["t5"]["title"] == "offline 1"
    assert state["tasks"]["t6"]["title"] == "offline 2"
    sync_ok(a)
    assert dump(a)["tasks"] == state["tasks"]
