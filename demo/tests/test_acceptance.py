"""M2 acceptance tests (DESIGN.md "Milestones", M2).

Each test runs the demo CLI as a child process against a relay process, so
each step is a real restart from the files on disk.
"""

from __future__ import annotations

import base64
import itertools
import json
import os
from typing import TYPE_CHECKING, Any

from conftest import demo, dump, setup, sync_ok

from snailfish_demo import app

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Relay


def test_edit_on_a_shows_on_b(relay: Relay, tmp_path: Path) -> None:
    """Device A edits a task, both devices sync, and B shows the edit."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    assert demo(a, "edit", "t1", "title", "buy milk").returncode == 0
    sync_ok(a)
    sync_ok(b)
    assert dump(b)["tasks"] == {"t1": {"title": "buy milk"}}
    assert demo(b, "edit", "t1", "done", "true").returncode == 0
    assert demo(a, "edit", "t1", "title", "buy oat milk").returncode == 0
    for d in (b, a, b):
        sync_ok(d)
    want = {"t1": {"done": True, "title": "buy oat milk"}}
    assert dump(a)["tasks"] == want
    assert dump(b)["tasks"] == want
    listed = demo(b, "list").stdout.strip()
    assert listed == "[x] t1: buy oat milk"
    for d in (a, b):
        state = dump(d)
        assert state["outbox"] == []
        assert state["engine_outbox"] == 0
        assert len(state["handled"]) == len(set(state["handled"])) == 3


def test_relay_storage_holds_no_plaintext(relay: Relay, tmp_path: Path) -> None:
    """A scan of every relay file finds no task text, task ID, field name,
    app key or device private key: raw, hex or base64."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    marker = "plaintext-marker-7f3e9a"
    task = "task-id-marker-51c0d2"
    assert demo(a, "edit", task, "title", marker).returncode == 0
    sync_ok(a)
    sync_ok(b)
    assert dump(b)["tasks"][task]["title"] == marker
    relay.stop()
    # The key store items: the signing seed, the X-Wing seed and the app key.
    items = [
        bytes.fromhex(v)
        for d in (a, b)
        for v in json.loads((d / "keystore.json").read_text()).values()
    ]
    # Each needle is long enough that random ciphertext does not hold it.
    needles = [marker.encode(), task.encode(), b'"title":"']
    for item in items:
        for i in range(0, 96, 32):
            raw = item[i : i + 32]
            needles += [raw, raw.hex().encode(), base64.b64encode(raw)]
    files = [p for p in relay.data.rglob("*") if p.is_file()]
    assert any(p.name == "tenant.db" for p in files)
    assert any(p.parent.name == "spaces" for p in files)
    for p in files:
        data = p.read_bytes()
        for n in needles:
            assert n not in data, f"{p.relative_to(relay.data)} holds {n[:16]!r}"


def merged_state(changes: list[bytes]) -> dict[tuple[str, str], Any]:
    """Apply changes in the given order with the app merge rules."""
    state: dict[tuple[str, str], tuple[Any, app.Stamp]] = {}
    for c in changes:
        app.merge(state, c)
    return {k: v[0] for k, v in state.items()}


def test_device_merge_matches_the_pure_merge(relay: Relay, tmp_path: Path) -> None:
    """The app database merge of a device gives the same values as `merge`,
    for changes that arrive in an order with older stamps last."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    dev = app.Device(a, now_ms=lambda: 50)
    s = app.Stamp
    changes = [
        app.encode_change("t1", "title", "new", s(60, 0, "d_z")),
        app.encode_change("t1", "title", "old", s(40, 3, "d_z")),
        app.encode_change("t1", "done", value=True, stamp=s(60, 0, "d_a")),
    ]
    with dev.transaction():
        for c in changes:
            task, field, value, stamp = app.decode_change(c)
            dev.merge_into_db(task, field, value, stamp)
    got = {(t, f): v for t, fs in dev.tasks().items() for f, v in fs.items()}
    assert got == merged_state(changes)
    dev.close()


def test_two_orders_give_the_same_state() -> None:
    """[MRG-2]: each order of the same changes gives the same app state.

    The changes include a tie on the wall time and counter, which the device
    ID breaks, and an older stamp that arrives last.
    """
    s = app.Stamp
    changes = [
        app.encode_change("t1", "title", "a", s(10, 0, "d_a")),
        app.encode_change("t1", "title", "b", s(10, 0, "d_b")),
        app.encode_change("t1", "title", "c", s(9, 5, "d_c")),
        app.encode_change("t1", "done", value=True, stamp=s(11, 0, "d_a")),
        app.encode_change("t1", "done", value=False, stamp=s(11, 1, "d_a")),
        app.encode_change("t2", "title", "x", s(1, 0, "d_b")),
    ]
    want = {("t1", "title"): "b", ("t1", "done"): False, ("t2", "title"): "x"}
    for order in itertools.permutations(changes):
        assert merged_state(list(order)) == want


def test_two_devices_in_two_orders_converge(relay: Relay, tmp_path: Path) -> None:
    """The same offline edits reach A and B in different log orders, and both
    devices show the same state (S3)."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sync_ok(a)
    sync_ok(b)
    # Offline edits on both devices of the same fields.
    assert demo(a, "edit", "t1", "title", "from a").returncode == 0
    assert demo(b, "edit", "t1", "title", "from b").returncode == 0
    assert demo(b, "edit", "t1", "done", "true").returncode == 0
    assert demo(a, "edit", "t2", "title", "only a").returncode == 0
    for d in (b, a, b):
        sync_ok(d)
    assert dump(a)["tasks"] == dump(b)["tasks"]
    assert dump(a)["tasks"]["t2"] == {"title": "only a"}


def test_env_is_clean() -> None:
    """The tests run without a crash point from the outer environment."""
    assert "SNAILFISH_DEMO_CRASH_AT" not in os.environ
