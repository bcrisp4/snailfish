"""The demo task app: one device is one data directory.

The layout of a device directory:

- `app.sqlite3`: the app database. It holds the tasks, the app outbox and
  the applied position (DESIGN.md "App integration").
- `engine/`: the engine state file. Only the engine writes it.
- `keys.json`: the device keys and the space reference. A real app keeps the
  keys in its key store.

The merge rules meet the merge contract ([MRG-1], [MRG-2]): each field of a
task is a last-writer-wins register on a hybrid logical clock, with the
device ID as the tie-break. The result depends on the set of changes, not
on their order.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import time
from typing import TYPE_CHECKING, Any, Protocol

import snailfish as sf

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

APP_ID = "com.example.tasks"
FORMAT = 1
FIELDS = ("title", "done")
BATCH = 500


class Transport(Protocol):
    """Sends one engine request. The app owns HTTP, TLS and retries."""

    def __call__(self, req: sf.Request) -> tuple[int, list[sf.Header], bytes]:
        """Send `req` and return the status, the headers and the body."""
        ...


@dataclasses.dataclass(frozen=True, order=True)
class Stamp:
    """A hybrid logical clock value with the device ID as the tie-break.

    The natural order of the fields is the merge order: wall time in
    milliseconds, then the counter, then the device ID.
    """

    wall: int
    counter: int
    device: str

    def to_json(self) -> list[Any]:
        """Return the JSON form."""
        return [self.wall, self.counter, self.device]

    @classmethod
    def from_json(cls, v: list[Any]) -> Stamp:
        """Read the JSON form."""
        return cls(int(v[0]), int(v[1]), str(v[2]))


def encode_change(task: str, field: str, value: object, stamp: Stamp) -> bytes:
    """Return the bytes of one change: one field of one task."""
    body = {"v": FORMAT, "task": task, "field": field, "value": value, "hlc": stamp.to_json()}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def decode_change(b: bytes) -> tuple[str, str, Any, Stamp]:
    """Read the bytes of one change.

    Raises:
        UnknownFormat: The change has an app format that this app cannot read
            ([DLV-14]).
    """
    d = json.loads(b)
    if d.get("v") != FORMAT or d.get("field") not in FIELDS:
        raise UnknownFormat(d.get("v"))
    return d["task"], d["field"], d["value"], Stamp.from_json(d["hlc"])


class UnknownFormat(Exception):
    """An app change format that this app cannot read."""


def merge(state: dict[tuple[str, str], tuple[Any, Stamp]], change: bytes) -> None:
    """Apply one change to an in-memory state with the app merge rules.

    A field takes the value of the change with the highest stamp ([MRG-2]).
    `Device._merge` applies the same rule to the app database.
    """
    task, field, value, stamp = decode_change(change)
    old = state.get((task, field))
    if old is None or old[1] < stamp:
        state[(task, field)] = (value, stamp)


SCHEMA = """
CREATE TABLE IF NOT EXISTS fields (
  task TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL,
  wall INTEGER NOT NULL, counter INTEGER NOT NULL, device TEXT NOT NULL,
  PRIMARY KEY (task, field)
);
CREATE TABLE IF NOT EXISTS outbox (
  change_id BLOB PRIMARY KEY, change_bytes BLOB NOT NULL, seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS applied (
  id INTEGER PRIMARY KEY CHECK (id = 1), position INTEGER NOT NULL, digest BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS clock (
  id INTEGER PRIMARY KEY CHECK (id = 1), wall INTEGER NOT NULL, counter INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS applied_log (change_id BLOB PRIMARY KEY);
"""


def keys_to_json(k: sf.DeviceKeys) -> dict[str, str]:
    """Return the JSON form of device keys."""
    return {
        "sign_seed": k.sign_seed.hex(),
        "seal_seed": k.seal_seed.hex(),
        "app_key": k.app_key.hex(),
    }


def keys_from_json(d: dict[str, str]) -> sf.DeviceKeys:
    """Read the JSON form of device keys."""
    return sf.DeviceKeys(
        sign_seed=bytes.fromhex(d["sign_seed"]),
        seal_seed=bytes.fromhex(d["seal_seed"]),
        app_key=bytes.fromhex(d["app_key"]),
    )


def write_private(path: Path, text: str) -> None:
    """Write a file with mode 0600, durably, through a temporary name."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def create_space(relay_url: str, tenant: str, dir_a: Path, dir_b: Path) -> str:
    """Create a space with devices A and B from key files on one machine.

    The engine makes the recovery key, the genesis record with a grant to A,
    and a grant to B signed by A (M2 decision 2). The function writes A's
    key file and engine setup, and copies B's keys and the app key into B's
    directory. A's next sync creates the space on the relay.

    Returns:
        The recovery key in its display form. Show it once.
    """
    ka = sf.new_device_keys()
    kb = sf.new_device_keys()
    setup = sf.create_space(
        APP_ID, sf.NewDevice(keys=ka, name="A"), [sf.NewDevice(keys=kb, name="B")]
    )
    ka.app_key = setup.app_key
    kb.app_key = setup.app_key
    space = {"relay_url": relay_url, "tenant": tenant, "log_id": setup.log_id, "app_id": APP_ID}
    for d, k in ((dir_a, ka), (dir_b, kb)):
        d.mkdir(parents=True, exist_ok=True)
        write_private(d / "keys.json", json.dumps({"space": space, "keys": keys_to_json(k)}))
    sf.install_setup(str(dir_a / "engine"), sf.SpaceRef(**space), ka, setup.envelopes)
    return setup.recovery_key


def _no_crash(_name: str) -> None:
    """A crash point that does nothing."""


class Device:
    """One device of the demo app."""

    def __init__(
        self,
        data_dir: Path,
        now_ms: Callable[[], int] | None = None,
        crash_point: Callable[[str], None] | None = None,
    ) -> None:
        """Open the device in `data_dir`.

        `crash_point` runs before each app transaction, before each commit
        and after each commit. The crash tests use it to stop the process.

        The app database uses WAL with `synchronous=FULL`, and `fullfsync`
        on Apple platforms ([DLV-1]). At startup the app gives its outbox
        rows to the engine again ([DLV-2]).
        """
        self.dir = data_dir
        cfg = json.loads((data_dir / "keys.json").read_text())
        self.space = sf.SpaceRef(**cfg["space"])
        self.engine = sf.Engine.open(
            str(data_dir / "engine"), self.space, keys_from_json(cfg["keys"])
        )
        self.device_id = self.engine.device_id()
        self.now_ms = now_ms or (lambda: time.time_ns() // 1_000_000)
        self.crash_point: Callable[[str], None] = crash_point or _no_crash
        self.db = sqlite3.connect(data_dir / "app.sqlite3", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA fullfsync=ON")
        self.db.executescript(SCHEMA)
        self.refused: list[bytes] = []
        self.flush_outbox()

    def close(self) -> None:
        """Close the app database. The engine closes with the object."""
        self.db.close()

    def transaction(self) -> Txn:
        """Return a context manager for one durable app transaction."""
        self.crash_point("before an app transaction")
        return Txn(self.db, self.crash_point)

    def applied_position(self) -> sf.Applied:
        """Return the applied position."""
        row = self.db.execute("SELECT position, digest FROM applied").fetchone()
        if row is None:
            return self.engine.genesis_base()
        return sf.Applied(position=row[0], digest=bytes(row[1]))

    def _tick(self) -> Stamp:
        """Advance the hybrid logical clock for a local edit."""
        row = self.db.execute("SELECT wall, counter FROM clock").fetchone()
        wall, counter = row if row else (0, 0)
        now = self.now_ms()
        stamp = (
            Stamp(now, 0, self.device_id)
            if now > wall
            else Stamp(wall, counter + 1, self.device_id)
        )
        self._save_clock(stamp)
        return stamp

    def _observe(self, s: Stamp) -> None:
        """Move the clock past a remote stamp."""
        row = self.db.execute("SELECT wall, counter FROM clock").fetchone()
        wall, counter = row if row else (0, 0)
        if (s.wall, s.counter) > (wall, counter):
            self._save_clock(Stamp(s.wall, s.counter, self.device_id))

    def _save_clock(self, s: Stamp) -> None:
        self.db.execute(
            "INSERT INTO clock (id, wall, counter) VALUES (1, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET wall = excluded.wall, counter = excluded.counter",
            (s.wall, s.counter),
        )

    def merge_into_db(self, task: str, field: str, value: Any, stamp: Stamp) -> None:
        """Apply one field change if its stamp is newer ([MRG-2])."""
        row = self.db.execute(
            "SELECT wall, counter, device FROM fields WHERE task = ? AND field = ?", (task, field)
        ).fetchone()
        if row is not None and Stamp(row[0], row[1], row[2]) >= stamp:
            return
        self.db.execute(
            "INSERT INTO fields (task, field, value, wall, counter, device) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (task, field) DO UPDATE SET value = excluded.value, wall = excluded.wall, "
            "counter = excluded.counter, device = excluded.device",
            (task, field, json.dumps(value), stamp.wall, stamp.counter, stamp.device),
        )

    def edit(self, task: str, field: str, value: Any) -> bytes:
        """Apply an edit and write its outbox row in one transaction ([DLV-2]).

        Returns:
            The change ID.
        """
        if field not in FIELDS:
            raise ValueError(field)
        cid = bytes(self.engine.new_change_id())
        with self.transaction():
            stamp = self._tick()
            self.merge_into_db(task, field, value, stamp)
            seq = self.db.execute("SELECT coalesce(max(seq), 0) + 1 FROM outbox").fetchone()[0]
            self.db.execute(
                "INSERT INTO outbox (change_id, change_bytes, seq) VALUES (?, ?, ?)",
                (cid, encode_change(task, field, value, stamp), seq),
            )
        self.flush_outbox()
        return cid

    def flush_outbox(self) -> None:
        """Give the outbox rows to the engine, in batches ([DLV-2], [DLV-4]).

        A refused change ([DLV-5], [DLV-9]) is reverted: the app removes the
        row. The task field keeps its value until a newer change arrives,
        and the change stays in `refused` for the user.
        """
        rows = self.db.execute("SELECT change_id, change_bytes FROM outbox ORDER BY seq").fetchall()
        for i in range(0, len(rows), BATCH):
            batch = [
                sf.OutboxRow(change_id=bytes(c), change_bytes=bytes(b))
                for c, b in rows[i : i + BATCH]
            ]
            result = self.engine.enqueue_many(batch)
            for cid in result.refused:
                with self.transaction():
                    self.db.execute("DELETE FROM outbox WHERE change_id = ?", (bytes(cid),))
                self.refused.append(bytes(cid))

    def sync(self, send: Transport) -> sf.Status:
        """Exchange with the relay, then pull. Returns the engine status."""
        exchange = self.engine.start_sync()
        while (req := exchange.next_request()) is not None:
            status, headers, body = send(req)
            exchange.handle_response(status, headers, body)
        self.pull()
        self.flush_outbox()
        return self.engine.status()

    def pull(self) -> int:
        """Apply the changes after the applied position ([DLV-10], [DLV-11]).

        Each batch is one durable transaction. The position check is inside
        the transaction, so a crash between batches applies no change twice.

        Returns:
            The number of changes from other devices that the app applied.
        """
        applied = 0
        while True:
            try:
                batch = self.engine.changes_after(self.applied_position(), BATCH)
            except sf.SnailfishError.ResetRequired:
                self.reset()
                continue
            if not batch:
                return applied
            with self.transaction():
                for c in batch:
                    if c.position <= self.applied_position().position:
                        continue
                    cid = bytes(c.change_id)
                    own = self.db.execute(
                        "SELECT 1 FROM outbox WHERE change_id = ?", (cid,)
                    ).fetchone()
                    if own:
                        self.db.execute("DELETE FROM outbox WHERE change_id = ?", (cid,))
                    else:
                        task, field, value, stamp = decode_change(bytes(c.change_bytes))
                        self._observe(stamp)
                        self.merge_into_db(task, field, value, stamp)
                        applied += 1
                    self._ghost_applied(cid)
                    self.db.execute(
                        "INSERT INTO applied (id, position, digest) VALUES (1, ?, ?) "
                        "ON CONFLICT (id) DO UPDATE SET position = excluded.position, "
                        "digest = excluded.digest",
                        (c.position, bytes(c.digest)),
                    )

    def _ghost_applied(self, cid: bytes) -> None:
        """Count each change that the app handles, own edits included.

        The crash tests read this table: a second row for one change_id is
        a change applied twice. The primary key makes it fail loudly.
        """
        self.db.execute("INSERT INTO applied_log (change_id) VALUES (?)", (cid,))

    def reset(self) -> None:
        """Handle `ResetRequired`: delete the synced data, apply each outbox
        row again, and pull from the start ([DLV-12]). M2 has no snapshot."""
        with self.transaction():
            self.db.execute("DELETE FROM fields")
            self.db.execute("DELETE FROM applied")
            self.db.execute("DELETE FROM applied_log")
            for (b,) in self.db.execute("SELECT change_bytes FROM outbox ORDER BY seq").fetchall():
                task, field, value, stamp = decode_change(bytes(b))
                self.merge_into_db(task, field, value, stamp)

    def tasks(self) -> dict[str, dict[str, Any]]:
        """Return the app state: each task with its fields."""
        out: dict[str, dict[str, Any]] = {}
        for task, field, value in self.db.execute(
            "SELECT task, field, value FROM fields ORDER BY task, field"
        ):
            out.setdefault(task, {})[field] = json.loads(value)
        return out

    def outbox_ids(self) -> list[bytes]:
        """Return the change IDs of the app outbox."""
        return [bytes(r[0]) for r in self.db.execute("SELECT change_id FROM outbox ORDER BY seq")]

    def handled_ids(self) -> list[bytes]:
        """Return each change ID that a pull handled."""
        return [bytes(r[0]) for r in self.db.execute("SELECT change_id FROM applied_log")]


class Txn:
    """One `BEGIN IMMEDIATE` transaction on the app database."""

    def __init__(self, db: sqlite3.Connection, crash_point: Callable[[str], None]) -> None:
        """Wrap `db`. `crash_point` runs around the commit."""
        self.db = db
        self.crash_point = crash_point

    def __enter__(self) -> sqlite3.Connection:
        """Begin the transaction."""
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Commit, or roll back after an exception."""
        if exc_type:
            self.db.execute("ROLLBACK")
            return
        self.crash_point("before an app commit")
        self.db.execute("COMMIT")
        self.crash_point("after an app commit")


def iter_tasks(state: dict[str, dict[str, Any]]) -> Iterator[str]:
    """Return one line of text for each task."""
    for task, f in sorted(state.items()):
        mark = "x" if f.get("done") else " "
        yield f"[{mark}] {task}: {f.get('title', '')}"
