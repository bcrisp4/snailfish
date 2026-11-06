"""The demo task app: one device is one data directory.

The layout of a device directory:

- `app.sqlite3`: the app database. It holds the tasks, the app outbox and
  the applied position (DESIGN.md "App integration").
- `engine/`: the engine state file. Only the engine writes it.
- `space.json`: the space reference.
- `keystore.json`: the key store of the demo (`FileKeyStore`). The engine
  reads and writes the device keys and the app key there. The Swift app
  uses the data protection keychain.

The merge rules meet the merge contract ([MRG-1], [MRG-2]): each field of a
task is a last-writer-wins register on a hybrid logical clock, with the
device ID as the tie-break. The result depends on the set of changes, not
on their order.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
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


# A `stale_base` refusal of the grant or a paused relay leaves the grant for
# a later sync (PROTOCOL.md 13.4), so `recover` syncs again. The Swift app
# waits until the user cancels. The CLI has no cancel, so it stops after
# these syncs.
RECOVER_SYNCS = 5
RECOVER_WAIT_SECONDS = 1


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


def write_private(path: Path, text: str) -> None:
    """Write a file with mode 0600, durably, through a temporary name."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


class FileKeyStore(sf.KeyStore):
    """The key store of the demo: one JSON file with mode 0600 that maps each
    account to its item in hex (DESIGN.md "App integration")."""

    def __init__(self, path: Path) -> None:
        """Use the file at `path`. The first write creates it."""
        self.path = path

    def _items(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        items: dict[str, str] = json.loads(self.path.read_text())
        return items

    def load(self, account: str) -> bytes | None:
        """Return the item of `account`, or None."""
        v = self._items().get(account)
        return None if v is None else bytes.fromhex(v)

    def store(self, account: str, secret: bytes) -> None:
        """Replace the item of `account`, durably."""
        items = self._items()
        items[account] = secret.hex()
        write_private(self.path, json.dumps(items))

    def delete(self, account: str) -> None:
        """Remove the item of `account`, durably, if it exists."""
        items = self._items()
        if items.pop(account, None) is not None:
            write_private(self.path, json.dumps(items))


def key_store(data_dir: Path) -> FileKeyStore:
    """Return the key store of the device in `data_dir`."""
    return FileKeyStore(data_dir / "keystore.json")


class Browser(Protocol):
    """Shows the sign-in page of the relay to the user and returns the URL
    that the relay redirects to after the user allows the app."""

    def __call__(self, authorize_url: str) -> str:
        """Return the redirect URL for `authorize_url`."""
        ...


def sign_in(
    relay_url: str, keys: sf.DeviceKeys, redirect_uri: str, browser: Browser, send: Transport
) -> sf.SetupToken:
    """The native sign-in of PROTOCOL.md 12.2 and 12.3: the user signs in
    with a passkey in the browser and allows the app, and the device key
    exchanges the code for a setup token and the tenant handle."""
    si = sf.SignIn(relay_url, redirect_uri)
    redirect = browser(si.authorize_url())
    status, headers, body = send(si.token_request(redirect, keys, int(time.time())))
    try:
        return si.read_token(status, headers, body)
    except sf.SnailfishError.Invalid as e:
        # PROTOCOL.md 8.5: after `expired`, send once more with the relay time.
        if "expired" not in str(e):
            raise
    status, headers, body = send(si.token_request(redirect, keys, int(time.time())))
    return si.read_token(status, headers, body)


def create_space(
    relay_url: str, dir_a: Path, redirect_uri: str, browser: Browser, send: Transport
) -> str:
    """Create a space with device A as its first device.

    The user signs in first. The sign-in gives the tenant handle and the
    setup token. The engine makes the recovery key and the genesis record.
    The function writes A's key file and engine setup. A's next sync creates
    the space on the relay. Each other device joins through an enrollment.

    Returns:
        The recovery key in its display form. Show it once.
    """
    ka = sf.new_device_keys()
    token = sign_in(relay_url, ka, redirect_uri, browser, send)
    # PROTOCOL.md 13.4: a space of this app exists, so the user recovers it
    # with the recovery key and makes no second space.
    if any(s.app_id == APP_ID for s in token.spaces):
        raise SpaceExistsError(APP_ID)
    setup = sf.create_space(APP_ID, sf.NewDevice(keys=ka, name="A"))
    ka.app_key = setup.app_key
    space = {
        "relay_url": relay_url,
        "tenant": token.tenant,
        "log_id": setup.log_id,
        "app_id": APP_ID,
    }
    dir_a.mkdir(parents=True, exist_ok=True)
    sf.install_setup(
        str(dir_a / "engine"),
        sf.SpaceRef(**space),
        ka,
        setup.envelopes,
        token.token,
        key_store(dir_a),
    )
    write_private(dir_a / "space.json", json.dumps(space))
    return setup.recovery_key


def sign_in_again(dev: Device, redirect_uri: str, browser: Browser, send: Transport) -> None:
    """Sign in again after `stopped: setup failed` (PROTOCOL.md 10.5, 12.3).

    The engine signs the token request with the device keys that it holds,
    so the next sync creates the same space, with the same recovery key.
    """
    si = sf.SignIn(dev.space.relay_url, redirect_uri)
    redirect = browser(si.authorize_url())
    status, headers, body = send(
        si.token_request_for_engine(redirect, dev.engine, int(time.time()))
    )
    try:
        token = si.read_token(status, headers, body)
    except sf.SnailfishError.Invalid as e:
        # PROTOCOL.md 8.5: after `expired`, send once more with the relay time.
        if "expired" not in str(e):
            raise
        status, headers, body = send(
            si.token_request_for_engine(redirect, dev.engine, int(time.time()))
        )
        token = si.read_token(status, headers, body)
    dev.engine.set_setup_token(token.token)


class SpaceExistsError(Exception):
    """The tenant has a space of this app: recover it, do not make another."""


def recover(
    relay_url: str,
    data_dir: Path,
    name: str,
    recovery_key: str,
    redirect_uri: str,
    browser: Browser,
    send: Transport,
) -> Device:
    """Full recovery onto a new device (S5, PROTOCOL.md 13.4).

    The user signs in, and the sign-in names the space of the app. The
    engine verifies the log from the genesis record, and the recovery key
    signs a grant for this device. The function syncs until the verified
    log holds the grant. The device can then remove the lost devices.

    Raises:
        RecoveryError: The space does not exist, or the sync did not grant
            this device, for example after a wrong recovery key.
    """
    keys = sf.new_device_keys()
    token = sign_in(relay_url, keys, redirect_uri, browser, send)
    found = [s for s in token.spaces if s.app_id == APP_ID]
    if not found:
        raise RecoveryError("the account has no space of this app")
    space = {
        "relay_url": relay_url,
        "tenant": token.tenant,
        "log_id": found[0].log_id,
        "app_id": APP_ID,
    }
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        engine = sf.Engine.open_recovery(
            str(data_dir / "engine"),
            sf.SpaceRef(**space),
            keys,
            recovery_key,
            name,
            key_store(data_dir),
        )
    except sf.SnailfishError.Invalid as e:
        raise RecoveryError(str(e)) from e
    write_private(data_dir / "space.json", json.dumps(space))
    dev = Device(data_dir, engine=engine)
    status = dev.sync(send)
    for _ in range(RECOVER_SYNCS - 1):
        if any(d.this_device for d in dev.engine.active_devices()):
            return dev
        paused = (
            status.is_ok()
            or status.is_relay_unavailable()
            or status.is_restore_hold()
            or status.is_quota()
        )
        if not paused:
            break
        time.sleep(RECOVER_WAIT_SECONDS)
        status = dev.sync(send)
    if any(d.this_device for d in dev.engine.active_devices()):
        return dev
    dev.close()
    raise RecoveryError(f"no grant for this device: {status}")


class RecoveryError(Exception):
    """A full recovery did not grant this device."""


class ConfirmStay(Protocol):
    """Shows the devices that stay and asks the user to confirm the list."""

    def __call__(self, stay: str) -> bool:
        """Return True if the user confirms that only `stay` stays."""
        ...


def remove(dev: Device, removed: list[str], send: Transport, confirm: ConfirmStay) -> sf.Status:
    """Remove devices and rotate the key (S4, PROTOCOL.md 13.2).

    `confirm` gets the list of the devices that stay and returns True if
    the user confirms it. If another device joined first, the engine asks
    again ([LOG-7]), and `confirm` gets the new list.

    Returns:
        The engine status after the sync.
    """
    while True:
        stay = [d for d in dev.engine.active_devices() if d.id not in removed]
        if not confirm(", ".join(f"{d.name} ({d.id})" for d in stay)):
            return dev.engine.status()
        dev.engine.remove_devices(removed)
        status = dev.sync(send)
        # The engine drops each device that another removal took first.
        again = dev.engine.removal_to_confirm()
        if again is None:
            return status
        removed = again


# How long an enrollment waits between two reads of the session. The relay
# refills 2 requests per second for each IP address (`RATE` in
# crates/relay/src/http.rs). The two devices of an enrollment often share
# one address, so each device polls at most once a second.
POLL_SECONDS = 1.0


class Answer(Protocol):
    """Asks the user whether the code on the other device matches."""

    def __call__(self, code: str) -> bool:
        """Return True if the user confirms that `code` matches."""
        ...


class Say(Protocol):
    """Shows one line to the user."""

    def __call__(self, line: str) -> None:
        """Show `line`."""
        ...


def _ended(state: sf.EnrollState) -> bool:
    return isinstance(state, (sf.EnrollState.DONE, sf.EnrollState.FAILED))


def _cause(state: sf.EnrollState) -> str:
    return state.cause if isinstance(state, sf.EnrollState.FAILED) else ""


def invite(
    dev: Device,
    send: Transport,
    answer: Answer,
    say: Say,
    scanned: str | None = None,
    recovery_key: str | None = None,
    again: Callable[[], bool] | None = None,
) -> str:
    """Enroll a new device from this trusted device ([ENR-1] to [ENR-8]).

    If `scanned` is None, this device shows the session: `say` gets the QR
    payload and the typed code. Otherwise `scanned` is the payload or the
    typed code that the new device shows. If the user gives the recovery
    key, it signs the grant. `again` asks the user to confirm the grant
    again after another device joined or left first ([LOG-7]). Without it,
    the enrollment stops at that question.

    Returns:
        An empty string on success, or the cause of the failure.
    """
    t = sf.TrustedEnrollment(dev.engine, scanned, recovery_key)
    shown = scanned is not None
    while not _ended(state := t.state()):
        # The payload exists once the relay opened the session.
        if not shown and (payload := t.payload()) is not None:
            say(f"payload: {payload}")
            say(f"code: {t.code()}")
            shown = True
        if isinstance(state, sf.EnrollState.COMPARE):
            t.confirm(answer(state.code))
            continue
        if isinstance(state, sf.EnrollState.CONFIRM_AGAIN):
            t.confirm(again is not None and again())
            continue
        req = t.next_request()
        if req is None:
            break
        t.handle_response(*send(req))
        if isinstance(t.state(), sf.EnrollState.WAITING):
            time.sleep(POLL_SECONDS)
    return _cause(t.state())


def join(
    data_dir: Path,
    relay_url: str,
    name: str,
    send: Transport,
    answer: Answer,
    say: Say,
    scanned: str | None = None,
) -> str:
    """Join a space as a new device ([ENR-1] to [ENR-9]).

    The function makes the device keys. If `scanned` is None, this device
    shows the session: `say` gets the QR payload and the typed code.
    After the enrollment it writes the key file and the engine state, and
    the first sync checks the log up to the checkpoint before it uploads
    anything.

    Returns:
        An empty string on success, or the cause of the failure.
    """
    keys = sf.new_device_keys()
    n = sf.NewEnrollment(relay_url, keys, name, scanned)
    if (payload := n.payload()) is not None:
        say(f"payload: {payload}")
        say(f"code: {n.code()}")
    while not _ended(state := n.state()):
        if isinstance(state, sf.EnrollState.COMPARE):
            n.confirm(answer(state.code))
            continue
        req = n.next_request()
        if req is None:
            break
        status, _, body = send(req)
        n.handle_response(status, body)
        if isinstance(n.state(), sf.EnrollState.WAITING):
            time.sleep(POLL_SECONDS)
    joined = n.joined()
    if joined is None:
        return _cause(n.state()) or "the enrollment ended with no result"
    space = {
        "relay_url": n.relay_url(),
        "tenant": joined.tenant,
        "log_id": joined.log_id,
        "app_id": APP_ID,
    }
    data_dir.mkdir(parents=True, exist_ok=True)
    # The engine writes its state, then the keys ([ENR-9]).
    sf.install_enrollment(
        str(data_dir / "engine"), sf.SpaceRef(**space), keys, joined, key_store(data_dir)
    )
    write_private(data_dir / "space.json", json.dumps(space))
    return ""


def _no_crash(_name: str) -> None:
    """A crash point that does nothing."""


class Device:
    """One device of the demo app."""

    def __init__(
        self,
        data_dir: Path,
        now_ms: Callable[[], int] | None = None,
        crash_point: Callable[[str], None] | None = None,
        engine: sf.Engine | None = None,
    ) -> None:
        """Open the device in `data_dir`.

        `engine` is an engine that the caller opened, for example for a full
        recovery. Without it, the device opens the engine from its key store.

        `crash_point` runs before each app transaction, before each commit
        and after each commit. The crash tests use it to stop the process.

        The app database uses WAL with `synchronous=FULL`, and `fullfsync`
        on Apple platforms ([DLV-1]). At startup the app gives its outbox
        rows to the engine again ([DLV-2]).
        """
        self.dir = data_dir
        self.space = sf.SpaceRef(**json.loads((data_dir / "space.json").read_text()))
        self.engine = engine or sf.Engine.open(
            str(data_dir / "engine"), self.space, key_store(data_dir)
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
        self.repairs: list[sf.Repair] = []
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

    def edit_many(self, count: int, prefix: str) -> None:
        """Set the title of tasks `<prefix>-0` to `<prefix>-<count - 1>`, with
        one app transaction for each batch of edits ([DLV-3])."""
        for start in range(0, count, BATCH):
            with self.transaction():
                seq = self.db.execute("SELECT coalesce(max(seq), 0) FROM outbox").fetchone()[0]
                for i in range(start, min(start + BATCH, count)):
                    task = f"{prefix}-{i}"
                    stamp = self._tick()
                    self.merge_into_db(task, "title", task, stamp)
                    seq += 1
                    self.db.execute(
                        "INSERT INTO outbox (change_id, change_bytes, seq) VALUES (?, ?, ?)",
                        (
                            bytes(self.engine.new_change_id()),
                            encode_change(task, "title", task, stamp),
                            seq,
                        ),
                    )
        self.flush_outbox()

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
        """Exchange with the relay, then pull. Returns the engine status.

        After the exchange, `repairs` holds each repair of the relay log
        that this device made (S6), for the app to show.
        """
        exchange = self.engine.start_sync()
        while (req := exchange.next_request()) is not None:
            status, headers, body = send(req)
            exchange.handle_response(status, headers, body)
        self.repairs = self.engine.take_repairs()
        self.pull()
        self.flush_outbox()
        self.check_snapshots()
        if self.engine.snapshot_due():
            self.write_snapshot()
        return self.engine.status()

    def export_state(self) -> bytes:
        """Return the app state with its merge metadata ([CMP-2]).

        Each field keeps its hybrid logical clock stamp, so a later change
        merges as on a device that applied every change ([MRG-4]).
        """
        rows = self.db.execute(
            "SELECT task, field, value, wall, counter, device FROM fields ORDER BY task, field"
        ).fetchall()
        body = {"v": FORMAT, "fields": [list(r) for r in rows]}
        return json.dumps(body, separators=(",", ":")).encode()

    @staticmethod
    def can_import(state: bytes) -> bool:
        """Check a snapshot state without a change to the app database ([CMP-2])."""
        try:
            d = json.loads(state)
            if d.get("v") != FORMAT:
                return False
            for task, field, value, wall, counter, device in d["fields"]:
                json.loads(value)
                if not (
                    isinstance(task, str)
                    and field in FIELDS
                    and isinstance(wall, int)
                    and isinstance(counter, int)
                    and isinstance(device, str)
                ):
                    return False
        except (ValueError, TypeError, KeyError):
            return False
        return True

    def _import_state(self, state: bytes) -> None:
        """Replace the synced data with a snapshot state, inside the caller's
        transaction ([CMP-2])."""
        self.db.execute("DELETE FROM fields")
        for task, field, value, wall, counter, device in json.loads(state)["fields"]:
            self.db.execute(
                "INSERT INTO fields (task, field, value, wall, counter, device) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (task, field, value, wall, counter, device),
            )
            self._observe(Stamp(wall, counter, device))

    def check_snapshots(self) -> None:
        """Check each new snapshot with `can_import`, and accept it ([CMP-5])."""
        for snap in self.engine.unchecked_snapshots():
            self.engine.accept_snapshot(snap.position, self.can_import(bytes(snap.state_bytes)))

    def write_snapshot(self) -> bool:
        """Write a snapshot of the state at the applied position, only with
        an empty app outbox ([CMP-3]). Returns true if the engine queued it:
        false for a state over the relay limit, which sets `degraded`."""
        with self.transaction():
            if self.db.execute("SELECT 1 FROM outbox LIMIT 1").fetchone():
                return False
            applied = self.applied_position()
            state = self.export_state()
        if applied.position == 0:
            return False
        return self.engine.write_snapshot(applied, state)

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
        """Handle `ResetRequired` (DESIGN.md "Log compaction", [DLV-12]).

        Delete the synced data and import the usable snapshot, if any. Then
        apply each outbox row again, unless the snapshot already holds its
        edit ([CMP-14]). The next pull starts after the state position.
        """
        snap = self.engine.usable_snapshot()
        with self.transaction():
            self.db.execute("DELETE FROM fields")
            self.db.execute("DELETE FROM applied")
            self.db.execute("DELETE FROM applied_log")
            if snap is not None:
                self._import_state(bytes(snap.state_bytes))
                self.db.execute(
                    "INSERT INTO applied (id, position, digest) VALUES (1, ?, ?)",
                    (snap.state_position, bytes(snap.state_digest)),
                )
            rows = self.db.execute("SELECT change_id, change_bytes FROM outbox ORDER BY seq")
            for c, b in rows.fetchall():
                if self.engine.is_covered(bytes(c)):
                    self.db.execute("DELETE FROM outbox WHERE change_id = ?", (bytes(c),))
                    continue
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


# ---------------------------------------------------------------- M9
# Deletion, export, import, a move to another relay and fork repair
# (PROTOCOL.md 10.12, 10.13 and section 15, DESIGN.md "Fork repair").

OLD_ENGINE = "engine-old"


class ImportError_(Exception):
    """The relay refused an import, or the space is not in the account."""


def run_import(imp: sf.Import, send: Transport) -> None:
    """Run an import session (PROTOCOL.md 10.13) until it ends.

    Raises:
        ImportError_: The relay refused a request, with its error code.
    """
    try:
        while (req := imp.next_request()) is not None:
            imp.handle_response(*send(req))
    except sf.SnailfishError.Refused as e:
        raise ImportError_(str(e)) from e


def delete_space(dev: Device, send: Transport) -> sf.Status:
    """Delete the space on the relay ([LOG-13], [FRK-4]). The device syncs
    first, because the statement names the verified head. Each device keeps
    its data. Returns `stopped: deleted` on success."""
    dev.sync(send)
    req = dev.engine.delete_request()
    dev.engine.handle_delete_response(*send(req))
    return dev.engine.status()


def export_log(dev: Device, path: Path) -> int:
    """Write the export file of the verified log ([FRK-3], section 15).
    Returns the head position."""
    data = dev.engine.export_log()
    write_private(path, data.decode())
    return dev.engine.verified_head().position


def _engine_token(
    engine: sf.Engine, relay_url: str, redirect_uri: str, browser: Browser, send: Transport
) -> sf.SetupToken:
    """A setup token for the device keys of `engine` on `relay_url`."""
    si = sf.SignIn(relay_url, redirect_uri)
    redirect = browser(si.authorize_url())
    for _ in range(2):
        status, headers, body = send(
            si.token_request_for_engine(redirect, engine, int(time.time()))
        )
        try:
            return si.read_token(status, headers, body)
        except sf.SnailfishError.Invalid as e:
            # PROTOCOL.md 8.5: after `expired`, send once more with the relay time.
            if "expired" not in str(e):
                raise
    raise ImportError_("the sign-in failed twice with expired")


def _save_space(data_dir: Path, space: sf.SpaceRef) -> None:
    write_private(
        data_dir / "space.json",
        json.dumps(
            {
                "relay_url": space.relay_url,
                "tenant": space.tenant,
                "log_id": space.log_id,
                "app_id": space.app_id,
            }
        ),
    )


def import_space(
    dev: Device, relay_url: str, redirect_uri: str, browser: Browser, send: Transport
) -> sf.SpaceRef:
    """Import the verified log into the relay at `relay_url` ([FRK-5]): the
    same relay after a deletion, or a new relay. The user signs in there.
    The device then uses that relay. Returns the new space reference."""
    token = _engine_token(dev.engine, relay_url, redirect_uri, browser, send)
    target = sf.SpaceRef(
        relay_url=relay_url, tenant=token.tenant, log_id=dev.space.log_id, app_id=APP_ID
    )
    run_import(dev.engine.import_space(target, token.token), send)
    _save_space(dev.dir, target)
    return target


def switch_relay(
    dev: Device, relay_url: str, redirect_uri: str, browser: Browser, send: Transport
) -> sf.SpaceRef:
    """Use the space on another relay after a move ([FRK-5]). The device
    keeps its state file: its verified log is the imported log.

    Raises:
        ImportError_: The account on that relay holds no space of this log.
    """
    token = _engine_token(dev.engine, relay_url, redirect_uri, browser, send)
    if not any(s.log_id == dev.space.log_id for s in token.spaces):
        raise ImportError_("the account on that relay holds no space of this log")
    target = sf.SpaceRef(
        relay_url=relay_url, tenant=token.tenant, log_id=dev.space.log_id, app_id=APP_ID
    )
    _save_space(dev.dir, target)
    return target


def prepare_rejoin(data_dir: Path, log_id: str) -> None:
    """FRK-6: keep the key item and the state file of the old engine before
    the device enrolls again. The enrollment writes new keys and a new state
    file. The app database stays."""
    old = data_dir / OLD_ENGINE
    if old.exists():
        # An earlier rejoin stopped before its recovery. The old key item
        # and state file are in place. A new copy would hold the new keys.
        return
    sf.keep_old_keys(key_store(data_dir), log_id)
    (data_dir / "engine").rename(old)


def first_exchange(engine: sf.Engine, send: Transport) -> sf.Status:
    """One exchange with no pull. A new state file checks its enrollment
    checkpoint and opens the app key in it ([ENR-9])."""
    exchange = engine.start_sync()
    while (req := exchange.next_request()) is not None:
        exchange.handle_response(*send(req))
    return engine.status()


def recover_fork(data_dir: Path, space: sf.SpaceRef, engine: sf.Engine) -> int:
    """FRK-7 and FRK-8: write an outbox row for each own change that only the
    old state file holds, with its old change ID. The app writes the rows
    before its next pull, because that pull raises ResetRequired and the
    reset applies each outbox row again. The old state file goes only after
    the commit, so a crash before that point runs the comparison again with
    the same result.

    Returns:
        The number of recovered changes.
    """
    old_dir = data_dir / OLD_ENGINE
    if not old_dir.exists():
        return 0
    old = sf.Engine.open_old(str(old_dir), space, key_store(data_dir))
    rows = engine.fork_changes(old)
    db = sqlite3.connect(data_dir / "app.sqlite3", isolation_level=None)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA fullfsync=ON")
        db.execute("BEGIN IMMEDIATE")
        seq = db.execute("SELECT coalesce(max(seq), 0) FROM outbox").fetchone()[0]
        for r in rows:
            seq += 1
            db.execute(
                "INSERT OR IGNORE INTO outbox (change_id, change_bytes, seq) VALUES (?, ?, ?)",
                (bytes(r.change_id), bytes(r.change_bytes), seq),
            )
        db.execute("COMMIT")
    finally:
        db.close()
    del old
    shutil.rmtree(old_dir)
    key_store(data_dir).delete(f"{space.log_id}.old")
    return len(rows)


def restore_from_file(
    relay_url: str,
    data_dir: Path,
    name: str,
    file: Path,
    recovery_key: str,
    redirect_uri: str,
    browser: Browser,
    send: Transport,
) -> Device:
    """DESIGN.md "Data retention": after the loss of every device and of the
    relay copy, import the export file and recover the space with the paper
    recovery key on a new device."""
    data = file.read_bytes()
    log_id = json.loads(data.split(b"\n", 1)[0])["log"]
    keys = sf.new_device_keys()
    token = sign_in(relay_url, keys, redirect_uri, browser, send)
    space = sf.SpaceRef(relay_url=relay_url, tenant=token.tenant, log_id=log_id, app_id=APP_ID)
    run_import(sf.import_file(data, space, keys, token.token, recovery_key), send)
    return recover(relay_url, data_dir, name, recovery_key, redirect_uri, browser, send)
