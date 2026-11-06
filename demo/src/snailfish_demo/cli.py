"""The demo task app CLI.

Usage:
    snailfish-demo setup --relay URL [--browser STATE --user NAME] DIR_A
    snailfish-demo --dir DIR invite [--scan TEXT] [--recovery-key KEY] [--confirm ask|yes|no]
    snailfish-demo join --relay URL [--scan TEXT] [--name NAME] [--confirm ask|yes|no] DIR
    snailfish-demo --dir DIR edit TASK FIELD VALUE
    snailfish-demo --dir DIR sync
    snailfish-demo --dir DIR list
    snailfish-demo --dir DIR sign-in-again [--browser STATE --user NAME]
    snailfish-demo --dir DIR devices
    snailfish-demo --dir DIR remove [--confirm ask|yes|no] DEVICE_ID...
    snailfish-demo --dir DIR replace-recovery-key [--current KEY] [--new KEY]
    snailfish-demo recover --relay URL --recovery-key KEY
        [--browser STATE --user NAME] [--name NAME] DIR
    snailfish-demo --dir DIR delete
    snailfish-demo --dir DIR export FILE
    snailfish-demo --dir DIR import [--relay URL] [--browser STATE --user NAME]
    snailfish-demo --dir DIR switch-relay --relay URL [--browser STATE --user NAME]
    snailfish-demo rejoin [--scan TEXT] [--name NAME] [--confirm ask|yes|no] DIR
    snailfish-demo restore --relay URL --file FILE --recovery-key KEY
        [--browser STATE --user NAME] [--name NAME] DIR

`invite` runs on a device of the space and `join` on the new device. The
device that shows the session prints its QR payload as a text line and
its typed code. The other device takes either one with `--scan`. Both
devices print the 6-digit code, and the user confirms the match on each
device at a prompt. `--confirm yes` or `--confirm no` answers the prompt
with no input, for tests.

`setup` signs in to the relay in the system browser and creates a space.
It prints the sign-in URL and waits for the browser to return to a loopback
address. `--browser STATE --user NAME` uses the software browser of
`softbrowser.py` with the state file STATE instead, for tests.

`remove` shows the devices that stay and asks the user to confirm them,
then removes the named devices and rotates the key (S4). `replace-recovery-key`
prints a new recovery key, asks the user to type it back, and asks for the
current key (`--current` and `--new` answer with no input, for tests).
`recover` signs in on a new device, finds the space of the app and recovers
it with the paper recovery key (S5).

Fork repair (DESIGN.md "Fork repair"): on the source device, `delete`
deletes the space on the relay and `import` uploads its log again, or to
another relay with `--relay`. Each other device runs `rejoin`: it keeps
its old state file, enrolls again from the source (with `invite` there),
and sends each own change that only the old file holds. For a move to
another relay, the source runs `import --relay URL` and each other device
runs `switch-relay --relay URL`. `export` writes the export file of the
log, and `restore` makes the space again from it with the recovery key
after the loss of every device.

`SNAILFISH_DEMO_CRASH_AT=N` makes the process exit at the Nth crash point
of the run, with no cleanup, as a kill does. The crash points are before
and after each HTTP request, and around each app transaction. The crash
tests use them.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import snailfish as sf

from snailfish_demo import app, softbrowser

if TYPE_CHECKING:
    from collections.abc import Callable


class Crasher:
    """Exits at once at the Nth crash point, as a kill does.

    `SNAILFISH_DEMO_CRASH_AT` sets N. Without it, no crash point exits.
    """

    def __init__(self) -> None:
        """Read N from the environment."""
        at = os.environ.get("SNAILFISH_DEMO_CRASH_AT")
        self.at = int(at) if at else None
        self.count = 0

    def __call__(self, name: str) -> None:
        """Count one crash point, and exit if it is the Nth."""
        if self.at is None:
            return
        self.count += 1
        if self.count == self.at:
            sys.stderr.write(f"crash at point {self.count}: {name}\n")
            sys.stderr.flush()
            os._exit(137)


def http_transport(client: httpx.Client, crash_point: Crasher) -> app.Transport:
    """Return a transport that sends each request with `client`.

    The client follows no redirects, because the request signature covers
    the relay authority (DESIGN.md "App integration").
    """

    def send(req: sf.Request) -> tuple[int, list[sf.Header], bytes]:
        crash_point(f"before {req.method} {req.url}")
        resp = client.request(
            req.method,
            req.url,
            headers=[(h.name, h.value) for h in req.headers],
            content=req.body,
            follow_redirects=False,
        )
        crash_point(f"after {req.method} {req.url}")
        return (
            resp.status_code,
            [sf.Header(name=k, value=v) for k, v in resp.headers.multi_items()],
            resp.content,
        )

    return send


# The redirect URI of the software browser. It never navigates, so a
# private-use scheme like that of a phone app works (PROTOCOL.md 12.2).
SOFT_REDIRECT = "com.example.tasks:/callback"


class _CatchServer(http.server.HTTPServer):
    """An HTTP server that keeps the path of the redirect."""

    got: str | None = None


class _Catch(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/callback?") and isinstance(self.server, _CatchServer):
            self.server.got = self.path
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Sign-in done. You can close this page.")


class Loopback:
    """A one-request HTTP server on 127.0.0.1 that catches the redirect of
    the system browser (RFC 8252 section 7.3)."""

    def __init__(self) -> None:
        """Listen on a free port."""
        self.server = _CatchServer(("127.0.0.1", 0), _Catch)
        self.uri = f"http://127.0.0.1:{self.server.server_port}/callback"

    def __enter__(self) -> Loopback:
        """Return self."""
        return self

    def __exit__(self, *_: object) -> None:
        """Stop listening."""
        self.server.server_close()

    def wait(self, authorize_url: str) -> str:
        """Print the sign-in URL and return the redirect URL of the browser."""
        say(f"open this URL in a browser to sign in: {authorize_url}")
        while self.server.got is None:
            self.server.handle_request()
        return f"http://127.0.0.1:{self.server.server_port}{self.server.got}"


def say(line: str) -> None:
    """Print one line at once, so a test can read it while the process runs."""
    print(line, flush=True)


def answer_for(mode: str) -> app.Answer:
    """Return the code comparison: a prompt, or a fixed answer for tests."""

    def ask(code: str) -> bool:
        if mode != "ask":
            say(f"compare: {code}")
            return mode == "yes"
        reply = input(f"compare: {code}\nDoes the other device show the same code? [y/N] ")
        return reply.strip().lower() in ("y", "yes")

    return ask


def again_for(mode: str) -> Callable[[], bool]:
    """Return the question of [LOG-7]: a prompt, or a fixed answer for tests."""

    def ask() -> bool:
        if mode != "ask":
            say("confirm again: another device joined or left first")
            return mode == "yes"
        reply = input("Another device joined or left first. Add the new device anyway? [y/N] ")
        return reply.strip().lower() in ("y", "yes")

    return ask


def finish(cause: str) -> int:
    """Print the result of an enrollment and return the exit code."""
    if cause:
        say(f"failed: {cause}")
        return 1
    say("enrolled")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    p = argparse.ArgumentParser(prog="snailfish-demo")
    p.add_argument("--dir", type=Path)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--relay", required=True)
    s.add_argument("--browser", type=Path)
    s.add_argument("--user")
    s.add_argument("dir_a", type=Path)
    i = sub.add_parser("invite")
    i.add_argument("--scan")
    i.add_argument("--recovery-key")
    i.add_argument("--confirm", choices=("ask", "yes", "no"), default="ask")
    j = sub.add_parser("join")
    j.add_argument("--relay", required=True)
    j.add_argument("--scan")
    j.add_argument("--name", default="new device")
    j.add_argument("--confirm", choices=("ask", "yes", "no"), default="ask")
    j.add_argument("dir_new", type=Path)
    e = sub.add_parser("edit")
    e.add_argument("task")
    e.add_argument("field", choices=app.FIELDS)
    e.add_argument("value")
    m = sub.add_parser("edit-many")
    m.add_argument("count", type=int)
    m.add_argument("--prefix", default="bulk")
    sub.add_parser("snapshot")
    sub.add_parser("sync")
    sub.add_parser("list")
    sub.add_parser("dump")
    sub.add_parser("devices")
    g = sub.add_parser("sign-in-again")
    g.add_argument("--browser", type=Path)
    g.add_argument("--user")
    r = sub.add_parser("remove")
    r.add_argument("--confirm", choices=("ask", "yes", "no"), default="ask")
    r.add_argument("device_ids", nargs="+")
    k = sub.add_parser("replace-recovery-key")
    k.add_argument("--current")
    k.add_argument("--new")
    v = sub.add_parser("recover")
    v.add_argument("--relay", required=True)
    v.add_argument("--recovery-key", required=True)
    v.add_argument("--browser", type=Path)
    v.add_argument("--user")
    v.add_argument("--name", default="new device")
    v.add_argument("dir_new", type=Path)
    sub.add_parser("delete")
    x = sub.add_parser("export")
    x.add_argument("file", type=Path)
    im = sub.add_parser("import")
    im.add_argument("--relay")
    im.add_argument("--browser", type=Path)
    im.add_argument("--user")
    sw = sub.add_parser("switch-relay")
    sw.add_argument("--relay", required=True)
    sw.add_argument("--browser", type=Path)
    sw.add_argument("--user")
    rj = sub.add_parser("rejoin")
    rj.add_argument("--scan")
    rj.add_argument("--name", default="new device")
    rj.add_argument("--confirm", choices=("ask", "yes", "no"), default="ask")
    rj.add_argument("dir_old", type=Path)
    rs = sub.add_parser("restore")
    rs.add_argument("--relay", required=True)
    rs.add_argument("--file", type=Path, required=True)
    rs.add_argument("--recovery-key", required=True)
    rs.add_argument("--browser", type=Path)
    rs.add_argument("--user")
    rs.add_argument("--name", default="new device")
    rs.add_argument("dir_new", type=Path)
    args = p.parse_args(argv)
    if args.cmd in ("rejoin", "restore"):
        return lifecycle_command(args)

    if args.cmd == "setup":
        with httpx.Client(timeout=30) as client:
            send = http_transport(client, Crasher())
            if args.browser is not None:
                soft = softbrowser.SoftBrowser(args.browser, args.relay)
                key = app.create_space(
                    args.relay,
                    args.dir_a,
                    SOFT_REDIRECT,
                    lambda authorize_url: soft.approve(authorize_url, args.user or ""),
                    send,
                )
            else:
                with Loopback() as lb:
                    key = app.create_space(args.relay, args.dir_a, lb.uri, lb.wait, send)
        print(f"recovery key (write it down): {key}")
        return 0
    if args.cmd == "recover":
        with httpx.Client(timeout=30) as client:
            send = http_transport(client, Crasher())
            try:
                if args.browser is not None:
                    soft = softbrowser.SoftBrowser(args.browser, args.relay)
                    dev = app.recover(
                        args.relay,
                        args.dir_new,
                        args.name,
                        args.recovery_key,
                        SOFT_REDIRECT,
                        lambda authorize_url: soft.approve(authorize_url, args.user or ""),
                        send,
                    )
                else:
                    with Loopback() as lb:
                        dev = app.recover(
                            args.relay,
                            args.dir_new,
                            args.name,
                            args.recovery_key,
                            lb.uri,
                            lb.wait,
                            send,
                        )
            except app.RecoveryError as e:
                return finish(str(e))
        dev.close()
        print("recovered: remove the lost devices with `remove`")
        return 0
    if args.cmd == "join":
        with httpx.Client(timeout=30) as client:
            cause = app.join(
                args.dir_new,
                args.relay,
                args.name,
                http_transport(client, Crasher()),
                answer_for(args.confirm),
                say,
                args.scan,
            )
        return finish(cause)
    if args.dir is None:
        p.error("--dir is required")
    crasher = Crasher()
    dev = app.Device(args.dir, crash_point=crasher)
    try:
        if args.cmd == "invite":
            with httpx.Client(timeout=30) as client:
                cause = app.invite(
                    dev,
                    http_transport(client, crasher),
                    answer_for(args.confirm),
                    say,
                    args.scan,
                    args.recovery_key,
                    again_for(args.confirm),
                )
            return finish(cause)
        if args.cmd == "edit":
            value: object = args.value == "true" if args.field == "done" else args.value
            dev.edit(args.task, args.field, value)
        elif args.cmd == "edit-many":
            dev.edit_many(args.count, args.prefix)
        elif args.cmd == "snapshot":
            if not dev.write_snapshot():
                print(
                    "no snapshot: the app outbox holds a change, nothing is applied, "
                    "or the state is larger than the relay limit"
                )
                return 1
        elif args.cmd == "sync":
            with httpx.Client(timeout=30) as client:
                status = dev.sync(http_transport(client, crasher))
            for r in dev.repairs:
                print(
                    f"repair: the relay lost positions {r.first} to {r.tip}, "
                    "and this device uploaded them again"
                )
            print(f"status: {status}")
            return 0 if status.is_ok() else 1
        elif args.cmd == "list":
            for line in app.iter_tasks(dev.tasks()):
                print(line)
        elif args.cmd == "sign-in-again":
            with httpx.Client(timeout=30) as client:
                send = http_transport(client, crasher)
                if args.browser is not None:
                    soft = softbrowser.SoftBrowser(args.browser, dev.space.relay_url)
                    app.sign_in_again(
                        dev,
                        SOFT_REDIRECT,
                        lambda authorize_url: soft.approve(authorize_url, args.user or ""),
                        send,
                    )
                else:
                    with Loopback() as lb:
                        app.sign_in_again(dev, lb.uri, lb.wait, send)
        elif args.cmd == "devices":
            for d in dev.engine.active_devices():
                print(f"{d.id} {d.name}{' (this device)' if d.this_device else ''}")
        elif args.cmd == "remove":
            mode = args.confirm

            def confirm(stay: str) -> bool:
                say(f"devices that stay: {stay}")
                if mode != "ask":
                    return mode == "yes"
                reply = input("Keep only these devices? [y/N] ")
                return reply.strip().lower() in ("y", "yes")

            with httpx.Client(timeout=30) as client:
                status = app.remove(dev, args.device_ids, http_transport(client, crasher), confirm)
            print(f"status: {status}")
            return 0 if status.is_ok() else 1
        elif args.cmd == "replace-recovery-key":
            new = args.new or sf.new_recovery_key()
            if args.new is None:
                print(f"new recovery key (write it down): {new}")
                if input("type the new key back: ").strip().upper() != new:
                    return finish("the typed key differs")
            current = args.current or input("current recovery key: ")
            dev.engine.replace_recovery_key(current, new)
            with httpx.Client(timeout=30) as client:
                send = http_transport(client, crasher)
                # The recovery record, then the rotation after it (13.3).
                dev.sync(send)
                status = dev.sync(send)
            print(f"status: {status}")
            return 0 if status.is_ok() else 1
        elif args.cmd == "delete":
            with httpx.Client(timeout=30) as client:
                try:
                    status = app.delete_space(dev, http_transport(client, crasher))
                except sf.SnailfishError.Refused as e:
                    # bad_head: the verified head of this device is not in the
                    # relay log, for example after a fork (PROTOCOL.md 10.12).
                    return finish(
                        f"the relay refused the deletion ({e}): delete it from a device "
                        "that did not stop, or ask the relay operator to run "
                        "`snailfish-relay space delete`"
                    )
            print(f"status: {status}")
            return 0 if status.is_deleted() else 1
        elif args.cmd == "export":
            head = app.export_log(dev, args.file)
            print(f"exported: {head} entries to {args.file}")
        elif args.cmd in ("import", "switch-relay"):
            url = args.relay or dev.space.relay_url
            with httpx.Client(timeout=30) as client, BrowserFor(args, url) as (redirect, browse):
                send = http_transport(client, crasher)
                fn = app.import_space if args.cmd == "import" else app.switch_relay
                try:
                    space = fn(dev, url, redirect, browse, send)
                except app.ImportError_ as e:
                    return finish(str(e))
            print(f"space {space.log_id} on {space.relay_url}, tenant {space.tenant}")
        elif args.cmd == "dump":
            print(
                json.dumps(
                    {
                        "tasks": dev.tasks(),
                        "outbox": [c.hex() for c in dev.outbox_ids()],
                        "handled": [c.hex() for c in dev.handled_ids()],
                        "engine_outbox": dev.engine.outbox_len(),
                        "applied": dev.applied_position().position,
                        "head": dev.engine.verified_head().position,
                        "status": str(dev.engine.status()),
                        "log_id": dev.space.log_id,
                        "snapshot": (
                            None if (u := dev.engine.usable_snapshot()) is None else u.position
                        ),
                    },
                    sort_keys=True,
                )
            )
    finally:
        dev.close()
    return 0


class BrowserFor:
    """The browser of a sign-in: the software browser with `--browser`, or
    the system browser with a loopback redirect."""

    def __init__(self, args: argparse.Namespace, relay_url: str) -> None:
        """Keep the arguments."""
        self.args = args
        self.url = relay_url
        self.lb: Loopback | None = None

    def __enter__(self) -> tuple[str, app.Browser]:
        """Return the redirect URI and the browser."""
        if self.args.browser is not None:
            soft = softbrowser.SoftBrowser(self.args.browser, self.url)
            user = self.args.user or ""
            return SOFT_REDIRECT, lambda authorize_url: soft.approve(authorize_url, user)
        self.lb = Loopback()
        lb = self.lb.__enter__()
        return lb.uri, lb.wait

    def __exit__(self, *exc: object) -> None:
        """Stop the loopback server."""
        if self.lb is not None:
            self.lb.__exit__(*exc)


def lifecycle_command(args: argparse.Namespace) -> int:
    """`rejoin` and `restore`: they open the engine themselves."""
    with httpx.Client(timeout=30) as client:
        send = http_transport(client, Crasher())
        if args.cmd == "restore":
            with BrowserFor(args, args.relay) as (redirect, browse):
                try:
                    dev = app.restore_from_file(
                        args.relay,
                        args.dir_new,
                        args.name,
                        args.file,
                        args.recovery_key,
                        redirect,
                        browse,
                        send,
                    )
                except (app.ImportError_, app.RecoveryError) as e:
                    return finish(str(e))
            dev.close()
            print("restored: remove the lost devices with `remove`")
            return 0
        space = json.loads((args.dir_old / "space.json").read_text())
        app.prepare_rejoin(args.dir_old, space["log_id"])
        if not (args.dir_old / "engine").exists():
            cause = app.join(
                args.dir_old,
                space["relay_url"],
                args.name,
                send,
                answer_for(args.confirm),
                say,
                args.scan,
            )
            if cause:
                return finish(cause)
        ref = sf.SpaceRef(**json.loads((args.dir_old / "space.json").read_text()))
        engine = sf.Engine.open(str(args.dir_old / "engine"), ref, app.key_store(args.dir_old))
        app.first_exchange(engine, send)
        n = app.recover_fork(args.dir_old, ref, engine)
        dev = app.Device(args.dir_old, engine=engine)
        try:
            status = dev.sync(send)
        finally:
            dev.close()
    print(f"recovered: {n} own changes")
    print("remove the old device ID of this device on the source with `remove`")
    print(f"status: {status}")
    return 0 if status.is_ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
