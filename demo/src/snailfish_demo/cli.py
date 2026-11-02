"""The demo task app CLI.

Usage:
    snailfish-demo setup --relay URL [--browser STATE --user NAME] DIR_A
    snailfish-demo --dir DIR invite [--scan TEXT] [--recovery-key KEY] [--confirm ask|yes|no]
    snailfish-demo join --relay URL [--scan TEXT] [--name NAME] [--confirm ask|yes|no] DIR
    snailfish-demo --dir DIR edit TASK FIELD VALUE
    snailfish-demo --dir DIR sync
    snailfish-demo --dir DIR list

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
    sub.add_parser("sync")
    sub.add_parser("list")
    sub.add_parser("dump")
    args = p.parse_args(argv)

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
                    },
                    sort_keys=True,
                )
            )
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
