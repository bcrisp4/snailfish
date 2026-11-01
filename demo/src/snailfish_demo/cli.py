"""The demo task app CLI.

Usage:
    snailfish-demo setup --relay URL --tenant T DIR_A
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

`SNAILFISH_DEMO_CRASH_AT=N` makes the process exit at the Nth crash point
of the run, with no cleanup, as a kill does. The crash points are before
and after each HTTP request, and around each app transaction. The crash
tests use them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
import snailfish as sf

from snailfish_demo import app


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
    s.add_argument("--tenant", required=True)
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
        key = app.create_space(args.relay, args.tenant, args.dir_a)
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
