"""The browser step of the native sign-in and a Python demo device, for the
Swift app tests.

The iOS simulator cannot make a passkey without an iCloud account, so the
app tests cannot sign in on the relay page. This service does the browser
step with the software browser of the demo (`softbrowser.py`): it
registers a passkey with the invite link at start, and for each request
`GET /approve?url=<authorize URL>` it signs in, allows the request, and
answers with the redirect URL as text.

The Swift code then runs the rest of the sign-in on the real relay: the
redirect, the PKCE code exchange and the setup token. The Chromium test
(`demo/tests/test_browser.py`) checks the relay page itself.

The `/py/` requests drive one device of the Python demo (`app.py`), so a
Swift test can share a space with it. The two apps write the change bytes
with different JSON encoders, so only a shared space shows that each app
reads the changes of the other:

- `POST /py/setup`: create a space with a new demo device.
- `POST /py/edit?task=T&field=F&value=JSON`: one edit.
- `POST /py/sync`: one sync. The answer is `ok`, or the status.
- `GET /py/tasks`: the tasks as JSON.
- `POST /py/invite`: start an enrollment that shows the session. The
  answer is the QR payload.
- `POST /py/compare?code=C`: give the 6-digit code of the new device. The
  answer is the code of the demo device, after the demo device shows it.
  The demo device confirms only if the two codes match ([ENR-7]).
- `GET /py/invite/result`: wait for the enrollment. The answer is empty on
  success, or the cause of the failure.
- `POST /py/user`: make a new relay user with its own tenant, register its
  passkey, and sign in as that user from now on. A tenant holds one space of
  the app (PROTOCOL.md 13.4), so each test that makes a space starts here.
  It needs `SNAILFISH_RELAY_ADMIN` of `with-relay.sh`.
- `GET /py/recovery-key`: the recovery key of the space of `setup`.
- `GET /py/devices`: the active devices as JSON: `[[id, name, this], ...]`.
- `POST /py/remove?ids=A,B`: remove the devices, with the list of the devices
  that stay confirmed (S4, PROTOCOL.md 13.2). The answer is the status.
- `POST /py/recover?key=K`: recover the space onto a new demo device with
  the recovery key (S5, PROTOCOL.md 13.4). The new device replaces the
  device of `setup`.

Usage: approver.py RELAY_URL INVITE_LINK USER PORT_FILE

The service listens on a free loopback port and writes the port to
PORT_FILE.
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import snailfish as sf

from snailfish_demo import app
from snailfish_demo.cli import SOFT_REDIRECT, Crasher, http_transport
from snailfish_demo.softbrowser import RelayError, SoftBrowser

# Each wait of a `/py/` request ends after this time, so a fault in a test
# fails the test and does not stop the run.
WAIT_SECONDS = 60


class PyDevice:
    """One demo device and its enrollment, for the `/py/` requests."""

    def __init__(self, relay_url: str, browser: SoftBrowser, user: str) -> None:
        """Use the relay at `relay_url`. Sign in as `user` with `browser`."""
        self.relay_url = relay_url
        self.browser = browser
        self.user = user
        self.send = http_transport(httpx.Client(timeout=30), Crasher())
        self.dev: app.Device | None = None
        self.recovery_key = ""
        self.enrollment: threading.Thread | None = None
        self.payload: queue.Queue[str] = queue.Queue()
        self.own_code: queue.Queue[str] = queue.Queue()
        self.other_code: queue.Queue[str] = queue.Queue()
        self.cause = ""

    def device(self) -> app.Device:
        """Return the device. `setup` must come first."""
        if self.dev is None:
            raise KeyError("no demo device: send POST /py/setup first")
        return self.dev

    def setup(self) -> str:
        """Create a space with a new device in a new directory."""
        d = Path(tempfile.mkdtemp()) / "py"
        self.recovery_key = app.create_space(
            self.relay_url,
            d,
            SOFT_REDIRECT,
            lambda authorize_url: self.browser.approve(authorize_url, self.user),
            self.send,
        )
        self.dev = app.Device(d)
        return ""

    def new_user(self) -> str:
        """Make a new relay user, register its passkey, and use it."""
        name = "u" + secrets.token_hex(4)
        admin = shlex.split(os.environ["SNAILFISH_RELAY_ADMIN"])
        link = subprocess.run(
            [*admin, "user", "add", name], capture_output=True, text=True, check=True, timeout=60
        ).stdout.strip()
        browser = SoftBrowser(Path(tempfile.mkdtemp()) / "browser.json", self.relay_url)
        browser.register(link)
        self.browser, self.user = browser, name
        return name

    def devices(self) -> str:
        """The active devices of the space as JSON."""
        return json.dumps(
            [[d.id, d.name, d.this_device] for d in self.device().engine.active_devices()]
        )

    def remove(self, ids: list[str]) -> str:
        """Remove `ids` with the list of the devices that stay confirmed."""
        status = app.remove(self.device(), ids, self.send, lambda _stay: True)
        return "ok" if status.is_ok() else str(status)

    def recover(self, key: str) -> str:
        """Recover the space onto a new demo device."""
        d = Path(tempfile.mkdtemp()) / "py-recovered"
        self.dev = app.recover(
            self.relay_url,
            d,
            "P",
            key,
            SOFT_REDIRECT,
            lambda authorize_url: self.browser.approve(authorize_url, self.user),
            self.send,
        )
        return ""

    def invite(self) -> str:
        """Start an enrollment in a thread, and return its QR payload."""
        dev = self.device()
        # New queues, so values of an earlier enrollment cannot feed this one.
        self.payload = queue.Queue()
        self.own_code = queue.Queue()
        self.other_code = queue.Queue()

        def answer(code: str) -> bool:
            self.own_code.put(code)
            return self.other_code.get(timeout=WAIT_SECONDS) == code

        def say(line: str) -> None:
            if line.startswith("payload: "):
                self.payload.put(line.removeprefix("payload: "))

        def run() -> None:
            self.cause = app.invite(dev, self.send, answer, say)

        # An exception in the thread leaves this cause, and the log of the
        # service holds the traceback.
        self.cause = "the enrollment stopped with an exception"
        self.enrollment = threading.Thread(target=run, daemon=True)
        self.enrollment.start()
        return self.payload.get(timeout=WAIT_SECONDS)

    def compare(self, code: str) -> str:
        """Give the code of the new device, and return the own code."""
        self.other_code.put(code)
        return self.own_code.get(timeout=WAIT_SECONDS)

    def result(self) -> str:
        """Wait for the enrollment, and return its cause."""
        if self.enrollment is not None:
            self.enrollment.join(WAIT_SECONDS)
            if self.enrollment.is_alive():
                return "the enrollment did not end"
        return self.cause


def main() -> None:
    """Register the passkey, then serve until the process ends."""
    relay_url, invite, user, port_file = sys.argv[1:5]
    state = Path(tempfile.mkdtemp()) / "browser.json"
    browser = SoftBrowser(state, relay_url)
    browser.register(invite)
    py = PyDevice(relay_url, browser, user)

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def route(self, method: str) -> None:
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if method == "GET" and u.path == "/approve" and "url" in q:
                    body = py.browser.approve(q["url"], py.user)
                elif method == "POST" and u.path == "/py/user":
                    body = py.new_user()
                elif method == "GET" and u.path == "/py/recovery-key":
                    body = py.recovery_key
                elif method == "GET" and u.path == "/py/devices":
                    body = py.devices()
                elif method == "POST" and u.path == "/py/remove":
                    body = py.remove(q["ids"].split(","))
                elif method == "POST" and u.path == "/py/recover":
                    py.recover(q["key"])
                    body = ""
                elif method == "POST" and u.path == "/py/setup":
                    body = py.setup()
                elif method == "POST" and u.path == "/py/edit":
                    py.device().edit(q["task"], q["field"], json.loads(q["value"]))
                    body = ""
                elif method == "POST" and u.path == "/py/sync":
                    status = py.device().sync(py.send)
                    body = "ok" if status.is_ok() else str(status)
                elif method == "GET" and u.path == "/py/tasks":
                    body = json.dumps(py.device().tasks())
                elif method == "POST" and u.path == "/py/invite":
                    body = py.invite()
                elif method == "POST" and u.path == "/py/compare":
                    body = py.compare(q["code"])
                elif method == "GET" and u.path == "/py/invite/result":
                    body = py.result()
                else:
                    self.send_error(404)
                    return
            except (
                RelayError,
                OSError,
                KeyError,
                ValueError,
                queue.Empty,
                app.RecoveryError,
                sf.SnailfishError,
                subprocess.CalledProcessError,
            ) as e:
                self.reply(502, f"{type(e).__name__}: {e}".encode())
                return
            self.reply(200, body.encode())

        def do_GET(self) -> None:
            self.route("GET")

        def do_POST(self) -> None:
            self.route("POST")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Path(port_file).write_text(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
