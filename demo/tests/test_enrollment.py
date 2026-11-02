"""M4 acceptance tests: device authority (DESIGN.md "Milestones", M4).

Each device is a demo CLI child process. The device that shows the
session prints its QR payload as a text line, and the test passes it to
the other device, as a user scans the code ([ENR-1] to [ENR-9]).
"""

from __future__ import annotations

import base64
import http.client
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import snailfish as sf
from conftest import (
    Relay,
    demo,
    dump,
    enroll,
    finish,
    free_port,
    read_line,
    setup,
    start,
    sync_ok,
)

from snailfish_demo.app import key_store

if TYPE_CHECKING:
    from pathlib import Path


def edit(device: Path, task: str, value: str) -> None:
    """Edit the title of a task."""
    r = demo(device, "edit", task, "title", value)
    assert r.returncode == 0, r.stderr


def b64(data: bytes) -> str:
    """Standard base64 with padding, as the protocol bodies hold it."""
    return base64.b64encode(data).decode()


def http_send(
    url: str, method: str, headers: dict[str, str], body: bytes
) -> tuple[int, bytes, list[tuple[str, str]]]:
    """Send one request with `http.client`, which follows no redirects."""
    u = urlsplit(url)
    conn = http.client.HTTPConnection(u.netloc, timeout=10)
    target = u.path + (f"?{u.query}" if u.query else "")
    conn.request(method, target, body=body or None, headers=headers)
    resp = conn.getresponse()
    out = resp.read()
    conn.close()
    return resp.status, out, resp.getheaders()


def space_of(device: Path) -> dict[str, Any]:
    """Return the space reference of a device."""
    return json.loads((device / "space.json").read_text())


def app_key_of(device: Path) -> bytes:
    """Return the app key in the key store of a device: the last 32 bytes
    of its item."""
    item = key_store(device).load(space_of(device)["log_id"])
    assert item is not None
    return item[64:]


def test_new_device_joins_and_the_relay_refuses_an_unknown_key(
    relay: Relay, tmp_path: Path
) -> None:
    """M4 demo: B joins through the text payload and a code match, and shows
    the edits of A. A request signed by a key that no grant names gets 403
    `unknown_device` (T5, [LOG-8])."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    edit(a, "t1", "buy milk")
    sync_ok(a)
    sync_ok(b)
    assert dump(b)["tasks"] == {"t1": {"title": "buy milk"}}
    assert app_key_of(b) == app_key_of(a) != bytes(32)
    edit(b, "t1", "buy oat milk")
    sync_ok(b)
    sync_ok(a)
    assert dump(a)["tasks"] == {"t1": {"title": "buy oat milk"}}

    space = sf.SpaceRef(**space_of(a))
    k = sf.new_device_keys()
    stranger_keys = key_store(tmp_path / "x")
    (tmp_path / "x").mkdir()
    stranger_keys.store(space.log_id, k.sign_seed + k.seal_seed + k.app_key)
    stranger = sf.Engine.open(str(tmp_path / "x"), space, stranger_keys)
    fetches: list[tuple[int, bytes]] = []
    sync = stranger.start_sync()
    while (req := sync.next_request()) is not None:
        headers = {h.name: h.value for h in req.headers}
        status, body, _ = http_send(req.url, req.method, headers, req.body)
        if "/entries" in req.url:
            fetches.append((status, body))
        sync.handle_response(status, [], body)
    assert fetches
    assert fetches[0][0] == 403
    assert json.loads(fetches[0][1])["error"] == "unknown_device"
    assert stranger.status() == sf.Status.RELAY_UNAVAILABLE()


def test_new_device_shows_the_code_and_the_user_confirms_at_prompts(
    relay: Relay, tmp_path: Path
) -> None:
    """Enrollment in the other direction: the new device shows the session
    and A reads it. Both devices ask the user at a prompt, and both show
    the same code ([ENR-1], [ENR-7])."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, tmp_path / "unused")
    n = start("join", "--relay", relay.url, "--name", "B", str(b))
    payload = read_line(n, "payload: ")
    assert payload.startswith(f"snailfish-enroll-v1 n {relay.url} ")
    t = start("--dir", str(a), "invite", "--scan", payload)
    codes = [read_line(p, "compare: ") for p in (t, n)]
    assert codes[0] == codes[1] and len(codes[0]) == 6 and codes[0].isdigit()
    for p in (t, n):
        assert p.stdin is not None
        p.stdin.write("y\n")
        p.stdin.flush()
    (tc, tout), (nc, nout) = finish(t), finish(n)
    assert (tc, nc) == (0, 0), tout + nout
    edit(a, "t1", "x")
    sync_ok(a)
    sync_ok(b)
    assert dump(b)["tasks"] == {"t1": {"title": "x"}}


class SubstitutingRelay:
    """A relay in front of the real relay that substitutes keys (T6).

    It shows A a new device with its own keys, and shows B a trusted device
    with its own keys and a matching commitment, so each device passes its
    checks up to the code comparison. Only the codes differ.
    """

    def __init__(self, port: int) -> None:
        """Make the substitute keys and nonces."""
        self.port = port
        self.target = 0
        self.active = False
        self.x_new = self.device(sf.new_device_keys(), "B")
        self.x_trusted = self.device(sf.new_device_keys(), "A")
        self.x_new_nonce = bytes([7]) * 32
        self.x_trusted_nonce = bytes([9]) * 32

    @staticmethod
    def device(k: sf.DeviceKeys, name: str) -> dict[str, Any]:
        """The device object of keys `k` (PROTOCOL.md 6.1)."""
        sign = sf.sign_public_key(k.sign_seed)
        seal = sf.seal_public_key(k.seal_seed)
        return {
            "id": sf.device_id(sign, seal),
            "sign": b64(sign),
            "seal": b64(seal),
            "name": name,
            "level": 1,
        }

    def rewrite(self, path: str, body: bytes) -> bytes:
        """Rewrite a session object for the device that reads it."""
        s: dict[str, Any] = json.loads(body)
        if "state" not in s:
            return body
        session = bytes.fromhex(s["session"][2:])
        new: dict[str, Any] = s["new"]
        trusted: dict[str, Any] = s["trusted"]
        if path.startswith("/v1/t/"):
            if "hello" in new:
                new["hello"] = {"device": self.x_new}
            if "nonce" in new:
                new["nonce"] = b64(self.x_new_nonce)
        else:
            if "hello" in trusted:
                n_id = new["hello"]["device"]["id"]
                c = sf.enroll_commitment(session, self.x_trusted["id"], n_id, self.x_trusted_nonce)
                keys = {"sign": self.x_trusted["sign"], "seal": self.x_trusted["seal"]}
                trusted["hello"] = {"keys": keys, "commitment": b64(c)}
            if "nonce" in trusted:
                trusted["nonce"] = b64(self.x_trusted_nonce)
        return json.dumps(s).encode()

    def forward(self, method: str, path: str, headers: dict[str, str], body: bytes) -> Answer:
        """Send a request to the real relay and rewrite the session object."""
        status, out, hs = http_send(f"http://127.0.0.1:{self.target}{path}", method, headers, body)
        if self.active and ("/enroll/" in path or path.startswith("/v1/e/")):
            out = self.rewrite(path.split("?")[0], out)
        return status, out, hs

    def serve(self) -> ThreadingHTTPServer:
        """Start the proxy on its port in a thread."""
        server = ThreadingHTTPServer(("127.0.0.1", self.port), make_handler(self))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


Answer = tuple[int, bytes, list[tuple[str, str]]]


def make_handler(mitm: SubstitutingRelay) -> type[BaseHTTPRequestHandler]:
    """The request handler class of the substituting relay."""

    class Handler(BaseHTTPRequestHandler):
        def forward(self) -> None:
            n = int(self.headers.get("content-length") or 0)
            data = self.rfile.read(n) if n else b""
            headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
            status, body, hs = mitm.forward(self.command, self.path, headers, data)
            self.send_response(status)
            for k, v in hs:
                if k.lower() not in ("content-length", "transfer-encoding", "connection", "date"):
                    self.send_header(k, v)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self.forward()

        def do_POST(self) -> None:
            self.forward()

        def do_PUT(self) -> None:
            self.forward()

    return Handler


def test_relay_that_substitutes_keys_causes_a_code_mismatch(tmp_path: Path) -> None:
    """M4 demo, T6: a relay that substitutes the keys of both devices
    passes the commitment check of each device, but the two codes differ.
    The user reports the mismatch on both devices, and A appends no grant
    (`specs/enrollment/user_blind.pv` shows why the comparison matters)."""
    port = free_port()
    mitm = SubstitutingRelay(port)
    relay = Relay(tmp_path / "relay", authority=f"localhost:{port}")
    mitm.target = relay.port
    server = mitm.serve()
    try:
        a, b = tmp_path / "a", tmp_path / "b"
        setup(relay, a, tmp_path / "unused")
        head = dump(a)["head"]
        mitm.active = True
        t = start("--dir", str(a), "invite")
        payload = read_line(t, "payload: ")
        n = start("join", "--relay", relay.url, "--scan", payload, "--name", "B", str(b))
        codes = [read_line(p, "compare: ") for p in (t, n)]
        assert codes[0] != codes[1]
        for p in (t, n):
            assert p.stdin is not None
            p.stdin.write("n\n")
            p.stdin.flush()
        (tc, tout), (nc, nout) = finish(t), finish(n)
        assert (tc, nc) == (1, 1), tout + nout
        assert "codes differ" in tout and "codes differ" in nout
        assert not (b / "space.json").exists()
        assert not (b / "keystore.json").exists()
        sync_ok(a)
        assert dump(a)["head"] == head, "no grant"
    finally:
        server.shutdown()
        relay.stop()


def test_expired_and_reused_sessions_are_refused(relay: Relay, tmp_path: Path) -> None:
    """[ENR-1]: a session works once and expires after 10 minutes. The test
    moves the expiry of the session in the relay storage to the past, which
    stands for 10 minutes that pass. Then a second device cannot reuse the
    payload of a session that ended."""
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    setup(relay, a, b)
    t = start("--dir", str(a), "invite", "--confirm", "yes")
    payload = read_line(t, "payload: ")
    db = sqlite3.connect(relay.data / "directory.db", timeout=10)
    with db:
        db.execute("UPDATE enroll_sessions SET expires = 0")
    db.close()
    n = start("join", "--relay", relay.url, "--scan", payload, "--confirm", "yes", str(c))
    (tc, tout), (nc, nout) = finish(t), finish(n)
    assert (tc, nc) == (1, 1), tout + nout
    assert "expired" in tout and "expired" in nout

    t = start("--dir", str(a), "invite", "--confirm", "yes")
    payload = read_line(t, "payload: ")
    n = start("join", "--relay", relay.url, "--scan", payload, "--confirm", "yes", str(c))
    (tc, tout), (nc, nout) = finish(t), finish(n)
    assert (tc, nc) == (0, 0), tout + nout
    d = tmp_path / "d"
    r = start("join", "--relay", relay.url, "--scan", payload, "--confirm", "yes", str(d))
    code, out = finish(r)
    assert code == 1, out
    assert "session_closed" in out, out


def test_device_with_a_lost_grant_repairs_the_log(relay: Relay, tmp_path: Path) -> None:
    """`specs/delivery/test.qnt::lateDeviceRepairTest`, [LOG-12]: B joins
    after a relay backup. After the restore, the grant of B is only in the
    lost range. B repairs the log from the position before its grant, and
    A then reads the edit of B."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, tmp_path / "unused")
    relay.backup(tmp_path / "backup")
    (tc, tout), (nc, nout) = enroll(relay, a, b)
    assert (tc, nc) == (0, 0), tout + nout
    sync_ok(b)
    edit(b, "t1", "from b")
    sync_ok(b)
    relay.restore(tmp_path / "backup")
    out = demo(b, "sync").stdout
    # setup enrolled one device before the backup, so the grant of B is
    # at position 3, and B repairs from the relay head at position 2.
    assert "repair: the relay lost positions 3 to 4" in out, out
    log = space_of(a)["log_id"]
    assert relay.admin("release-hold", "sam", log).returncode == 0
    sync_ok(a)
    assert dump(a)["tasks"] == {"t1": {"title": "from b"}}
