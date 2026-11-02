"""The M5 acceptance tests: user sign-in, the user page, tenant isolation,
quotas and webhooks, against a relay process (DESIGN.md "Milestones" M5).

Each user signs in with a software passkey in a software browser
(`snailfish_demo.softbrowser`), so the relay runs its real WebAuthn,
session, Origin and anti-CSRF checks.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

import pytest
from conftest import Relay, create, demo, dump, free_port, setup, sync_ok

from snailfish_demo.softbrowser import RelayError, SoftBrowser

if TYPE_CHECKING:
    from pathlib import Path


def browser(relay: Relay, state: Path | None = None) -> SoftBrowser:
    """The software browser of a user."""
    return SoftBrowser(state or relay.browser, relay.url)


def test_first_device_gets_its_tenant_through_the_handoff(relay: Relay, tmp_path: Path) -> None:
    """S1, [USR-3] to [USR-6]: the first device signs in, gets its tenant
    handle and setup token from the handoff, and creates the space. The
    `user add` output holds only the invite link, no tenant handle."""
    out = relay.admin("user", "add", "kim").stdout.strip()
    assert out.startswith(f"{relay.url}/u/invite#it_"), out
    assert re.search(r"\bt_[0-9a-f]{32}", out) is None
    a = tmp_path / "a"
    create(relay, a)
    sync_ok(a)
    space = json.loads((a / "space.json").read_text())
    assert space["tenant"].startswith("t_")
    page = browser(relay).page()
    assert dump(a)["log_id"] in page


def test_second_user_cannot_reach_the_first_tenant(relay: Relay, tmp_path: Path) -> None:
    """M5 demo, [USR-3], `specs/signin/no_tenant_check.pv`: a second user on
    the same relay cannot read, write or list the tenant of the first user,
    through the user page or the device routes."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    sam_log = dump(a)["log_id"]
    sam_tenant = json.loads((a / "space.json").read_text())["tenant"]
    kim = relay.add_user("kim")
    k = tmp_path / "k"
    create(relay, k, browser=kim, user="kim")
    sync_ok(k)
    kim_page = browser(relay, kim).page()
    assert "Signed in as <b>kim</b>" in kim_page
    assert sam_log not in kim_page, "kim lists the space of sam"
    assert sam_tenant not in kim_page
    # A device with the keys of kim names the tenant and the space of sam:
    # it is not active there, so the relay refuses each read and write.
    space = json.loads((k / "space.json").read_text())
    kim_item = json.loads((k / "keystore.json").read_text())[space["log_id"]]
    space["tenant"] = sam_tenant
    space["log_id"] = sam_log
    x = tmp_path / "x"
    x.mkdir()
    (x / "space.json").write_text(json.dumps(space))
    (x / "keystore.json").write_text(json.dumps({sam_log: kim_item}))
    assert demo(x, "edit", "t9", "title", "intruder").returncode == 0
    r = demo(x, "sync")
    assert r.returncode != 0
    assert "RELAY_UNAVAILABLE" in r.stdout.upper().replace(" ", "_"), r.stdout
    # Sam's space is unchanged and still syncs.
    sync_ok(a)
    sync_ok(b)
    assert dump(a)["head"] == dump(b)["head"]
    assert "t9" not in dump(b)["tasks"]


def test_invite_link_works_once_and_expires(relay: Relay, tmp_path: Path) -> None:
    """[USR-1]: an invite link works once. The relay refuses it after it
    expires. The test moves the expiry into the past in `directory.db`, in
    place of a wait of 7 days."""
    link = relay.admin("user", "add", "kim").stdout.strip()
    first = SoftBrowser(tmp_path / "k1.json", relay.url)
    first.register(link)
    with pytest.raises(RelayError) as e:
        SoftBrowser(tmp_path / "k2.json", relay.url).register(link)
    assert (e.value.status, e.value.code) == (403, "bad_invite")
    link = relay.admin("user", "invite", "kim").stdout.strip()
    db = sqlite3.connect(relay.data / "directory.db")
    with db:
        db.execute("UPDATE invites SET expires = ?", (int(time.time()) - 1,))
    db.close()
    with pytest.raises(RelayError) as e:
        SoftBrowser(tmp_path / "k3.json", relay.url).register(link)
    assert (e.value.status, e.value.code) == (403, "bad_invite")
    # The new link removed the old passkey of kim ([USR-2]).
    with pytest.raises(RelayError) as e:
        first.sign_in("kim")
    assert e.value.code == "bad_passkey"


def test_full_quota_pauses_sync_and_serves_stored_changes(relay: Relay, tmp_path: Path) -> None:
    """S7, `specs/quota/test.qnt::fullQuotaKeepsOutboxTest` and
    `raiseStoresQueuedTest` ([QTA-1] to [QTA-4]): at a full quota the relay
    refuses new changes and serves the stored changes. A reports
    `paused: quota` and keeps its edit. After a larger quota, A syncs it."""
    a, b = tmp_path / "a", tmp_path / "b"
    setup(relay, a, b)
    assert demo(a, "edit", "t1", "title", "first").returncode == 0
    sync_ok(a)
    assert relay.admin("quota", "sam", "--space-bytes", "1").returncode == 0
    assert demo(a, "edit", "t2", "title", "second").returncode == 0
    r = demo(a, "sync")
    assert r.returncode != 0
    assert "QUOTA" in r.stdout.upper(), r.stdout
    assert dump(a)["engine_outbox"] == 1
    # B still gets the stored change.
    sync_ok(b)
    assert "t1" in dump(b)["tasks"]
    assert "t2" not in dump(b)["tasks"]
    # The user page shows the usage at its limit and the device status.
    page = browser(relay).page()
    assert 'class="warn"' in page
    assert "paused: quota" in page
    assert relay.admin("quota", "sam").returncode == 0
    sync_ok(a)
    assert dump(a)["engine_outbox"] == 0
    sync_ok(b)
    assert "t2" in dump(b)["tasks"]


# The bodies that the webhook receiver got.
GOT: list[bytes] = []


class Hook(BaseHTTPRequestHandler):
    """A webhook receiver that keeps each body in GOT."""

    def do_POST(self) -> None:
        n = int(self.headers.get("content-length") or 0)
        GOT.append(self.rfile.read(n))
        self.send_response(200)
        self.end_headers()


def test_webhook_needs_an_allowed_host_and_a_public_address(relay: Relay) -> None:
    """[USR-8]: the relay refuses a webhook to a host outside the allowlist,
    and to a host that resolves to a private address. A loopback address
    that the allowlist names gets the test message."""
    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        relay.stop()
        relay.serve_args = ["--webhook-hosts", "localhost"]
        relay.start()
        br = browser(relay)
        for url in ["http://example.com/h", f"http://localhost:{port}/h"]:
            with pytest.raises(RelayError) as e:
                br.form("/u/webhook", [("url", url)])
            assert (e.value.status, e.value.code) == (400, "bad_webhook"), url
        # The allowlist names the loopback address, so the relay sends.
        relay.stop()
        relay.serve_args = ["--webhook-hosts", "127.0.0.1"]
        relay.start()
        status, _, _ = br.form("/u/webhook", [("url", f"http://127.0.0.1:{port}/hook")])
        assert status == 303
        br.form("/u/webhook/test", [])
        deadline = time.monotonic() + 15
        while not GOT and time.monotonic() < deadline:
            time.sleep(0.1)
        assert GOT, "no webhook message"
        assert json.loads(GOT[0]) == {"text": "Snailfish: a test message from the user page."}
        assert "HTTP 200" in br.page()
    finally:
        server.shutdown()


def test_user_write_needs_origin_and_csrf(relay: Relay) -> None:
    """T4, [USR-7]: the relay refuses a user write with a wrong Origin or
    with no anti-CSRF token, and a device route with the session cookie."""
    br = browser(relay)
    csrf = br.csrf()
    assert csrf
    body = f"name=phone&csrf={csrf}".encode()
    form = {"content-type": "application/x-www-form-urlencoded"}
    status, _, out = br.request(
        "POST", "/u/groups", body, {**form, "origin": "http://evil.example"}
    )
    assert (status, json.loads(out)["error"]) == (403, "bad_origin")
    status, _, out = br.request("POST", "/u/groups", b"name=phone", {**form, "origin": br.origin})
    assert (status, json.loads(out)["error"]) == (403, "bad_csrf")
    assert "phone" not in br.page()
    status, _, _ = br.request("POST", "/u/groups", body, {**form, "origin": br.origin})
    assert status == 303
    assert "phone" in br.page()
    status, _, out = br.request("GET", "/v1/info")
    assert (status, json.loads(out)["error"]) == (400, "bad_request")
