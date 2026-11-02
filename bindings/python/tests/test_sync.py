"""Two devices sync through the Python binding and a real relay process.

The relay is a real `snailfish-relay` process. The test sends each engine
request with `http.client`, which follows no redirects (DESIGN.md "App
integration"). A marshalling fault in a binding record fails here.
"""

from __future__ import annotations

import base64
import http.client
import os
import time
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
import snailfish as sf
from keystores import MemStore, stored
from snailfish_demo.softbrowser import SoftBrowser

if TYPE_CHECKING:
    from pathlib import Path

APP = "com.example.tasks"


class Relay:
    """The relay that `make test-python` starts, and a signed-in browser.

    `bindings/scripts/with-relay.sh` starts `snailfish-relay` on a free port
    and sets `SNAILFISH_RELAY_URL` and `SNAILFISH_INVITE`. The software
    browser of the demo registers a passkey with the invite once.
    """

    def __init__(self, browser: SoftBrowser) -> None:
        """Read the relay from the environment."""
        url = os.environ.get("SNAILFISH_RELAY_URL")
        if not url:
            pytest.fail("SNAILFISH_RELAY_URL is not set: run make test-python")
        self.url = url
        self.browser = browser

    def setup_token(self, keys: sf.DeviceKeys) -> sf.SetupToken:
        """The native sign-in of PROTOCOL.md 12.2 and 12.3 through the
        binding: the setup token and the tenant handle ([USR-4], [USR-5])."""
        si = sf.SignIn(self.url, "com.example.tasks:/callback")
        redirect = self.browser.approve(si.authorize_url(), "sam")
        req = si.token_request(redirect, keys, int(time.time()))
        status, headers, body = self.send(req.method, req.url, req.headers, req.body)
        return si.read_token(status, headers, body)

    def first_device(
        self, ka: sf.DeviceKeys, log_id: str, url: str = ""
    ) -> tuple[sf.SpaceRef, str]:
        """Sign in for device A. Returns its space and its setup token."""
        token = self.setup_token(ka)
        space = sf.SpaceRef(
            relay_url=url or self.url, tenant=token.tenant, log_id=log_id, app_id=APP
        )
        return space, token.token

    def send(
        self, method: str, url: str, headers: list[sf.Header], body: bytes
    ) -> tuple[int, list[sf.Header], bytes]:
        """Send one request and return the status, headers and body."""
        u = urlsplit(url)
        conn = http.client.HTTPConnection(u.netloc, timeout=10)
        target = u.path + (f"?{u.query}" if u.query else "")
        conn.request(
            method, target, body=body, headers={h.name: h.value for h in headers}
        )
        resp = conn.getresponse()
        out = resp.read()
        hs = [sf.Header(name=k, value=v) for k, v in resp.getheaders()]
        conn.close()
        return resp.status, hs, out


@pytest.fixture(scope="session")
def browser(tmp_path_factory: pytest.TempPathFactory) -> SoftBrowser:
    """A software browser that registered the passkey of "sam" once."""
    url = os.environ.get("SNAILFISH_RELAY_URL", "")
    invite = os.environ.get("SNAILFISH_INVITE", "")
    if not url or not invite:
        pytest.fail("SNAILFISH_INVITE is not set: run make test-python")
    b = SoftBrowser(tmp_path_factory.mktemp("browser") / "state.json", url)
    b.register(invite)
    return b


@pytest.fixture
def relay(browser: SoftBrowser) -> Relay:
    """The running relay."""
    return Relay(browser)


def exchange(relay: Relay, engine: sf.Engine) -> None:
    """Run one exchange: the loop of DESIGN.md "App integration"."""
    sync = engine.start_sync()
    while (req := sync.next_request()) is not None:
        status, headers, body = relay.send(req.method, req.url, req.headers, req.body)
        sync.handle_response(status, headers, body)


def enroll(
    relay: Relay, a: sf.Engine, kb: sf.DeviceKeys, answers: tuple[bool, bool]
) -> tuple[sf.TrustedEnrollment, sf.NewEnrollment]:
    """Run an enrollment of new keys `kb` with A: A shows the session.

    Each device answers the code comparison with its value of `answers`.
    """
    t = sf.TrustedEnrollment(a, None, None)
    assert t.payload() is None  # shown only after the open
    req = t.next_request()
    assert req is not None
    t.handle_response(*relay.send(req.method, req.url, req.headers, req.body))
    n = sf.NewEnrollment(relay.url, kb, "B", t.payload())

    def ended(s: sf.EnrollState) -> bool:
        return isinstance(s, (sf.EnrollState.DONE, sf.EnrollState.FAILED))

    for _ in range(400):
        if ended(t.state()) and ended(n.state()):
            return t, n
        if isinstance(t.state(), sf.EnrollState.COMPARE):
            t.confirm(answers[0])
        if isinstance(n.state(), sf.EnrollState.COMPARE):
            n.confirm(answers[1])
        if (req := t.next_request()) is not None:
            t.handle_response(*relay.send(req.method, req.url, req.headers, req.body))
        if (req := n.next_request()) is not None:
            status, _, body = relay.send(req.method, req.url, req.headers, req.body)
            n.handle_response(status, body)
    pytest.fail("the enrollment does not end")


def test_change_from_a_reaches_b(relay: Relay, tmp_path: Path) -> None:
    """B joins through an enrollment with A ([ENR-1] to [ENR-9]). A change by
    device A reaches device B once, and A does not get it back."""
    ka = sf.new_device_keys()
    kb = sf.new_device_keys()
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"))
    ka.app_key = setup.app_key
    space, token = relay.first_device(ka, setup.log_id)
    sa = MemStore()
    sf.install_setup(str(tmp_path / "a"), space, ka, setup.envelopes, token, sa)
    a = sf.Engine.open(str(tmp_path / "a"), space, sa)
    exchange(relay, a)
    assert a.status() == sf.Status.OK()
    t, n = enroll(relay, a, kb, (True, True))
    assert (t.state(), n.state()) == (sf.EnrollState.DONE(), sf.EnrollState.DONE())
    joined = n.joined()
    assert joined is not None and joined.position == 2
    sb = MemStore()
    sf.install_enrollment(str(tmp_path / "b"), space, kb, joined, sb)
    b = sf.Engine.open(str(tmp_path / "b"), space, sb)
    assert sb.items[setup.log_id][64:] == bytes(32)
    cid = a.new_change_id()
    result = a.enqueue_many([sf.OutboxRow(change_id=cid, change_bytes=b"rename")])
    assert (result.stored, result.refused) == ([cid], [])
    exchange(relay, a)
    assert a.outbox_len() == 0
    exchange(relay, b)
    assert b.status() == sf.Status.OK()
    assert sb.items[setup.log_id][64:] == setup.app_key

    got = b.changes_after(b.genesis_base(), 500)
    assert [(c.position, c.change_id, c.change_bytes) for c in got] == [
        (3, cid, b"rename")
    ]
    at = sf.Applied(position=got[0].position, digest=got[0].digest)
    assert b.changes_after(at, 500) == []
    bad = sf.Applied(position=at.position, digest=bytes(32))
    with pytest.raises(sf.SnailfishError.ResetRequired):
        b.changes_after(bad, 500)


def test_wrong_authority_is_paused(relay: Relay, tmp_path: Path) -> None:
    """An engine that signs another authority reports `paused: relay authority`."""
    ka = sf.new_device_keys()
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"))
    ka.app_key = setup.app_key
    url = relay.url.replace("localhost", "127.0.0.1")
    space, token = relay.first_device(ka, setup.log_id, url)
    sa = MemStore()
    sf.install_setup(str(tmp_path / "a"), space, ka, setup.envelopes, token, sa)
    a = sf.Engine.open(str(tmp_path / "a"), space, sa)
    exchange(relay, a)
    assert a.status() == sf.Status.RELAY_AUTHORITY()


def test_relay_down_is_unavailable(tmp_path: Path) -> None:
    """A connection failure is the app's error. A 503 is `relay unavailable`."""
    ka = sf.new_device_keys()
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"))
    ka.app_key = setup.app_key
    space = sf.SpaceRef(
        relay_url="https://r.example",
        tenant="t_" + "0" * 32,
        log_id=setup.log_id,
        app_id=APP,
    )
    a = sf.Engine.open(str(tmp_path / "a"), space, stored(ka, setup.log_id))
    sync = a.start_sync()
    req = sync.next_request()
    assert req is not None
    assert (req.method, req.url) == ("GET", "https://r.example/v1/info")
    sync.handle_response(503, [], b"")
    assert a.status() == sf.Status.RELAY_UNAVAILABLE()


def test_hold_and_repair_cross_the_binding(relay: Relay, tmp_path: Path) -> None:
    """A fetch with a hold gives `paused: restore hold`, and a relay log that
    ends before the verified head gives a repair session. The repair reaches
    the app through `take_repairs` (S6, [LOG-10], [LOG-14])."""
    ka = sf.new_device_keys()
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"))
    ka.app_key = setup.app_key
    space, token = relay.first_device(ka, setup.log_id)
    sa = MemStore()
    sf.install_setup(str(tmp_path / "a"), space, ka, setup.envelopes, token, sa)
    a = sf.Engine.open(str(tmp_path / "a"), space, sa)
    exchange(relay, a)
    a.enqueue_many([sf.OutboxRow(change_id=a.new_change_id(), change_bytes=b"x")])
    exchange(relay, a)
    assert a.verified_head().position == 2
    assert a.take_repairs() == []

    g = sf.parse_envelope(setup.envelopes[0].encode())
    eh = sf.entry_hash(
        g.payload_type, None, sf.record_hash(g.payload_type, g.payload, g.sig)
    )
    d1 = sf.digest_next(sf.digest0(setup.log_id), 1, eh)
    head = a.verified_head()
    sync = a.start_sync()
    req = sync.next_request()
    assert req is not None
    sync.handle_response(*relay.send(req.method, req.url, req.headers, req.body))
    req = sync.next_request()
    assert req is not None and "/entries?after=2" in req.url
    d1_text = base64.b64encode(d1).decode()
    shorter = (
        '{"entries":[],"head":{"position":1,"digest":"'
        + d1_text
        + '"},"has_more":false,"hold":true}'
    )
    sync.handle_response(200, [], shorter.encode())
    req = sync.next_request()
    assert req is not None and req.url.endswith("/repair")
    sync.handle_response(201, [], b'{"session":"' + b"ab" * 16 + b'","next":3}')
    req = sync.next_request()
    assert req is not None and req.url.endswith("/repair/finish")
    done = (
        '{"head":{"position":2,"digest":"'
        + base64.b64encode(head.digest).decode()
        + '"}}'
    )
    sync.handle_response(200, [], done.encode())
    assert a.take_repairs() == [sf.Repair(first=2, tip=2)]
    req = sync.next_request()
    assert req is not None and req.url.endswith("/status")
    sync.handle_response(200, [], b'{"hold":true}')
    assert a.status() == sf.Status.RESTORE_HOLD()


def test_code_mismatch_appends_no_grant(relay: Relay, tmp_path: Path) -> None:
    """A code mismatch on the new device ends both sides, and A appends no
    grant ([ENR-7])."""
    ka = sf.new_device_keys()
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"))
    ka.app_key = setup.app_key
    space, token = relay.first_device(ka, setup.log_id)
    sa = MemStore()
    sf.install_setup(str(tmp_path / "a"), space, ka, setup.envelopes, token, sa)
    a = sf.Engine.open(str(tmp_path / "a"), space, sa)
    exchange(relay, a)
    t, n = enroll(relay, a, sf.new_device_keys(), (True, False))
    assert isinstance(t.state(), sf.EnrollState.FAILED)
    assert isinstance(n.state(), sf.EnrollState.FAILED)
    assert n.joined() is None
    exchange(relay, a)
    assert a.verified_head().position == 1
