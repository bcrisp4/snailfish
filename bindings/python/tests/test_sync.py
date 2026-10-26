"""Two devices sync through the Python binding and a real relay process.

The relay is a real `snailfish-relay` process. The test sends each engine
request with `http.client`, which follows no redirects (DESIGN.md "App
integration"). A marshalling fault in a binding record fails here.
"""

from __future__ import annotations

import http.client
import os
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest
import snailfish as sf

if TYPE_CHECKING:
    from pathlib import Path

APP = "com.example.tasks"


class Relay:
    """The relay that `make test-python` starts, and its tenant handle.

    `bindings/scripts/with-relay.sh` starts `snailfish-relay` on a free port
    and sets `SNAILFISH_RELAY_URL` and `SNAILFISH_TENANT`.
    """

    def __init__(self) -> None:
        """Read the relay from the environment."""
        url = os.environ.get("SNAILFISH_RELAY_URL")
        tenant = os.environ.get("SNAILFISH_TENANT")
        if not url or not tenant:
            pytest.fail("SNAILFISH_RELAY_URL is not set: run make test-python")
        self.url = url
        self.tenant = tenant

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


@pytest.fixture
def relay() -> Relay:
    """The running relay."""
    return Relay()


def exchange(relay: Relay, engine: sf.Engine) -> None:
    """Run one exchange: the loop of DESIGN.md "App integration"."""
    sync = engine.start_sync()
    while (req := sync.next_request()) is not None:
        status, headers, body = relay.send(req.method, req.url, req.headers, req.body)
        sync.handle_response(status, headers, body)


def test_change_from_a_reaches_b(relay: Relay, tmp_path: Path) -> None:
    """A change by device A reaches device B once, and A does not get it back."""
    ka = sf.new_device_keys()
    kb = sf.new_device_keys()
    setup = sf.create_space(
        APP, sf.NewDevice(keys=ka, name="A"), [sf.NewDevice(keys=kb, name="B")]
    )
    ka.app_key = setup.app_key
    kb.app_key = setup.app_key
    space = sf.SpaceRef(
        relay_url=relay.url, tenant=relay.tenant, log_id=setup.log_id, app_id=APP
    )
    sf.install_setup(str(tmp_path / "a"), space, ka, setup.envelopes)
    a = sf.Engine.open(str(tmp_path / "a"), space, ka)
    b = sf.Engine.open(str(tmp_path / "b"), space, kb)

    exchange(relay, a)
    assert a.status() == sf.Status.OK()
    cid = a.new_change_id()
    result = a.enqueue_many([sf.OutboxRow(change_id=cid, change_bytes=b"rename")])
    assert (result.stored, result.refused) == ([cid], [])
    exchange(relay, a)
    assert a.outbox_len() == 0
    exchange(relay, b)
    assert b.status() == sf.Status.OK()

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
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"), [])
    ka.app_key = setup.app_key
    url = relay.url.replace("127.0.0.1", "localhost")
    space = sf.SpaceRef(
        relay_url=url, tenant=relay.tenant, log_id=setup.log_id, app_id=APP
    )
    sf.install_setup(str(tmp_path / "a"), space, ka, setup.envelopes)
    a = sf.Engine.open(str(tmp_path / "a"), space, ka)
    exchange(relay, a)
    assert a.status() == sf.Status.RELAY_AUTHORITY()


def test_relay_down_is_unavailable(tmp_path: Path) -> None:
    """A connection failure is the app's error. A 503 is `relay unavailable`."""
    ka = sf.new_device_keys()
    setup = sf.create_space(APP, sf.NewDevice(keys=ka, name="A"), [])
    ka.app_key = setup.app_key
    space = sf.SpaceRef(
        relay_url="https://r.example",
        tenant="t_" + "0" * 32,
        log_id=setup.log_id,
        app_id=APP,
    )
    a = sf.Engine.open(str(tmp_path / "a"), space, ka)
    sync = a.start_sync()
    req = sync.next_request()
    assert req is not None
    assert (req.method, req.url) == ("GET", "https://r.example/v1/info")
    sync.handle_response(503, [], b"")
    assert a.status() == sf.Status.RELAY_UNAVAILABLE()
