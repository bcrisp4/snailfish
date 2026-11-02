"""The user page in a real browser: Chromium through Playwright, with a
virtual WebAuthn authenticator from the Chrome DevTools Protocol.

The software browser of the other tests (`softbrowser.py`) imitates a
browser. This test runs the page script `/u/app.js` and the real browser
rules: the `Origin` header of a form POST, the cookie, the CSP, and the
redirect of the native approval (PROTOCOL.md 12.2 and 12.4).

`uv.lock` pins Playwright, and Playwright pins its Chromium build. `make
test-demo` and `make test-browser` install that build into the user cache
(`uv run playwright install chromium`).

To debug a failure:

- Launch with `headless=False` to watch the page.
- Read `chrome.errors`: a CSP refusal shows there, not as an HTTP error.
- Use `page.expect_response` to see the status of a form POST.
- Do not use `page.wait_for_function`: the page CSP blocks string eval.
- Click buttons with `button:has-text(...)`. `text=Allow` also matches the
  page heading.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from conftest import Relay, sync_ok
from playwright.sync_api import Error, Page, sync_playwright

from snailfish_demo import app, cli

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

# A platform authenticator with user verification, as Touch ID or Windows
# Hello. Presence is automatic, so no person taps it.
AUTHENTICATOR = {
    "protocol": "ctap2",
    "transport": "internal",
    "hasResidentKey": True,
    "hasUserVerification": True,
    "isUserVerified": True,
    "automaticPresenceSimulation": True,
}


class _Cdp(Protocol):
    """A DevTools session, with typed answers."""

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send one DevTools command."""
        ...


class Chrome:
    """One page of Chromium with a virtual authenticator, and its errors."""

    def __init__(self, page: Page) -> None:
        """Attach the console and the DevTools session to `page`."""
        self.page = page
        self.errors: list[str] = []
        page.on("console", lambda m: self.errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: self.errors.append(str(e)))
        # Playwright types the DevTools answers as plain dicts.
        self.cdp = cast("_Cdp", page.context.new_cdp_session(page)).send
        self.cdp("WebAuthn.enable")
        self.auth = self.new_authenticator()

    def new_authenticator(self) -> str:
        """Remove the current virtual authenticator, if any, add a new one,
        and return its ID, as a user who moves to a second device."""
        if getattr(self, "auth", None):
            self.cdp("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": self.auth})
        r = self.cdp("WebAuthn.addVirtualAuthenticator", {"options": AUTHENTICATOR})
        return str(r["authenticatorId"])

    def passkeys(self) -> int:
        """The number of passkeys that the current authenticator holds."""
        r = self.cdp("WebAuthn.getCredentials", {"authenticatorId": self.auth})
        return len(r["credentials"])

    def sign_in(self, name: str) -> None:
        """Sign out if signed in, then sign in with the passkey."""
        if self.page.locator("text=Sign out").count():
            self.page.click("text=Sign out")
        self.page.fill("#signin input[name=name]", name)
        self.page.click("text=Sign in with a passkey")
        self.page.wait_for_selector("text=Signed in as", timeout=10_000)
        # The script binds its handlers at DOMContentLoaded.
        self.page.wait_for_load_state("load")


@pytest.fixture
def chrome() -> Iterator[Chrome]:
    """A headless Chromium page with a virtual authenticator."""
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
        except Error as e:
            pytest.fail(f"run `uv run playwright install chromium` in demo/: {e}")
        yield Chrome(browser.new_context().new_page())
        browser.close()


class _Catch(BaseHTTPRequestHandler):
    """The loopback listener of an app (RFC 8252 section 7.3)."""

    got: list[str]

    def do_GET(self) -> None:
        self.got.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def test_user_page_works_in_chrome(relay: Relay, chrome: Chrome, tmp_path: Path) -> None:
    """[USR-1], [USR-4] to [USR-7] in Chrome: an invite registers a passkey,
    a form write passes the Origin and anti-CSRF rules, the passkey signs in,
    a second authenticator adds a passkey, and the native approval redirects
    to the app, whose engine creates the space."""
    page = chrome.page
    link = relay.admin("user", "invite", "sam").stdout.strip()
    page.goto(link)
    page.click("#invite")
    page.wait_for_url(f"{relay.url}/u/", timeout=10_000)
    page.wait_for_selector("text=Signed in as", timeout=10_000)
    assert chrome.passkeys() == 1
    page.wait_for_load_state("load")

    # A form POST. Under `Referrer-Policy: no-referrer`, Chrome sends
    # `Origin: null` here and the relay answers `bad_origin`.
    page.fill("input[name=name]", "phone")
    with page.expect_response("**/u/groups") as resp:
        page.click("text=New group")
    assert resp.value.status == 303
    page.wait_for_selector("h3:has-text('phone')", timeout=5_000)

    chrome.sign_in("sam")

    # The options exclude the passkey of this authenticator, so Chrome
    # refuses a second one on it. A second authenticator adds one.
    page.click("#addkey")
    page.wait_for_selector("#msg:has-text('already registered')", timeout=10_000)
    chrome.auth = chrome.new_authenticator()
    page.click("#addkey")
    page.locator("li:has-text('added')").nth(1).wait_for(timeout=10_000)
    assert chrome.passkeys() == 1
    chrome.sign_in("sam")

    # The native approval. Chrome checks the CSP `form-action` also on the
    # redirect after the Allow POST.
    got: list[str] = []
    handler = type("Catch", (_Catch,), {"got": got})
    lb = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=lb.serve_forever, daemon=True).start()
    redirect = f"http://127.0.0.1:{lb.server_port}/cb"

    def approve(authorize_url: str) -> str:
        page.goto(authorize_url)
        page.click("button:has-text('Allow')")
        page.wait_for_url(f"{redirect}?**", timeout=10_000)
        return f"http://127.0.0.1:{lb.server_port}{next(g for g in got if g.startswith('/cb?'))}"

    a = tmp_path / "a"
    try:
        with httpx.Client(timeout=30) as client:
            send = cli.http_transport(client, cli.Crasher())
            app.create_space(relay.url, a, redirect, approve, send)
    finally:
        lb.shutdown()
    query = parse_qs(urlsplit(next(g for g in got if g.startswith("/cb?"))).query)
    assert query["code"][0].startswith("ac_")
    sync_ok(a)
    page.goto(f"{relay.url}/u/")
    assert app.APP_ID in page.content()
    assert chrome.errors == [], chrome.errors
