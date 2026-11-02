"""The browser step of the native sign-in, for the Swift app tests.

The iOS simulator cannot make a passkey without an iCloud account, so the
app tests cannot sign in on the relay page. This service does the browser
step with the software browser of the demo (`softbrowser.py`): it
registers a passkey with the invite link at start, and for each request
`GET /approve?url=<authorize URL>` it signs in, allows the request, and
answers with the redirect URL as text.

The Swift code then runs the rest of the sign-in on the real relay: the
redirect, the PKCE code exchange and the setup token. The Chromium test
(`demo/tests/test_browser.py`) checks the relay page itself.

Usage: approver.py RELAY_URL INVITE_LINK USER PORT_FILE

The service listens on a free loopback port and writes the port to
PORT_FILE.
"""

from __future__ import annotations

import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from snailfish_demo.softbrowser import RelayError, SoftBrowser


def main() -> None:
    """Register the passkey, then serve until the process ends."""
    relay_url, invite, user, port_file = sys.argv[1:5]
    state = Path(tempfile.mkdtemp()) / "browser.json"
    browser = SoftBrowser(state, relay_url)
    browser.register(invite)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            u = urlsplit(self.path)
            urls = parse_qs(u.query).get("url", [])
            if u.path != "/approve" or len(urls) != 1:
                self.send_error(404)
                return
            try:
                body = browser.approve(urls[0], user).encode()
                status = 200
            except (RelayError, OSError, KeyError) as e:
                body = f"{type(e).__name__}: {e}".encode()
                status = 502
            self.send_response(status)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            sys.stderr.write(fmt % args + "\n")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    Path(port_file).write_text(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
