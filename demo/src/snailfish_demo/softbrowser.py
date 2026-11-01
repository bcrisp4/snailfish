"""A software browser with a software passkey, for tests with no person.

It does what a browser and a platform authenticator do on the user page of
the relay (PROTOCOL.md 12): it registers a passkey with an invite link,
signs in, keeps the session cookie, sends the Origin header and the
anti-CSRF token, and approves a native sign-in. The passkey is ES256 with
attestation "none", user presence and user verification, so the relay runs
its real WebAuthn checks.

The state file holds the private key of the passkey. It is for tests only.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qsl, quote, urlsplit

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

if TYPE_CHECKING:
    from pathlib import Path


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class RelayError(Exception):
    """The relay refused a request of the user page."""

    def __init__(self, status: int, code: str) -> None:
        """Keep the HTTP status and the error code."""
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class SoftBrowser:
    """A browser for one relay, with its state in a JSON file."""

    def __init__(self, path: Path, relay_url: str, connect: str | None = None) -> None:
        """Open the state file, or start with no passkey. `connect` is the
        address to connect to, if it is not the authority of `relay_url`,
        for example the relay behind a test proxy."""
        self.path = path
        self.origin = relay_url.rstrip("/")
        u = urlsplit(self.origin)
        self.netloc = connect or u.netloc
        self.rp_id = u.hostname or ""
        self.state: dict[str, Any] = json.loads(path.read_text()) if path.exists() else {}

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(self.state))
        tmp.replace(self.path)

    def request(
        self, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        """Send one request with the cookie of the session, if any."""
        h = dict(headers or {})
        if self.state.get("cookie"):
            h["cookie"] = f"sf_session={self.state['cookie']}"
        conn = http.client.HTTPConnection(self.netloc, timeout=10)
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        out = resp.read()
        rh = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        cookie = rh.get("set-cookie")
        if cookie is not None:
            value = cookie.split(";")[0].removeprefix("sf_session=")
            self.state["cookie"] = value or None
            self._save()
        return resp.status, rh, out

    def _post(
        self, path: str, body: bytes, content_type: str, csrf: str | None
    ) -> tuple[int, dict[str, str], bytes]:
        h = {"origin": self.origin, "content-type": content_type}
        if csrf:
            h["snailfish-csrf"] = csrf
        status, rh, out = self.request("POST", path, body, h)
        if status >= 400:
            code = json.loads(out).get("error", "") if out.startswith(b"{") else ""
            raise RelayError(status, code)
        return status, rh, out

    def json(self, path: str, body: dict[str, Any], csrf: str | None = None) -> dict[str, Any]:
        """POST a JSON body under the write rules of 12.4."""
        _, _, out = self._post(path, json.dumps(body).encode(), "application/json", csrf)
        return cast("dict[str, Any]", json.loads(out))

    def form(self, path: str, fields: list[tuple[str, str]]) -> tuple[int, dict[str, str], bytes]:
        """POST a form with the anti-CSRF token of the session."""
        csrf = self.csrf()
        body = "&".join(f"{k}={quote(v, safe='')}" for k, v in [*fields, ("csrf", csrf or "")])
        return self._post(path, body.encode(), "application/x-www-form-urlencoded", None)

    def page(self) -> str:
        """The user page, or the sign-in page without a session."""
        _, _, out = self.request("GET", "/u/")
        return out.decode()

    def csrf(self) -> str | None:
        """The anti-CSRF token of the session, from the user page."""
        m = re.search(r'name="csrf" content="([0-9a-f]{64})"', self.page())
        return m.group(1) if m else None

    # ------------------------------------------------------------ passkey

    def _key(self) -> ec.EllipticCurvePrivateKey:
        pem = self.state["key"].encode()
        return cast("ec.EllipticCurvePrivateKey", serialization.load_pem_private_key(pem, None))

    def _client_data(self, kind: str, challenge: str) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": False}
        ).encode()

    def register(self, invite_link: str) -> None:
        """Register a new passkey with an invite link, and keep the session."""
        token = invite_link.rsplit("#", 1)[1]
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(16)
        self.state["key"] = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        self.state["cred_id"] = _b64(cred_id)
        self.state["counter"] = 0
        start = self.json("/u/invite/start", {"token": token})
        challenge = start["options"]["publicKey"]["challenge"]
        nums = key.public_key().public_numbers()
        cose = cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )
        auth = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([0x45])
            + (0).to_bytes(4, "big")
            + bytes(16)
            + len(cred_id).to_bytes(2, "big")
            + cred_id
            + cose
        )
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        cd = self._client_data("webauthn.create", challenge)
        cred = {
            "id": _b64(cred_id),
            "rawId": _b64(cred_id),
            "type": "public-key",
            "response": {"attestationObject": _b64(att), "clientDataJSON": _b64(cd)},
            "extensions": {},
        }
        self.json("/u/invite/finish", {"ceremony": start["ceremony"], "credential": cred})
        self._save()

    def sign_in(self, name: str) -> None:
        """Sign in with the passkey."""
        start = self.json("/u/signin/start", {"name": name})
        challenge = start["options"]["publicKey"]["challenge"]
        self.state["counter"] = int(self.state["counter"]) + 1
        auth = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([0x05])
            + int(self.state["counter"]).to_bytes(4, "big")
        )
        cd = self._client_data("webauthn.get", challenge)
        sig = self._key().sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        cred = {
            "id": self.state["cred_id"],
            "rawId": self.state["cred_id"],
            "type": "public-key",
            "response": {
                "authenticatorData": _b64(auth),
                "clientDataJSON": _b64(cd),
                "signature": _b64(sig),
                "userHandle": None,
            },
            "extensions": {},
        }
        self.json("/u/signin/finish", {"ceremony": start["ceremony"], "credential": cred})
        self._save()

    def approve(self, authorize_url: str, name: str) -> str:
        """Approve a native sign-in as the user does (12.2). Signs in first
        if the session ended. Returns the URL of the redirect."""
        if self.csrf() is None:
            self.sign_in(name)
        query = urlsplit(authorize_url).query
        fields = parse_qsl(query, keep_blank_values=True)
        _, rh, _ = self.form("/u/authorize", fields)
        return rh["location"]
