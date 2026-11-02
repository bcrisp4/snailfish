"""Host key stores for the tests (DESIGN.md "App integration")."""

from __future__ import annotations

import snailfish as sf


class MemStore(sf.KeyStore):
    """A host key store in memory. With `fail`, each call raises, as the
    keychain does without its entitlement (C62)."""

    def __init__(self, *, fail: bool = False) -> None:
        """Start empty."""
        self.items: dict[str, bytes] = {}
        self.fail = fail

    def load(self, account: str) -> bytes | None:
        """Return the item, or None."""
        if self.fail:
            raise sf.KeyStoreError.Failed("errSecMissingEntitlement")
        return self.items.get(account)

    def store(self, account: str, secret: bytes) -> None:
        """Replace the item."""
        if self.fail:
            raise sf.KeyStoreError.Failed("errSecMissingEntitlement")
        self.items[account] = secret


def stored(keys: sf.DeviceKeys, log_id: str) -> MemStore:
    """A key store that holds `keys` for the space `log_id`, in the item
    form of the engine: the two seeds and the app key."""
    s = MemStore()
    s.items[log_id] = keys.sign_seed + keys.seal_seed + keys.app_key
    return s
