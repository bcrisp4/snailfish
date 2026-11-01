"""The engine through the Python binding, with no relay."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import snailfish as sf

if TYPE_CHECKING:
    from pathlib import Path


def space(log_id: str) -> sf.SpaceRef:
    """A space reference on a relay that the test never calls."""
    return sf.SpaceRef(
        relay_url="https://r.example/",
        tenant="t_" + "0" * 32,
        log_id=log_id,
        app_id="com.example.tasks",
    )


def test_second_engine_on_one_directory_is_refused(tmp_path: Path) -> None:
    keys = sf.new_device_keys()
    sp = space("l_" + "1" * 32)
    first = sf.Engine.open(str(tmp_path), sp, keys)
    with pytest.raises(sf.SnailfishError.Locked):
        sf.Engine.open(str(tmp_path), sp, keys)
    del first


def test_enqueue_refuses_other_bytes_for_a_known_change_id(tmp_path: Path) -> None:
    keys = sf.new_device_keys()
    keys.app_key = bytes(range(32))
    engine = sf.Engine.open(str(tmp_path), space("l_" + "1" * 32), keys)
    cid = engine.new_change_id()
    assert len(cid) == 16
    row = sf.OutboxRow(change_id=cid, change_bytes=b"x")
    assert engine.enqueue_many([row]).stored == [cid]
    assert engine.enqueue_many([row]).stored == []
    other = sf.OutboxRow(change_id=cid, change_bytes=b"y")
    assert engine.enqueue_many([other]).refused == [cid]
    assert engine.outbox_len() == 1


def test_enqueue_without_an_app_key_is_invalid(tmp_path: Path) -> None:
    """A new device has no app key until its enrollment check passes, so the
    engine cannot encrypt a change yet."""
    engine = sf.Engine.open(str(tmp_path), space("l_" + "1" * 32), sf.new_device_keys())
    assert engine.app_key() is None
    row = sf.OutboxRow(change_id=engine.new_change_id(), change_bytes=b"x")
    with pytest.raises(sf.SnailfishError.Invalid):
        engine.enqueue_many([row])


def test_info_with_old_levels_is_relay_too_old(tmp_path: Path) -> None:
    engine = sf.Engine.open(str(tmp_path), space("l_" + "1" * 32), sf.new_device_keys())
    sync = engine.start_sync()
    req = sync.next_request()
    assert req is not None
    assert (req.method, req.url) == ("GET", "https://r.example/v1/info")
    sync.handle_response(200, [], b'{"levels":[0],"limits":{}}')
    assert sync.next_request() is None
    assert engine.status() == sf.Status.RELAY_TOO_OLD()


def test_short_key_is_invalid(tmp_path: Path) -> None:
    keys = sf.new_device_keys()
    keys.app_key = bytes(31)
    with pytest.raises(sf.SnailfishError.Invalid):
        sf.Engine.open(str(tmp_path), space("l_" + "1" * 32), keys)


def test_device_id_refuses_a_short_seal_key() -> None:
    with pytest.raises(sf.SnailfishError.Invalid):
        sf.device_id(bytes(32), bytes(1215))
