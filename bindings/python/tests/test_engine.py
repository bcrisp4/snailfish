"""The engine skeleton through the Python binding."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import snailfish as sf

if TYPE_CHECKING:
    from pathlib import Path


def test_second_engine_on_one_directory_is_refused(tmp_path: Path) -> None:
    first = sf.Engine.open(str(tmp_path), "https://r.example", "com.example.tasks")
    with pytest.raises(sf.SnailfishError.Locked):
        sf.Engine.open(str(tmp_path), "https://r.example", "com.example.tasks")
    del first


def test_info_exchange_sets_status(tmp_path: Path) -> None:
    engine = sf.Engine.open(str(tmp_path), "https://r.example/", "com.example.tasks")
    assert len(engine.new_change_id()) == 16
    sync = engine.start_sync()
    req = sync.next_request()
    assert req is not None
    assert (req.method, req.url) == ("GET", "https://r.example/v1/info")
    sync.handle_response(200, [], b'{"levels":[0]}')
    assert sync.next_request() is None
    assert engine.status() == sf.Status.RELAY_TOO_OLD


def test_http_error_reports_relay_unavailable(tmp_path: Path) -> None:
    engine = sf.Engine.open(str(tmp_path), "https://r.example", "com.example.tasks")
    sync = engine.start_sync()
    sync.next_request()
    sync.handle_response(503, [sf.Header(name="retry-after", value="5")], b"")
    assert engine.status() == sf.Status.RELAY_UNAVAILABLE


def test_device_id_refuses_a_short_seal_key() -> None:
    with pytest.raises(sf.SnailfishError.Invalid):
        sf.device_id(bytes(32), bytes(1215))
