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
    assert engine.status() == sf.SyncStatus.RELAY_TOO_OLD
