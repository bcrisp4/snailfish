"""Shared fixtures: the vector files of the repo `vectors/` directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

VECTORS = Path(__file__).resolve().parents[3] / "vectors"


def load(name: str) -> Any:
    """Return the parsed JSON of one vector file.

    Args:
        name: The path of the file below `vectors/`.

    Returns:
        The parsed JSON value.
    """
    return json.loads((VECTORS / name).read_text())


@pytest.fixture(scope="session")
def protocol() -> Any:
    """The parsed `vectors/protocol.json`."""
    return load("protocol.json")
