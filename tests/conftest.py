"""Pytest fixtures for cloudflare-publish tests."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.fake_environment import FakeEnvironment, make_fake_environment


@pytest.fixture
def fake_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEnvironment]:
    """Create a hermetic temp HOME, PATH, and fake binary suite."""

    yield from make_fake_environment(tmp_path, monkeypatch)
