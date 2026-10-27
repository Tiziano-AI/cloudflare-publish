"""Connector admission checks the platform security floor, not old CLI capability."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.errors import AppError
from cloudflare_publish.host_platform import HostPlatform
from cloudflare_publish.process import CommandRunner


@pytest.mark.parametrize(
    ("platform", "version", "accepted"),
    [
        ("darwin", "2025.4.0", False),
        ("linux", "2025.4.0", False),
        ("darwin", "2026.10.1", False),
        ("linux", "2026.10.1", False),
        ("darwin", "2026.10.2", False),
        ("linux", "2026.10.2", True),
        ("darwin", "2026.10.3", True),
        ("linux", "2026.10.3", True),
        ("darwin", "2026.10.10", True),
        ("linux", "2027.1.0", True),
    ],
)
def test_security_minimum_on_path_and_service_binary(
    platform: HostPlatform,
    version: str,
    accepted: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PATH and native-service binaries use one platform-aware admission decision."""

    binary = tmp_path / "cloudflared"
    binary.touch()
    adapter = Cloudflared(CommandRunner(), platform=platform)
    monkeypatch.setattr(adapter, "binary", lambda: binary)
    monkeypatch.setattr(adapter, "version_for_binary", lambda _: f"cloudflared version {version}")
    expected_minimum = "2026.10.3" if platform == "darwin" else "2026.10.2"
    info = adapter.version_info()
    assert info.meets_security_minimum is accepted
    assert info.minimum_text == expected_minimum
    for check in (
        adapter.require_security_minimum,
        lambda: adapter.require_security_minimum_for_binary(binary),
    ):
        if accepted:
            assert check() == info
        else:
            with pytest.raises(AppError, match=f"cloudflared {expected_minimum} or later"):
                check()


def test_unknown_version_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unrecognized vendor version cannot bypass the security floor."""

    adapter = Cloudflared(CommandRunner(), platform="darwin")
    monkeypatch.setattr(adapter, "version", lambda: "cloudflared development build")
    with pytest.raises(AppError, match="unrecognized version"):
        adapter.require_security_minimum()
