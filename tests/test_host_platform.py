"""Canonical native host selection preserves Mac storage and separates Linux."""

from pathlib import Path

import pytest

from cloudflare_publish.connector_service import build_connector_service
from cloudflare_publish.errors import AppError
from cloudflare_publish.launchd import Launchd
from cloudflare_publish.paths import build_paths
from cloudflare_publish.process import CommandRunner
from cloudflare_publish.systemd import Systemd


def test_native_paths_and_adapter_selection(tmp_path: Path) -> None:
    mac = build_paths(tmp_path, tmp_path, platform="darwin")
    linux = build_paths(tmp_path, tmp_path, platform="linux")
    assert (
        mac.service_file
        == tmp_path / "Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist"
    )
    assert mac.state_dir == tmp_path / "Library/Application Support/cloudflare-publish"
    assert mac.logs_dir == tmp_path / "Library/Logs/cloudflare-publish"
    assert linux.state_dir == tmp_path / ".local/state/cloudflare-publish"
    assert linux.logs_dir == linux.state_dir / "logs"
    assert linux.service_file == tmp_path / ".config/systemd/user/cloudflare-publish.service"
    assert linux.service_target == "cloudflare-publish.service"
    assert isinstance(build_connector_service(CommandRunner(), mac), Launchd)
    assert isinstance(build_connector_service(CommandRunner(), linux), Systemd)


def test_unsupported_platform_has_no_storage_effect(tmp_path: Path) -> None:
    with pytest.raises(AppError, match="Only macOS and Linux"):
        _ = build_paths(tmp_path, tmp_path / "unused", platform="win32")
    assert not (tmp_path / "unused").exists()


def test_platform_is_not_selectable_by_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLOUDFLARE_PUBLISH_PLATFORM", "linux")
    monkeypatch.setattr("cloudflare_publish.host_platform.sys.platform", "darwin")
    assert build_paths(tmp_path, tmp_path).host_platform == "darwin"
