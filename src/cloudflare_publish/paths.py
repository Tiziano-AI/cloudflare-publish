"""Canonical path construction for manager-owned local state."""

from __future__ import annotations

from pathlib import Path

from cloudflare_publish.host_platform import host_platform
from cloudflare_publish.models import (
    CANONICAL_LABEL,
    LEGACY_CLOUDFLARED_LABEL,
    AppPaths,
)


def build_paths(repo_root: Path, home: Path, *, platform: str | None = None) -> AppPaths:
    """Build the canonical local path set for the current home directory."""

    selected = host_platform(platform)
    if selected == "linux":
        service_dir = home / ".config" / "systemd" / "user"
        state_dir = home / ".local" / "state" / "cloudflare-publish"
        logs_dir = state_dir / "logs"
        service_file = service_dir / "cloudflare-publish.service"
        legacy_service_file = service_dir / "cloudflared.service"
    else:
        service_dir = home / "Library" / "LaunchAgents"
        state_dir = home / "Library" / "Application Support" / "cloudflare-publish"
        logs_dir = home / "Library" / "Logs" / "cloudflare-publish"
        service_file = service_dir / f"{CANONICAL_LABEL}.plist"
        legacy_service_file = service_dir / f"{LEGACY_CLOUDFLARED_LABEL}.plist"
    legacy_cloudflared_dir = home / ".cloudflared"
    return AppPaths(
        repo_root=repo_root,
        home=home,
        host_platform=selected,
        service_dir=service_dir,
        service_file=service_file,
        legacy_service_file=legacy_service_file,
        state_dir=state_dir,
        state_file=state_dir / "state.json",
        backups_dir=state_dir / "backups",
        tunnel_token_file=state_dir / "tunnel-token.txt",
        logs_dir=logs_dir,
        stdout_log_file=logs_dir / "cloudflared.out.log",
        stderr_log_file=logs_dir / "cloudflared.err.log",
        legacy_cloudflared_dir=legacy_cloudflared_dir,
        legacy_cloudflared_config_file=legacy_cloudflared_dir / "config.yml",
        legacy_cloudflared_cert_file=legacy_cloudflared_dir / "cert.pem",
    )
