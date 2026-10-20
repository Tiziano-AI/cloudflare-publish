"""Canonical path construction for manager-owned local state."""

from __future__ import annotations

from pathlib import Path

from cloudflare_publish.models import (
    CANONICAL_LABEL,
    LEGACY_CLOUDFLARED_LABEL,
    AppPaths,
)


def build_paths(repo_root: Path, home: Path) -> AppPaths:
    """Build the canonical local path set for the current home directory."""

    launch_agents_dir = home / "Library" / "LaunchAgents"
    state_dir = home / "Library" / "Application Support" / "cloudflare-publish"
    logs_dir = home / "Library" / "Logs" / "cloudflare-publish"
    legacy_cloudflared_dir = home / ".cloudflared"
    return AppPaths(
        repo_root=repo_root,
        home=home,
        launch_agents_dir=launch_agents_dir,
        canonical_launch_agent_file=launch_agents_dir / f"{CANONICAL_LABEL}.plist",
        legacy_launch_agent_file=launch_agents_dir / f"{LEGACY_CLOUDFLARED_LABEL}.plist",
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
