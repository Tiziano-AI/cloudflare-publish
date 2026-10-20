"""CLI runtime bundle construction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.launchd import Launchd
from cloudflare_publish.models import AppPaths
from cloudflare_publish.paths import build_paths
from cloudflare_publish.process import CommandRunner


@dataclass(frozen=True)
class CliRuntime:
    """Shared runtime objects for one CLI invocation."""

    paths: AppPaths
    cloudflared: Cloudflared
    http: CurlHttpClient
    keychain: Keychain
    launchd: Launchd


def build_cli_runtime(*, repo_root: Path | None, home: Path | None) -> CliRuntime:
    """Build the shared runtime bundle."""

    resolved_repo_root = Path.cwd() if repo_root is None else repo_root
    resolved_home = Path.home() if home is None else home
    paths = build_paths(repo_root=resolved_repo_root, home=resolved_home)
    runner = CommandRunner()
    return CliRuntime(
        paths=paths,
        cloudflared=Cloudflared(runner),
        http=CurlHttpClient(runner),
        keychain=Keychain(runner),
        launchd=Launchd(runner, paths),
    )
