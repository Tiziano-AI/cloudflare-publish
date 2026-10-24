"""Shared helpers for workflow modules."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.local_secrets import local_secret_env_value
from cloudflare_publish.models import AppPaths, StateManifest
from cloudflare_publish.private_files import (
    ensure_private_directory,
    private_directory_available,
    write_private_file,
)
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.state import load_manifest


def ensure_platform_tools(
    *,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    install_deps: bool,
) -> None:
    """Require the local external-tool baseline."""

    launchd.preflight()
    if cloudflared.binary() is None:
        if launchd.platform == "linux":
            raise AppError(
                "cloudflared is not installed.",
                hints=(
                    "Install cloudflared from Cloudflare's official Linux packages; "
                    + "--install-deps is macOS-only.",
                ),
            )
        if not install_deps:
            raise AppError(
                "cloudflared is not installed.",
                hints=("Re-run `cloudflare-publish setup --install-deps`.",),
            )
        if launchd.which("brew") is None:
            raise AppError("Homebrew is required for --install-deps.")
        _ = launchd.run(["brew", "install", "cloudflared"])
    _ = cloudflared.require_token_file_support()
    for program in ("curl",):
        if launchd.which(program) is None:
            raise AppError(f"Required tool {program!r} is not available on PATH.")
    if not keychain.binary_available():
        raise AppError("The platform secret store is unavailable.")


def ensure_manager_directories(paths: AppPaths) -> None:
    """Create the manager-owned local directories."""

    if paths.host_platform == "linux":
        for directory in (paths.state_dir, paths.backups_dir, paths.logs_dir):
            ensure_private_directory(directory)
        paths.service_dir.mkdir(parents=True, exist_ok=True)
        return
    for directory in (
        paths.service_dir,
        paths.state_dir,
        paths.backups_dir,
        paths.logs_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def install_connector_service(
    *,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
) -> None:
    """Render, validate, and load the native canonical user connector."""

    binary = cloudflared.binary()
    if binary is None:
        raise AppError("cloudflared is not installed.")
    launchd.install(binary)


def write_tunnel_token(paths: AppPaths, token: str) -> None:
    """Persist the tunnel runtime token with strict permissions."""

    if paths.host_platform == "linux":
        try:
            value = (token + "\n").encode("ascii")
        except UnicodeError as error:
            raise AppError("The tunnel runtime token must be printable ASCII.") from error
        if not token or any(byte < 33 or byte > 126 for byte in value[:-1]):
            raise AppError("The tunnel runtime token must be printable ASCII.")
        write_private_file(
            paths.tunnel_token_file.parent,
            paths.tunnel_token_file.name,
            value,
            max_bytes=65536,
        )
        return
    paths.tunnel_token_file.parent.mkdir(parents=True, exist_ok=True)
    _ = paths.tunnel_token_file.write_text(token + "\n", encoding="utf-8")
    paths.tunnel_token_file.chmod(0o600)


def require_manifest(paths: AppPaths) -> StateManifest:
    """Load the manager state manifest or fail with a typed error."""

    manifest = load_manifest(paths.state_file)
    if manifest is None:
        raise AppError("Manager state is missing. Run `cloudflare-publish setup` first.")
    return manifest


def load_api_token(
    *,
    keychain: SecretStore,
    manifest: StateManifest,
    home: Path,
    explicit_token: str | None = None,
) -> str:
    """Load the API token through flag, environment, private dotenv, then host storage."""

    if explicit_token is not None and explicit_token.strip():
        return explicit_token.strip()
    env_value = os.environ.get("CLOUDFLARE_API_TOKEN")
    if env_value is not None and env_value.strip():
        return env_value.strip()
    _ = home
    dotenv_value = local_secret_env_value(key="CLOUDFLARE_API_TOKEN")
    if dotenv_value is not None:
        return dotenv_value
    return keychain.load_secret(account=manifest.manager.api_token_keychain_account)


def remove_local_manager_artifacts(paths: AppPaths) -> None:
    """Remove manager-owned local files without touching backups."""

    if paths.host_platform == "linux":
        _remove_linux_manager_artifacts(paths)
        return
    for file_path in (
        paths.service_file,
        paths.tunnel_token_file,
        paths.stdout_log_file,
        paths.stderr_log_file,
    ):
        if file_path.exists():
            file_path.unlink()
    if paths.logs_dir.exists() and not any(paths.logs_dir.iterdir()):
        paths.logs_dir.rmdir()
    if paths.state_dir.exists():
        for child in tuple(paths.state_dir.iterdir()):
            if child in {paths.backups_dir, paths.state_dir / "manager.lock", paths.state_file}:
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    # Recovery custody remains available until every other local cleanup succeeded.
    paths.state_file.unlink(missing_ok=True)


def _remove_linux_manager_artifacts(paths: AppPaths) -> None:
    """Retire exact known artifacts, preserving unexplained entries and lock custody."""

    for directory in (paths.state_dir, paths.logs_dir, paths.state_dir / "credentials"):
        _ = private_directory_available(directory)
    for file_path in (
        paths.tunnel_token_file,
        paths.stdout_log_file,
        paths.stderr_log_file,
    ):
        file_path.unlink(missing_ok=True)
    for directory in (paths.logs_dir, paths.state_dir / "credentials"):
        if directory.exists() and not any(directory.iterdir()):
            directory.rmdir()
    # The native adapter alone validates and removes the unit definition.
    # Keep the manifest's recovery state until exact local cleanup has succeeded.
    paths.state_file.unlink(missing_ok=True)


def select_publications(
    manifest: StateManifest,
    *,
    publication_name: str | None,
) -> tuple[str, ...]:
    """Select one or all publication names from the manifest."""

    if publication_name is None:
        return tuple(sorted(manifest.publications))
    if publication_name not in manifest.publications:
        raise AppError(f"Unknown publication {publication_name!r}.")
    return (publication_name,)


def show_manifest_summary(console: Console, manifest: StateManifest) -> None:
    """Render a compact manager summary."""

    console.note(f"Account: {manifest.manager.account_name} ({manifest.manager.account_id})")
    console.note(f"Zone: {manifest.manager.zone_name}")
    console.note(f"Tunnel: {manifest.manager.tunnel_name} ({manifest.manager.tunnel_id})")
    console.note(f"Publications: {len(manifest.publications)}")


def canonical_public_url(hostname: str, verify_path: str) -> str:
    """Return the HTTPS verification URL for a publication."""

    return f"https://{hostname}{verify_path}"
