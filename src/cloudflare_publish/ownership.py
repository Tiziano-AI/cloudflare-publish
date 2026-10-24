"""Fail-closed local ownership inspection and takeover helpers."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.errors import AppError
from cloudflare_publish.launchd import Launchd
from cloudflare_publish.models import (
    AppPaths,
    BackupRecord,
    StateManifest,
)
from cloudflare_publish.state import load_manifest, now_rfc3339


@dataclass(frozen=True)
class OwnershipInspection:
    """Summary of local canonical and legacy ownership state."""

    manifest: StateManifest | None
    conflicting_paths: tuple[Path, ...]
    conflicting_labels: tuple[str, ...]
    takeover_supported: bool = True

    @property
    def requires_takeover(self) -> bool:
        """Return whether local conflicting state exists."""

        return bool(self.conflicting_paths or self.conflicting_labels)


def inspect_ownership(paths: AppPaths, launchd: ConnectorService) -> OwnershipInspection:
    """Inspect canonical local state and known legacy conflicts."""

    manifest = load_manifest(paths.state_file)
    conflicting_paths = _existing_conflict_paths(paths)
    conflicting_labels = launchd.conflicting_services()
    return OwnershipInspection(
        manifest=manifest,
        conflicting_paths=conflicting_paths,
        conflicting_labels=conflicting_labels,
        takeover_supported=paths.host_platform == "darwin",
    )


def require_takeover(inspection: OwnershipInspection) -> None:
    """Raise a typed error describing local conflicting ownership."""

    hints: list[str] = []
    if inspection.conflicting_labels:
        hints.append("Conflicting native services: " + ", ".join(inspection.conflicting_labels))
    if inspection.conflicting_paths:
        hints.extend(str(path) for path in inspection.conflicting_paths)
    raise AppError(
        "Conflicting local cloudflared state exists. Re-run setup with --takeover after review."
        if inspection.takeover_supported
        else (
            "Conflicting Linux cloudflared state exists. "
            "Resolve it explicitly; Linux takeover is not supported."
        ),
        hints=tuple(hints),
    )


def create_backup(paths: AppPaths, inspection: OwnershipInspection) -> BackupRecord:
    """Copy known conflicting local paths into a timestamped takeover backup."""

    if paths.host_platform != "darwin":
        raise AppError("Linux legacy takeover is not supported.")
    timestamp = now_rfc3339().replace(":", "-")
    backup_dir = paths.backups_dir / timestamp
    copied_paths: list[Path] = []
    for original in inspection.conflicting_paths:
        if not original.exists():
            continue
        destination = backup_dir / _backup_relative_path(paths.home, original)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if original.is_dir():
            _ = shutil.copytree(original, destination, dirs_exist_ok=True)
        else:
            _ = shutil.copy2(original, destination)
        copied_paths.append(original)
    return BackupRecord(
        created_at=now_rfc3339(),
        directory=backup_dir,
        copied_paths=tuple(copied_paths),
    )


def cleanup_conflicts(
    paths: AppPaths, launchd: ConnectorService, inspection: OwnershipInspection
) -> None:
    """Remove known legacy local state after a successful backup."""

    if paths.host_platform != "darwin" or not isinstance(launchd, Launchd):
        raise AppError("Linux legacy takeover is not supported.")
    for label in inspection.conflicting_labels:
        launchd.bootout(label)
    for file_path in (
        paths.legacy_service_file,
        paths.legacy_cloudflared_config_file,
        paths.legacy_cloudflared_cert_file,
    ):
        if file_path.exists():
            file_path.unlink()
    if paths.legacy_cloudflared_dir.exists() and not any(paths.legacy_cloudflared_dir.iterdir()):
        _ = paths.legacy_cloudflared_dir.rmdir()


def _existing_conflict_paths(paths: AppPaths) -> tuple[Path, ...]:
    """Return existing legacy local paths that the new manager must not ignore."""

    if paths.host_platform == "linux":
        return tuple(
            path
            for path in (paths.legacy_service_file, paths.legacy_cloudflared_dir)
            if path.exists() or path.is_symlink()
        )
    candidates = (
        paths.legacy_service_file,
        paths.legacy_cloudflared_config_file,
        paths.legacy_cloudflared_cert_file,
    )
    return tuple(path for path in candidates if path.exists())


def _backup_relative_path(home: Path, original: Path) -> Path:
    """Return the relative backup destination path for an original path."""

    try:
        return original.relative_to(home)
    except ValueError:
        return Path(original.name)
