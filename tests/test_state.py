"""State manifest persistence tests."""

from __future__ import annotations

from pathlib import Path

from cloudflare_publish.models import BackupRecord, ManagerConfig
from cloudflare_publish.state import build_initial_manifest, load_manifest, write_manifest


def test_manifest_roundtrip(tmp_path: Path) -> None:
    """The canonical nested manifest round-trips without drift."""

    state_file = tmp_path / "state.json"
    manifest = build_initial_manifest(
        manager=ManagerConfig(
            account_id="acc-123",
            account_name="Example Account",
            zone_id="zone-123",
            zone_name="example.com",
            auth_domain="example.cloudflareaccess.com",
            tunnel_name="cloudflare-publish",
            tunnel_id="tunnel-123",
            api_token_keychain_account="api-token",
        ),
        backups=(
            BackupRecord(
                created_at="2026-04-02T00:00:00Z",
                directory=tmp_path / "backups" / "first",
                copied_paths=(tmp_path / "conflict.cfg",),
            ),
        ),
    )
    write_manifest(state_file, manifest)
    assert load_manifest(state_file) == manifest
