"""Shared typed models for manager config, publications, and local ownership."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cloudflare_publish.host_platform import HostPlatform
from cloudflare_publish.json_types import JsonObject

CheckGroup = Literal["manager", "routing", "origin", "access", "public_probe"]
CHECK_GROUPS: tuple[CheckGroup, ...] = ("manager", "routing", "origin", "access", "public_probe")

SCHEMA_VERSION = 1
CANONICAL_LABEL = "com.cloudflare-publish.cloudflared"
LEGACY_CLOUDFLARED_LABEL = "com.cloudflare.cloudflared"
KEYCHAIN_SERVICE = "cloudflare-publish"
API_TOKEN_ACCOUNT = "api-token"
DEFAULT_TUNNEL_NAME = "cloudflare-publish"
DEFAULT_EXPECT_STATUS = "200-399"
DEFAULT_VERIFY_PATH = "/"


@dataclass(frozen=True)
class ConnectorStatus:
    """Native service process state, not tunnel readiness or application evidence."""

    pid: int | None
    status: int | None

    @property
    def running(self) -> bool:
        """Return whether the native service manager reports a process."""

        return self.pid is not None and self.pid > 0


@dataclass(frozen=True)
class AppPaths:
    """Canonical local filesystem paths owned or inspected by the repo."""

    repo_root: Path
    home: Path
    host_platform: HostPlatform
    service_dir: Path
    service_file: Path
    legacy_service_file: Path
    state_dir: Path
    state_file: Path
    backups_dir: Path
    tunnel_token_file: Path
    logs_dir: Path
    stdout_log_file: Path
    stderr_log_file: Path
    legacy_cloudflared_dir: Path
    legacy_cloudflared_config_file: Path
    legacy_cloudflared_cert_file: Path

    @property
    def domain_target(self) -> str:
        """Return the launchd domain target for the current GUI user."""

        import os

        return f"gui/{os.getuid()}"

    @property
    def service_target(self) -> str:
        """Return the canonical native user-service target."""

        if self.host_platform == "linux":
            return "cloudflare-publish.service"
        return f"{self.domain_target}/{CANONICAL_LABEL}"

    @property
    def managed_paths(self) -> tuple[Path, ...]:
        """Return the local files and directories managed by the repo."""

        return (
            self.service_file,
            self.state_file,
            self.tunnel_token_file,
            self.logs_dir,
        )


@dataclass(frozen=True)
class BackupRecord:
    """A local backup created during takeover."""

    created_at: str
    directory: Path
    copied_paths: tuple[Path, ...]


@dataclass(frozen=True)
class OriginOptions:
    """Origin connection options for a public hostname."""

    http_host_header: str | None
    origin_server_name: str | None
    no_tls_verify: bool


@dataclass(frozen=True)
class PublicationSpec:
    """Canonical publication contract owned by the manager."""

    kind: str
    name: str
    hostname: str
    origin_url: str
    audience: str
    allowed_emails: tuple[str, ...]
    allowed_email_domains: tuple[str, ...]
    verify_path: str | None
    expect_status: str | None
    origin_options: OriginOptions
    ssh_host_key: str | None = None


@dataclass(frozen=True)
class PublicationRemoteState:
    """Remote Cloudflare resource ownership for a publication."""

    dns_record_id: str
    access_application_id: str | None
    access_aud: str | None
    policy_ids: tuple[str, ...]
    service_token_id: str | None
    service_token_client_id: str | None
    service_token_keychain_account: str | None
    updated_at: str


@dataclass(frozen=True)
class ManagedPublication:
    """Combined publication spec plus remote ownership state."""

    spec: PublicationSpec
    state: PublicationRemoteState


@dataclass(frozen=True)
class ManagerConfig:
    """Top-level manager identity and shared-tunnel ownership."""

    account_id: str
    account_name: str
    zone_id: str
    zone_name: str
    auth_domain: str
    tunnel_name: str
    tunnel_id: str
    api_token_keychain_account: str


@dataclass(frozen=True)
class PendingEffect:
    """One non-repeatable provider effect whose response may have been lost."""

    kind: str
    resource_name: str
    resource_id: str | None = None


@dataclass(frozen=True)
class PendingTransition:
    """Custody of one unfinished domain mutation, never a separate history."""

    operation_id: str
    kind: str
    target: str
    request: JsonObject
    phase: str = "started"
    route: Literal["current", "withdrawn", "candidate"] = "current"
    candidate: ManagedPublication | None = None
    effect: PendingEffect | None = None
    configuration_version: int | None = None


@dataclass(frozen=True)
class StateManifest:
    """Canonical local state manifest for the manager."""

    schema_version: int
    manager: ManagerConfig
    publications: dict[str, ManagedPublication]
    backups: tuple[BackupRecord, ...]
    updated_at: str
    pending: PendingTransition | None = None


@dataclass(frozen=True)
class CheckResult:
    """A single local or live verification check result."""

    label: str
    ok: bool
    detail: str | None = None
    group: CheckGroup = "manager"
    publication_name: str | None = None
    hostname: str | None = None


@dataclass(frozen=True)
class SetupRequest:
    """CLI setup request contract."""

    install_deps: bool
    takeover: bool
    refresh_only: bool
    api_token: str | None
    account_id: str | None
    zone_id: str | None
    zone_name: str | None
    tunnel_name: str | None


@dataclass(frozen=True)
class PublishRequest:
    """CLI publication create-or-update contract."""

    name: str
    hostname: str
    origin_url: str
    audience: str
    allowed_emails: tuple[str, ...]
    allowed_email_domains: tuple[str, ...]
    verify_path: str | None
    expect_status: str | None
    http_host_header: str | None
    origin_server_name: str | None
    no_tls_verify: bool
    ssh_host_key: str | None = None
