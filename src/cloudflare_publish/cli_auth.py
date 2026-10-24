"""CLI API-token resolution helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cloudflare_publish.errors import AppError
from cloudflare_publish.local_secrets import local_secret_env_value
from cloudflare_publish.models import AppPaths
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.state import load_manifest


@dataclass(frozen=True)
class ApiTokenResolution:
    """Resolved API token plus non-secret source metadata."""

    token: str | None
    source: str

    @property
    def available(self) -> bool:
        """Return whether a token is available."""

        return self.token is not None


def resolve_api_token(
    *,
    explicit_token: str | None,
    keychain: SecretStore,
    paths: AppPaths,
) -> ApiTokenResolution:
    """Resolve an API token using flag, environment, local slice, then the host store."""

    if explicit_token is not None and explicit_token.strip():
        return ApiTokenResolution(token=explicit_token.strip(), source="flag")
    env_value = os.environ.get("CLOUDFLARE_API_TOKEN")
    if env_value is not None and env_value.strip():
        return ApiTokenResolution(token=env_value.strip(), source="env")
    dotenv_value = local_secret_env_value(key="CLOUDFLARE_API_TOKEN")
    if dotenv_value is not None:
        return ApiTokenResolution(token=dotenv_value, source="private_dotenv")
    manifest = load_manifest(paths.state_file)
    if manifest is None:
        return ApiTokenResolution(token=None, source="missing")
    try:
        token = keychain.load_secret(account=manifest.manager.api_token_keychain_account)
    except AppError:
        return ApiTokenResolution(token=None, source="missing")
    return ApiTokenResolution(
        token=token, source="keychain" if paths.host_platform == "darwin" else "private_file"
    )


def require_api_token(
    *,
    explicit_token: str | None,
    keychain: SecretStore,
    paths: AppPaths,
) -> ApiTokenResolution:
    """Resolve an API token or fail with setup guidance."""

    resolution = resolve_api_token(
        explicit_token=explicit_token,
        keychain=keychain,
        paths=paths,
    )
    if resolution.token is None:
        raise AppError(
            "Cloudflare API token is missing.",
            hints=(
                (
                    "Use the setup prompt, set CLOUDFLARE_API_TOKEN, populate "
                    "CLOUDFLARE_PUBLISH_DOTENV with an absolute private dotenv path, or run setup "
                    "so the token is stored in the host credential store."
                ),
            ),
            code="missing_api_token",
        )
    return resolution
