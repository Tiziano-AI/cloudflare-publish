"""Shared CLI command helpers."""

from __future__ import annotations

import os
from pathlib import Path

from cloudflare_publish.cli_auth import require_api_token
from cloudflare_publish.cli_runtime import CliRuntime
from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.errors import AppError
from cloudflare_publish.local_secrets import local_secret_env_value


def api_from_token(*, args_token: str | None, runtime: CliRuntime) -> CloudflareApi:
    """Build an API client from resolved token state."""

    resolution = require_api_token(
        explicit_token=args_token,
        keychain=runtime.keychain,
        paths=runtime.paths,
    )
    token = resolution.token
    if token is None:
        raise AppError("Cloudflare API token is missing.", code="missing_api_token")
    return CloudflareApi(runtime.http, token)


def env_or_none(value: str | None, env_name: str, *, home: Path) -> str | None:
    """Resolve a CLI option with process-env and private-dotenv fallbacks."""

    _ = home
    if value is not None:
        return value
    env_value = os.environ.get(env_name)
    if env_value is None or not env_value.strip():
        return local_secret_env_value(key=env_name)
    return env_value.strip()


def require_value(value: str | None, *, message: str) -> str:
    """Require a CLI string value after argparse parsing."""

    if value is None or not value.strip():
        raise AppError(message)
    return value


def raise_requires_yes(action: str) -> None:
    """Fail a high-impact command when explicit confirmation is missing."""

    raise AppError(
        f"{action} requires --yes.",
        hints=("Run the corresponding plan command first when available.",),
        code="confirmation_required",
    )
