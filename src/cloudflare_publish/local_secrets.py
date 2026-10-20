"""Explicit private-dotenv ingress for operator-owned secrets."""

from __future__ import annotations

import os
import re
from pathlib import Path

from cloudflare_publish.errors import AppError

LOCAL_DOTENV_ENV_VAR = "CLOUDFLARE_PUBLISH_DOTENV"
SECRET_ENV_KEYS = (
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_ZONE_ID",
    "CLOUDFLARE_ZONE",
    "CLOUDFLARE_TUNNEL_NAME",
)

_ASSIGNMENT_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")


def local_secret_env_value(*, key: str) -> str | None:
    """Return one non-empty value from the configured private dotenv file."""

    value = local_secret_env_values().get(key)
    if value is None or not value.strip():
        return None
    return value.strip()


def local_secret_env_values() -> dict[str, str]:
    """Load supported keys from the explicitly configured private dotenv file."""

    path = _local_secret_env_path()
    if path is None:
        return {}
    _require_regular_secret_file(path)
    values: dict[str, str] = {}
    seen: set[str] = set()
    invalid_lines: list[int] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped.removeprefix("export ").strip()
        match = _ASSIGNMENT_RE.fullmatch(stripped)
        if match is None:
            invalid_lines.append(line_number)
            continue
        key = match.group(1)
        if key in seen:
            invalid_lines.append(line_number)
            continue
        seen.add(key)
        if key in SECRET_ENV_KEYS:
            values[key] = _clean_dotenv_value(match.group(2))
    if invalid_lines:
        joined = ", ".join(str(line_number) for line_number in invalid_lines)
        raise AppError(
            "Configured cloudflare-publish private dotenv is not valid.",
            hints=(f"Fix {path} line(s): {joined}.",),
            code="invalid_secret_env_file",
        )
    return values


def _local_secret_env_path() -> Path | None:
    """Return the configured private dotenv path, if the operator provided one."""

    raw_path = os.environ.get(LOCAL_DOTENV_ENV_VAR)
    if raw_path is None or not raw_path.strip():
        return None
    path = Path(raw_path.strip()).expanduser()
    if not path.is_absolute():
        raise AppError(
            f"{LOCAL_DOTENV_ENV_VAR} must point to an absolute private dotenv path.",
            hints=(f"Set {LOCAL_DOTENV_ENV_VAR} to an absolute path outside the repository.",),
            code="invalid_secret_env_file",
        )
    return path


def _require_regular_secret_file(path: Path) -> None:
    """Fail closed when the private dotenv file is not strict and regular."""

    if path.is_symlink():
        raise AppError(
            "Configured cloudflare-publish private dotenv must be a regular file, not a symlink.",
            hints=(f"Set {LOCAL_DOTENV_ENV_VAR} to a regular file outside the repository.",),
            code="invalid_secret_env_file",
        )
    if not path.is_file():
        raise AppError(
            "Configured cloudflare-publish private dotenv is not a regular file.",
            hints=(f"Fix {path}.",),
            code="invalid_secret_env_file",
        )
    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        raise AppError(
            "Configured cloudflare-publish private dotenv must use mode 0600.",
            hints=(f"Run `chmod 600 {path}`.",),
            code="invalid_secret_env_file",
        )


def _clean_dotenv_value(value: str) -> str:
    """Normalize the dotenv value shape supported by this CLI."""

    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"'):
        return stripped[1:-1].strip()
    return stripped
