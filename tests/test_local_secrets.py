"""Private dotenv ingress coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.local_secrets import (
    LOCAL_DOTENV_ENV_VAR,
    local_secret_env_value,
    local_secret_env_values,
)


def test_missing_private_dotenv_env_var_is_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing private dotenv pointer produces no secret values."""

    monkeypatch.delenv(LOCAL_DOTENV_ENV_VAR, raising=False)

    assert local_secret_env_values() == {}
    assert local_secret_env_value(key="CLOUDFLARE_API_TOKEN") is None


def test_private_dotenv_returns_supported_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private dotenv supports token and setup fallback values."""

    path = _write_private_dotenv(
        tmp_path,
        (
            "CLOUDFLARE_API_TOKEN=' token-1 '",
            "export CLOUDFLARE_ACCOUNT_ID=acc-123",
            "UNRELATED_SECRET=ignored",
        ),
        monkeypatch=monkeypatch,
    )

    values = local_secret_env_values()
    assert path.is_file()
    assert values == {
        "CLOUDFLARE_API_TOKEN": "token-1",
        "CLOUDFLARE_ACCOUNT_ID": "acc-123",
    }


def test_private_dotenv_requires_absolute_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The private dotenv pointer must not depend on a process working directory."""

    monkeypatch.setenv(LOCAL_DOTENV_ENV_VAR, "relative.env")

    with pytest.raises(AppError) as error_info:
        _ = local_secret_env_values()

    assert error_info.value.code == "invalid_secret_env_file"
    assert "absolute" in error_info.value.message


def test_private_dotenv_rejects_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private dotenv cannot be a symlink to another secret file."""

    secret_dir = tmp_path / "private"
    secret_dir.mkdir(mode=0o700)
    target = secret_dir / "target.env"
    _ = target.write_text("CLOUDFLARE_API_TOKEN=token-1\n", encoding="utf-8")
    target.chmod(0o600)
    link_path = secret_dir / "cloudflare-publish.env"
    link_path.symlink_to(target)
    monkeypatch.setenv(LOCAL_DOTENV_ENV_VAR, str(link_path))

    with pytest.raises(AppError) as error_info:
        _ = local_secret_env_values()

    assert error_info.value.code == "invalid_secret_env_file"
    encoded = str(error_info.value)
    assert "token-1" not in encoded
    assert "regular file" in error_info.value.message


def test_private_dotenv_requires_strict_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private dotenv must be readable only by the user."""

    path = _write_private_dotenv(
        tmp_path,
        ("CLOUDFLARE_API_TOKEN=token-1",),
        monkeypatch=monkeypatch,
    )
    path.chmod(0o644)

    with pytest.raises(AppError) as error_info:
        _ = local_secret_env_values()

    assert error_info.value.code == "invalid_secret_env_file"
    assert "0600" in error_info.value.message


def test_private_dotenv_rejects_ambiguous_dotenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed or duplicated dotenv assignments fail closed."""

    _ = _write_private_dotenv(
        tmp_path,
        (
            "CLOUDFLARE_API_TOKEN=token-1",
            "CLOUDFLARE_API_TOKEN=token-2",
            "not dotenv",
        ),
        monkeypatch=monkeypatch,
    )

    with pytest.raises(AppError) as error_info:
        _ = local_secret_env_values()

    assert error_info.value.code == "invalid_secret_env_file"


def _write_private_dotenv(
    root: Path,
    lines: tuple[str, ...],
    *,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Write a strict private dotenv file and configure the product to read it."""

    secret_dir = root / "private"
    secret_dir.mkdir(mode=0o700)
    path = secret_dir / "cloudflare-publish.env"
    _ = path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setenv(LOCAL_DOTENV_ENV_VAR, str(path))
    return path
