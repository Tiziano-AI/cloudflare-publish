"""Typed host credential contract and headless Linux private-file implementation.

Linux files provide POSIX access control, not encryption at rest. No keyring,
desktop session or third-party service is needed; root/the same UID retain access.
The macOS Keychain adapter structurally implements the same SecretStore protocol.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol

from cloudflare_publish.errors import AppError
from cloudflare_publish.private_files import (
    delete_private_file,
    private_directory_available,
    read_private_file,
    write_private_file,
)

# Bounds persistent reads and write inputs; real API/Access tokens fit comfortably.
MAX_SECRET_BYTES = 4096


class SecretStore(Protocol):
    """Host-selected credential storage, using stable opaque manifest account references."""

    def binary_available(self) -> bool:
        """Check host availability without creating a store or fetching a credential."""
        ...

    def store_secret(self, *, account: str, secret: str) -> None:
        """Store one token and confirm its exact readback."""
        ...

    def load_secret(self, *, account: str) -> str:
        """Return a stored token, failing closed when missing or invalid."""
        ...

    def delete_secret(self, *, account: str) -> None:
        """Remove one token, or raise when absence cannot be confirmed."""
        ...


class FileSecretStore:
    """One opaque current-UID 0600 file per account in a current-UID 0700 root."""

    def __init__(self, root: Path) -> None:
        """Select the host-owned credential directory; do not create it yet."""

        self._root: Path = root

    def binary_available(self) -> bool:
        """Return POSIX availability; unsafe existing paths raise instead of passing."""

        return private_directory_available(self._root)

    def store_secret(self, *, account: str, secret: str) -> None:
        """Validate before any mutation, then privately replace and verify exact bytes."""

        name = _account_filename(account)
        _require_secret(secret)
        write_private_file(self._root, name, secret.encode("ascii"), max_bytes=MAX_SECRET_BYTES)

    def load_secret(self, *, account: str) -> str:
        """Read only a bounded no-follow private regular file, preserving whitespace."""

        value = read_private_file(
            self._root, _account_filename(account), max_bytes=MAX_SECRET_BYTES
        )
        if value is None:
            raise AppError(
                "Private credential is missing; restore it through its owning workflow.",
                code="secret_missing",
            )
        try:
            secret = value.decode("ascii")
        except UnicodeDecodeError:
            raise AppError(
                "Stored credential is not printable ASCII.", code="invalid_secret"
            ) from None
        _require_secret(secret)
        return secret

    def delete_secret(self, *, account: str) -> None:
        """Delete this exact opaque account only and confirm absence without creating paths."""

        delete_private_file(self._root, _account_filename(account))


def _account_filename(account: str) -> str:
    """Hash complete UTF-8 metadata rather than putting account text into paths or errors."""

    if not account or any(character in account for character in "\0\r\n"):
        raise AppError(
            "Credential account must be nonempty text without NUL, CR, or LF.",
            code="invalid_secret_account",
        )
    try:
        encoded = account.encode("utf-8")
    except UnicodeEncodeError:
        raise AppError(
            "Credential account must be valid UTF-8 text.", code="invalid_secret_account"
        ) from None
    return hashlib.sha256(encoded).hexdigest() + ".secret"


def _require_secret(secret: str) -> None:
    """Admit bounded printable ASCII tokens without trimming meaningful whitespace."""

    if (
        not secret.strip()
        or len(secret) > MAX_SECRET_BYTES
        or any(not 0x20 <= ord(character) <= 0x7E for character in secret)
    ):
        raise AppError(
            "Credentials must be nonempty printable ASCII tokens "
            + f"of at most {MAX_SECRET_BYTES} bytes.",
            code="invalid_secret",
        )
