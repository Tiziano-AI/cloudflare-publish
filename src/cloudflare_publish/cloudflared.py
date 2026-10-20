"""Adapter for the external `cloudflared` binary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.errors import AppError
from cloudflare_publish.process import CommandRunner

MIN_TOKEN_FILE_VERSION = (2025, 4, 0)
MIN_TOKEN_FILE_VERSION_TEXT = "2025.4.0"


@dataclass(frozen=True)
class CloudflaredVersionInfo:
    """Parsed runtime version information for `cloudflared`."""

    raw: str
    parsed: tuple[int, int, int]

    @property
    def supports_token_file(self) -> bool:
        """Return whether this version supports `cloudflared tunnel run --token-file`."""

        return self.parsed >= MIN_TOKEN_FILE_VERSION


class Cloudflared:
    """Runs `cloudflared` commands through the shared process adapter."""

    def __init__(self, runner: CommandRunner) -> None:
        """Store the command runner used by the adapter."""

        self._runner: CommandRunner = runner

    def binary(self) -> Path | None:
        """Return the resolved cloudflared binary."""

        return self._runner.which("cloudflared")

    def version(self) -> str:
        """Return the first line of `cloudflared --version`."""

        binary = self.binary()
        if binary is None:
            raise AppError("cloudflared is not installed.")
        return self.version_for_binary(binary)

    def version_for_binary(self, binary: Path) -> str:
        """Return the first line of one `cloudflared` binary's version output."""

        result = self._runner.run([str(binary), "--version"])
        line = result.stdout.strip().splitlines()
        if not line:
            raise AppError("cloudflared --version returned no output.")
        return line[0]

    def version_info(self) -> CloudflaredVersionInfo:
        """Return parsed version information for the installed `cloudflared`."""

        raw = self.version()
        return self._parse_version_info(raw)

    def version_info_for_binary(self, binary: Path) -> CloudflaredVersionInfo:
        """Return parsed version information for a concrete `cloudflared` binary."""

        if not binary.exists():
            raise AppError(f"cloudflared binary is missing: {binary}")
        raw = self.version_for_binary(binary)
        return self._parse_version_info(raw)

    def require_token_file_support_for_binary(self, binary: Path) -> CloudflaredVersionInfo:
        """Require token-file support from the launch-agent `cloudflared` binary."""

        info = self.version_info_for_binary(binary)
        if not info.supports_token_file:
            raise AppError(
                f"cloudflared {MIN_TOKEN_FILE_VERSION_TEXT} or later is required.",
                hints=(
                    f"Detected {info.raw}.",
                    "Upgrade cloudflared and rerun `cloudflare-publish setup`.",
                ),
            )
        return info

    def require_token_file_support(self) -> CloudflaredVersionInfo:
        """Require support for `cloudflared tunnel run --token-file`."""

        info = self.version_info()
        if not info.supports_token_file:
            raise AppError(
                f"cloudflared {MIN_TOKEN_FILE_VERSION_TEXT} or later is required.",
                hints=(
                    f"Detected {info.raw}.",
                    "Upgrade cloudflared and rerun the command.",
                ),
            )
        return info

    def _parse_version_info(self, raw: str) -> CloudflaredVersionInfo:
        """Parse a raw cloudflared version line."""

        matched = re.search(r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)", raw)
        if matched is None:
            raise AppError(
                "cloudflared --version returned an unrecognized version string.",
                hints=(raw,),
            )
        return CloudflaredVersionInfo(
            raw=raw,
            parsed=(
                int(matched.group("major")),
                int(matched.group("minor")),
                int(matched.group("patch")),
            ),
        )
