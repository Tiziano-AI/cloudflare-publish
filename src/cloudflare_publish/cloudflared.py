"""Adapter for the external `cloudflared` binary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.errors import AppError
from cloudflare_publish.host_platform import HostPlatform
from cloudflare_publish.process import CommandRunner

MIN_SECURITY_VERSIONS: dict[HostPlatform, tuple[int, int, int]] = {
    "darwin": (2026, 10, 3),
    "linux": (2026, 10, 2),
}


@dataclass(frozen=True)
class CloudflaredVersionInfo:
    """Parsed runtime version information for `cloudflared`."""

    raw: str
    parsed: tuple[int, int, int]
    minimum: tuple[int, int, int]

    @property
    def meets_security_minimum(self) -> bool:
        """Return whether this executable meets the host's connector security floor."""

        return self.parsed >= self.minimum

    @property
    def minimum_text(self) -> str:
        """Return the required version in the vendor's dotted release format."""

        return ".".join(str(part) for part in self.minimum)


class Cloudflared:
    """Runs `cloudflared` commands through the shared process adapter."""

    def __init__(self, runner: CommandRunner, *, platform: HostPlatform) -> None:
        """Store the command runner and the admitted native host's security floor."""

        self._runner: CommandRunner = runner
        self._minimum: tuple[int, int, int] = MIN_SECURITY_VERSIONS[platform]

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

    def require_security_minimum_for_binary(self, binary: Path) -> CloudflaredVersionInfo:
        """Require the security floor from the native-service `cloudflared` binary."""

        info = self.version_info_for_binary(binary)
        if not info.meets_security_minimum:
            raise AppError(
                f"cloudflared {info.minimum_text} or later is required for the security minimum.",
                hints=(
                    f"Detected {info.raw}.",
                    "Upgrade cloudflared and rerun `cloudflare-publish setup`.",
                ),
            )
        return info

    def require_security_minimum(self) -> CloudflaredVersionInfo:
        """Require the security floor from the PATH-selected `cloudflared` binary."""

        info = self.version_info()
        if not info.meets_security_minimum:
            raise AppError(
                f"cloudflared {info.minimum_text} or later is required for the security minimum.",
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
            minimum=self._minimum,
        )
