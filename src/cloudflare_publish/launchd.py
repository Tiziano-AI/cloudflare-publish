"""Adapter for launchd service management."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import CANONICAL_LABEL, AppPaths
from cloudflare_publish.process import CommandResult, CommandRunner

LAUNCHD_UNLOAD_TIMEOUT_SECONDS = 5.0
LAUNCHD_UNLOAD_POLL_SECONDS = 0.1


@dataclass(frozen=True)
class LaunchdService:
    """One parsed `launchctl list` service row."""

    label: str
    pid: int | None
    status: int | None

    @property
    def running(self) -> bool:
        """Return whether launchd reports an active process id for the service."""

        return self.pid is not None


class Launchd:
    """Runs `launchctl` commands through the shared process adapter."""

    def __init__(self, runner: CommandRunner, paths: AppPaths) -> None:
        """Store the command runner and canonical path set."""

        self._runner: CommandRunner = runner
        self._paths: AppPaths = paths

    def which(self, program: str) -> Path | None:
        """Resolve a required external program on PATH."""

        return self._runner.which(program)

    def run(
        self,
        command: list[str],
        *,
        check: bool = True,
        input_text: str | None = None,
    ) -> CommandResult:
        """Run an arbitrary local command through the shared runner."""

        return self._runner.run(command, check=check, input_text=input_text)

    def list_services(self) -> tuple[LaunchdService, ...]:
        """Return parsed launchd services for the current user session."""

        result = self.run(["launchctl", "list"])
        services: list[LaunchdService] = []
        for line in result.stdout.splitlines():
            service = _parse_launchctl_list_line(line)
            if service is not None:
                services.append(service)
        return tuple(services)

    def list_labels(self) -> tuple[str, ...]:
        """Return the loaded launchd labels for the current user session."""

        return tuple(service.label for service in self.list_services())

    def service(self, label: str) -> LaunchdService | None:
        """Return a parsed service row for one label when it is loaded."""

        for service in self.list_services():
            if service.label == label:
                return service
        return None

    def is_loaded(self, label: str) -> bool:
        """Return whether a given label appears in `launchctl list`."""

        return self.service(label) is not None

    def is_registered(self, label: str) -> bool:
        """Return whether launchd still has a service record for the label."""

        service_target = (
            self._paths.service_target
            if label == CANONICAL_LABEL
            else f"{self._paths.domain_target}/{label}"
        )
        result = self.run(["launchctl", "print", service_target], check=False)
        return result.returncode == 0

    def validate_plist(self, plist_file: Path) -> None:
        """Validate a launchd plist file with `plutil`."""

        _ = self.run(["plutil", "-lint", str(plist_file)])

    def bootout(self, label: str) -> None:
        """Stop a loaded service if it exists."""

        service_target = (
            self._paths.service_target
            if label == CANONICAL_LABEL
            else f"{self._paths.domain_target}/{label}"
        )
        _ = self.run(["launchctl", "bootout", service_target])

    def bootstrap(self, plist_file: Path) -> None:
        """Load a launch agent plist into the current GUI user domain."""

        _ = self.run(["launchctl", "bootstrap", self._paths.domain_target, str(plist_file)])

    def kickstart(self, label: str) -> None:
        """Restart a loaded launchd service."""

        service_target = (
            self._paths.service_target
            if label == CANONICAL_LABEL
            else f"{self._paths.domain_target}/{label}"
        )
        _ = self.run(["launchctl", "kickstart", "-k", service_target])

    def wait_until_unregistered(self, label: str) -> None:
        """Wait boundedly until launchd no longer has a service record."""

        deadline = time.monotonic() + LAUNCHD_UNLOAD_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if not self.is_registered(label):
                return
            time.sleep(LAUNCHD_UNLOAD_POLL_SECONDS)
        raise AppError(
            "Timed out waiting for launchd to unload the connector.",
            hints=(f"Target: {self._paths.service_target}",),
        )


def _parse_launchctl_list_line(line: str) -> LaunchdService | None:
    """Parse one `launchctl list` output row."""

    parts = line.split(maxsplit=2)
    if len(parts) != 3 or parts[2] == "Label":
        return None
    return LaunchdService(
        label=parts[2],
        pid=_optional_int(parts[0]),
        status=_optional_int(parts[1]),
    )


def _optional_int(value: str) -> int | None:
    """Parse a launchctl integer column where '-' means absent."""

    if value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None
