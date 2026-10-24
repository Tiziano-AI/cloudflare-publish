"""Adapter for launchd service management."""

from __future__ import annotations

import time
import xml.etree.ElementTree as element_tree
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import CANONICAL_LABEL, AppPaths, ConnectorStatus
from cloudflare_publish.process import CommandResult, CommandRunner

LAUNCHD_UNLOAD_TIMEOUT_SECONDS = 5.0
LAUNCHD_UNLOAD_POLL_SECONDS = 0.1


@dataclass(frozen=True)
class LaunchdService(ConnectorStatus):
    """One parsed `launchctl list` service row."""

    label: str


@dataclass(frozen=True)
class LaunchAgentContract:
    """Canonical fields loaded from the launch-agent plist."""

    label: str
    program_arguments: tuple[str, ...]

    @property
    def binary(self) -> Path:
        """Return the encoded cloudflared binary path."""

        return Path(self.program_arguments[0])


class Launchd:
    """Runs `launchctl` commands through the shared process adapter."""

    def __init__(self, runner: CommandRunner, paths: AppPaths) -> None:
        """Store the command runner and canonical path set."""

        self._runner: CommandRunner = runner
        self._paths: AppPaths = paths

    @property
    def platform(self) -> Literal["darwin"]:
        """Identify the native host without class-name or environment inference."""

        return "darwin"

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

    def service(self, label: str = CANONICAL_LABEL) -> LaunchdService | None:
        """Return a parsed service row for one label when it is loaded."""

        for service in self.list_services():
            if service.label == label:
                return service
        return None

    def is_loaded(self, label: str = CANONICAL_LABEL) -> bool:
        """Return whether a given label appears in `launchctl list`."""

        return self.service(label) is not None

    def is_registered(self, label: str = CANONICAL_LABEL) -> bool:
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

    def preflight(self) -> None:
        """Require launchd's existing native tool baseline."""

        for program in ("launchctl", "plutil"):
            if self.which(program) is None:
                raise AppError(f"Required tool {program!r} is not available on PATH.")

    def conflicting_services(self) -> tuple[str, ...]:
        """Return the supported legacy launchd identity if loaded."""

        from cloudflare_publish.models import LEGACY_CLOUDFLARED_LABEL

        return tuple(label for label in self.list_labels() if label == LEGACY_CLOUDFLARED_LABEL)

    def validate_definition(self) -> Path:
        """Validate the existing canonical plist and return its pinned binary."""

        self.validate_plist(self._paths.service_file)
        contract = _launch_agent_contract(self._paths.service_file)
        _require_canonical_launch_agent(contract=contract, paths=self._paths)
        return contract.binary

    def install(self, binary: Path) -> None:
        """Retain macOS setup's existing render/bootout/bootstrap lifecycle."""

        from cloudflare_publish.render import render_launch_agent_plist

        text = render_launch_agent_plist(self._paths, str(binary))
        _ = self._paths.service_file.write_text(text, encoding="utf-8")
        self.validate_plist(self._paths.service_file)
        if self.is_loaded():
            self.bootout(CANONICAL_LABEL)
            self.wait_until_unregistered(CANONICAL_LABEL)
        self.bootstrap(self._paths.service_file)
        self.kickstart(CANONICAL_LABEL)

    def start(self) -> None:
        """Bootstrap when absent and kickstart the canonical connector."""

        service = self.service()
        if service is not None and service.running:
            return
        if service is None:
            self.bootstrap(self._paths.service_file)
        self.kickstart(CANONICAL_LABEL)

    def stop(self) -> None:
        """Unload the canonical connector and confirm native absence."""

        if self.is_loaded():
            self.bootout(CANONICAL_LABEL)
            self.wait_until_stopped()

    def restart(self) -> None:
        """Kickstart the canonical loaded connector."""

        if not self.is_loaded():
            raise AppError(
                "Connector is not loaded.", hints=("Run `cloudflare-publish service start` first.",)
            )
        self.kickstart(CANONICAL_LABEL)

    def wait_until_stopped(self) -> None:
        """Wait for launchd's canonical service record to disappear."""

        self.wait_until_unregistered(CANONICAL_LABEL)

    def remove_definition(self) -> None:
        """Remove only the canonical inactive launch-agent file."""

        self.wait_until_stopped()
        self._paths.service_file.unlink(missing_ok=True)


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


def _launch_agent_contract(plist_file: Path) -> LaunchAgentContract:
    """Load and type-check the launch-agent plist contract."""

    if not plist_file.exists():
        raise AppError("Canonical launch agent file is missing.")
    try:
        root = element_tree.parse(plist_file).getroot()
    except (OSError, element_tree.ParseError) as error:
        raise AppError("Canonical launch agent plist is invalid.") from error
    fields = _plist_dict_fields(_plist_root_dict(root))
    label = _require_string_field(fields, "Label")
    arguments = _require_string_sequence_field(fields, "ProgramArguments")
    if not arguments:
        raise AppError("Canonical launch agent plist is missing ProgramArguments.")
    return LaunchAgentContract(label=label, program_arguments=arguments)


def _plist_root_dict(root: element_tree.Element) -> element_tree.Element:
    """Return the root dictionary element from an XML launch-agent plist."""

    for child in list(root):
        if _xml_local_name(child.tag) == "dict":
            return child
    raise AppError("Canonical launch agent plist must contain a dictionary.")


def _plist_dict_fields(element: element_tree.Element) -> dict[str, element_tree.Element]:
    """Return key-to-value elements for one XML plist dictionary."""

    children = list(element)
    fields: dict[str, element_tree.Element] = {}
    index = 0
    while index + 1 < len(children):
        key_element = children[index]
        value_element = children[index + 1]
        if _xml_local_name(key_element.tag) == "key" and key_element.text is not None:
            fields[key_element.text] = value_element
        index += 2
    return fields


def _require_string_field(fields: dict[str, element_tree.Element], key: str) -> str:
    """Require one string field from the launch-agent plist."""

    value = fields.get(key)
    if value is None or _xml_local_name(value.tag) != "string" or not value.text:
        raise AppError(f"Canonical launch agent plist field {key!r} must be a string.")
    return value.text


def _require_string_sequence_field(
    fields: dict[str, element_tree.Element],
    key: str,
) -> tuple[str, ...]:
    """Require one string-list field from the launch-agent plist."""

    value = fields.get(key)
    if value is None or _xml_local_name(value.tag) != "array":
        raise AppError(f"Canonical launch agent plist field {key!r} must be an array.")
    items: list[str] = []
    for item in list(value):
        if _xml_local_name(item.tag) != "string" or not item.text:
            raise AppError(f"Canonical launch agent plist field {key!r} must contain strings.")
        items.append(item.text)
    return tuple(items)


def _xml_local_name(tag: str) -> str:
    """Return an XML element local name without a namespace prefix."""

    return tag.rsplit("}", maxsplit=1)[-1]


def _require_canonical_launch_agent(*, contract: LaunchAgentContract, paths: AppPaths) -> None:
    """Fail closed unless the plist is the canonical manager launch agent."""

    if contract.label != CANONICAL_LABEL:
        raise AppError(
            "Canonical launch agent plist has the wrong label.",
            hints=(f"Expected {CANONICAL_LABEL!r}; found {contract.label!r}.",),
        )
    expected_tail = ("tunnel", "run", "--token-file", str(paths.tunnel_token_file))
    if contract.program_arguments[1:] != expected_tail:
        raise AppError("Canonical launch agent ProgramArguments do not match manager state.")
