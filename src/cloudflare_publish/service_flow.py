"""Local launchd connector lifecycle workflows."""

from __future__ import annotations

import xml.etree.ElementTree as element_tree
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.launchd import Launchd
from cloudflare_publish.models import CANONICAL_LABEL, AppPaths, StateManifest
from cloudflare_publish.state import load_manifest
from cloudflare_publish.workflow_support import require_manifest, show_manifest_summary

DEFAULT_LOG_LINES = 80


@dataclass(frozen=True)
class LaunchAgentContract:
    """Canonical fields loaded from the launch-agent plist."""

    label: str
    program_arguments: tuple[str, ...]

    @property
    def binary(self) -> Path:
        """Return the encoded cloudflared binary path."""

        return Path(self.program_arguments[0])


def run_service_status(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: Launchd,
    console: Console,
) -> None:
    """Render local connector lifecycle state without mutating local or remote resources."""

    payload = collect_service_status(paths=paths, cloudflared=cloudflared, launchd=launchd)
    console.section("Service Status")
    manifest = load_manifest(paths.state_file)
    _show_manager_status(console=console, manifest=manifest, paths=paths)
    console.note(f"Launch agent file: {payload['launch_agent_file']}")
    console.note(f"Launch agent loaded: {payload['launch_agent_loaded']}")
    console.note(f"Launch agent process: {payload['launch_agent_process']}")
    console.note(f"Launchd service target: {payload['launchd_service_target']}")
    console.note(f"Tunnel token file: {payload['tunnel_token_file']}")
    console.note(f"Launch agent binary: {payload['launch_agent_binary']}")
    console.note(f"Stdout log: {payload['stdout_log']}")
    console.note(f"Stderr log: {payload['stderr_log']}")


def collect_service_status(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: Launchd,
) -> JsonObject:
    """Collect local connector lifecycle state without rendering."""

    manifest = load_manifest(paths.state_file)
    manager: JsonObject | None = None
    if manifest is not None:
        manager = {
            "account_id": manifest.manager.account_id,
            "account_name": manifest.manager.account_name,
            "zone_name": manifest.manager.zone_name,
            "tunnel_id": manifest.manager.tunnel_id,
            "tunnel_name": manifest.manager.tunnel_name,
            "publication_count": len(manifest.publications),
        }
    return {
        "manager": manager,
        "state_file": _file_state(paths.state_file),
        "launch_agent_file": _file_state(paths.canonical_launch_agent_file),
        "launch_agent_loaded": _launch_agent_loaded_state(launchd),
        "launch_agent_process": _launch_agent_process_state(launchd),
        "launchd_service_target": paths.service_target,
        "tunnel_token_file": _file_state(paths.tunnel_token_file),
        "launch_agent_binary": _launch_agent_binary_state(paths, cloudflared),
        "stdout_log": _file_state(paths.stdout_log_file),
        "stderr_log": _file_state(paths.stderr_log_file),
    }


def run_service_start(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: Launchd,
    console: Console,
) -> None:
    """Load and kickstart the existing canonical launch agent."""

    _ = require_manifest(paths)
    _require_startable_connector(paths=paths, cloudflared=cloudflared, launchd=launchd)
    console.section("Service Start")
    service = launchd.service(CANONICAL_LABEL)
    if service is not None and service.running:
        console.note(f"Connector already running: {paths.service_target}")
        return
    if service is None:
        launchd.bootstrap(paths.canonical_launch_agent_file)
    launchd.kickstart(CANONICAL_LABEL)
    console.note(f"Connector kickstarted: {paths.service_target}")


def run_service_stop(*, paths: AppPaths, launchd: Launchd, console: Console) -> None:
    """Unload the canonical launch agent without deleting manager state."""

    console.section("Service Stop")
    if not launchd.is_loaded(CANONICAL_LABEL):
        console.note(f"Connector is not loaded: {paths.service_target}")
        return
    launchd.bootout(CANONICAL_LABEL)
    if launchd.is_loaded(CANONICAL_LABEL):
        raise AppError("Connector is still loaded after launchctl bootout.")
    console.note(f"Connector unloaded: {paths.service_target}")


def run_service_restart(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: Launchd,
    console: Console,
) -> None:
    """Kickstart the loaded canonical launch agent."""

    _ = require_manifest(paths)
    _require_startable_connector(paths=paths, cloudflared=cloudflared, launchd=launchd)
    console.section("Service Restart")
    if not launchd.is_loaded(CANONICAL_LABEL):
        raise AppError(
            "Connector is not loaded.",
            hints=("Run `cloudflare-publish service start` first.",),
        )
    launchd.kickstart(CANONICAL_LABEL)
    console.note(f"Connector kickstarted: {paths.service_target}")


def run_service_logs(*, paths: AppPaths, lines: int, console: Console) -> None:
    """Print recent connector stdout and stderr log lines."""

    _require_log_line_count(lines)
    console.section("Service Logs")
    _show_recent_log(path=paths.stdout_log_file, label="stdout", lines=lines, console=console)
    _show_recent_log(path=paths.stderr_log_file, label="stderr", lines=lines, console=console)


def _show_manager_status(
    *,
    console: Console,
    manifest: StateManifest | None,
    paths: AppPaths,
) -> None:
    """Render manager state summary for service status."""

    console.note(f"State file: {_file_state(paths.state_file)}")
    if manifest is None:
        console.note("Manager: not bootstrapped")
        return
    show_manifest_summary(console, manifest)
    console.note(f"Updated at: {manifest.updated_at}")


def _require_startable_connector(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: Launchd,
) -> None:
    """Require local files needed to load the existing connector."""

    if not paths.canonical_launch_agent_file.exists():
        raise AppError(
            "Canonical launch agent file is missing.",
            hints=("Run `cloudflare-publish setup` to render and load it.",),
        )
    if not paths.tunnel_token_file.exists():
        raise AppError(
            "Tunnel token file is missing.",
            hints=("Run `cloudflare-publish setup` to refresh local manager state.",),
        )
    launchd.validate_plist(paths.canonical_launch_agent_file)
    contract = _launch_agent_contract(paths.canonical_launch_agent_file)
    _require_canonical_launch_agent(contract=contract, paths=paths)
    _ = cloudflared.require_token_file_support_for_binary(contract.binary)


def _launch_agent_binary_state(paths: AppPaths, cloudflared: Cloudflared) -> str:
    """Return a compact status for the launch-agent binary."""

    try:
        binary = _launch_agent_binary(paths.canonical_launch_agent_file)
        info = cloudflared.version_info_for_binary(binary)
    except AppError as error:
        return error.message
    suffix = "supports --token-file" if info.supports_token_file else "too old for --token-file"
    return f"{binary}: {info.raw} ({suffix})"


def _launch_agent_binary(plist_file: Path) -> Path:
    """Return the cloudflared binary encoded in the canonical launch-agent plist."""

    return _launch_agent_contract(plist_file).binary


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


def _launch_agent_loaded_state(launchd: Launchd) -> str:
    """Render loaded state without making status brittle."""

    try:
        return _yes_no(launchd.is_loaded(CANONICAL_LABEL))
    except AppError as error:
        return f"unknown ({error.message})"


def _launch_agent_process_state(launchd: Launchd) -> str:
    """Render process health without making status brittle."""

    try:
        service = launchd.service(CANONICAL_LABEL)
    except AppError as error:
        return f"unknown ({error.message})"
    if service is None:
        return "not loaded"
    if service.running:
        return f"running pid {service.pid}"
    if service.status is None:
        return "loaded but not running"
    return f"loaded but not running; last status {service.status}"


def _show_recent_log(*, path: Path, label: str, lines: int, console: Console) -> None:
    """Render a recent tail for one log file."""

    console.note(f"{label}: {path}")
    if not path.exists():
        console.note("missing")
        return
    recent_lines = _tail_lines(path, lines)
    if not recent_lines:
        console.note("empty")
        return
    for line in recent_lines:
        console.line(f"{label}> {line}")


def _tail_lines(path: Path, lines: int) -> tuple[str, ...]:
    """Return at most the last N lines from a text file."""

    recent: deque[str] = deque(maxlen=lines)
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            recent.append(raw_line.rstrip("\n"))
    return tuple(recent)


def _file_state(path: Path) -> str:
    """Render existence and path for one local file."""

    state = "present" if path.exists() else "missing"
    return f"{state} ({path})"


def _yes_no(value: bool) -> str:
    """Render a bool as an operator-facing yes/no value."""

    return "yes" if value else "no"


def _require_log_line_count(lines: int) -> None:
    """Reject unreasonable log-tail counts."""

    if 1 <= lines <= 1000:
        return
    raise AppError("Log line count must be between 1 and 1000.")
