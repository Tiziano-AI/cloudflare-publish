"""Local native user-service connector lifecycle workflows."""

from __future__ import annotations

from collections import deque
from pathlib import Path

from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.models import AppPaths, StateManifest
from cloudflare_publish.state import load_manifest
from cloudflare_publish.workflow_support import require_manifest, show_manifest_summary

DEFAULT_LOG_LINES = 80


def run_service_status(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    console: Console,
) -> None:
    """Render local connector lifecycle state without mutating local or remote resources."""

    payload = collect_service_status(paths=paths, cloudflared=cloudflared, launchd=launchd)
    console.section("Service Status")
    manifest = load_manifest(paths.state_file)
    _show_manager_status(console=console, manifest=manifest, paths=paths)
    if paths.host_platform == "darwin":
        console.note(f"Launch agent file: {payload['launch_agent_file']}")
        console.note(f"Launch agent loaded: {payload['launch_agent_loaded']}")
        console.note(f"Launch agent process: {payload['launch_agent_process']}")
        console.note(f"Launchd service target: {payload['launchd_service_target']}")
        console.note(f"Launch agent binary: {payload['launch_agent_binary']}")
    else:
        console.note(f"User unit file: {payload['service_file']}")
        console.note(f"Unit enabled or active: {payload['service_enabled_or_active']}")
        console.note(f"Unit process: {payload['service_process']}")
        console.note(f"Systemd user service target: {payload['systemd_user_service_target']}")
        console.note(f"Unit binary: {payload['service_binary']}")
    console.note(f"Tunnel token file: {payload['tunnel_token_file']}")
    console.note(f"Stdout log: {payload['stdout_log']}")
    console.note(f"Stderr log: {payload['stderr_log']}")


def collect_service_status(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
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
    payload: JsonObject = {
        "manager": manager,
        "state_file": _file_state(paths.state_file),
        "tunnel_token_file": _file_state(paths.tunnel_token_file),
        "stdout_log": _file_state(paths.stdout_log_file),
        "stderr_log": _file_state(paths.stderr_log_file),
    }
    if paths.host_platform == "darwin":
        payload.update(
            {
                "launch_agent_file": _file_state(paths.service_file),
                "launch_agent_loaded": _connector_registered_state(launchd),
                "launch_agent_process": _connector_process_state(launchd),
                "launchd_service_target": paths.service_target,
                "launch_agent_binary": _connector_binary_state(cloudflared, launchd),
            }
        )
    else:
        payload.update(
            {
                "service_file": _file_state(paths.service_file),
                "service_enabled_or_active": _connector_registered_state(launchd),
                "service_process": _connector_process_state(launchd),
                "systemd_user_service_target": paths.service_target,
                "service_binary": _connector_binary_state(cloudflared, launchd),
            }
        )
    return payload


def run_service_start(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    console: Console,
) -> None:
    """Start the existing canonical native user connector."""

    _ = require_manifest(paths)
    _require_startable_connector(paths=paths, cloudflared=cloudflared, launchd=launchd)
    console.section("Service Start")
    service = launchd.service()
    if service is not None and service.running:
        console.note(f"Connector already running: {paths.service_target}")
        return
    launchd.start()
    console.note(f"Connector started: {paths.service_target}")


def run_service_stop(*, paths: AppPaths, launchd: ConnectorService, console: Console) -> None:
    """Stop the native user connector without deleting manager state."""

    console.section("Service Stop")
    if not launchd.is_loaded():
        console.note(f"Connector is already stopped: {paths.service_target}")
        return
    launchd.stop()
    if launchd.is_loaded():
        raise AppError("Connector is still active after native service stop.")
    console.note(f"Connector stopped: {paths.service_target}")


def run_service_restart(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    console: Console,
) -> None:
    """Restart the existing registered native user connector."""

    _ = require_manifest(paths)
    _require_startable_connector(paths=paths, cloudflared=cloudflared, launchd=launchd)
    console.section("Service Restart")
    if not launchd.is_loaded():
        raise AppError(
            "Connector is not loaded."
            if launchd.platform == "darwin"
            else "Connector is not enabled or active.",
            hints=("Run `cloudflare-publish service start` first.",),
        )
    launchd.restart()
    console.note(f"Connector restarted: {paths.service_target}")


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
    launchd: ConnectorService,
) -> None:
    """Require local files needed to load the existing connector."""

    if not paths.service_file.exists():
        raise AppError(
            "Canonical launch agent file is missing."
            if paths.host_platform == "darwin"
            else "Canonical user unit file is missing.",
            hints=("Run `cloudflare-publish setup` to render and load it.",),
        )
    if not paths.tunnel_token_file.exists():
        raise AppError(
            "Tunnel token file is missing.",
            hints=("Run `cloudflare-publish setup` to refresh local manager state.",),
        )
    launchd.preflight()
    binary = launchd.validate_definition()
    _ = cloudflared.require_security_minimum_for_binary(binary)


def _connector_binary_state(cloudflared: Cloudflared, launchd: ConnectorService) -> str:
    """Return a compact status for the native connector binary."""

    try:
        binary = launchd.validate_definition()
        info = cloudflared.version_info_for_binary(binary)
    except AppError as error:
        return error.message
    suffix = (
        "meets security minimum"
        if info.meets_security_minimum
        else f"below security minimum {info.minimum_text}"
    )
    return f"{binary}: {info.raw} ({suffix})"


def _connector_registered_state(launchd: ConnectorService) -> str:
    """Render native registration state without making status brittle."""

    try:
        return _yes_no(launchd.is_loaded())
    except AppError as error:
        return f"unknown ({error.message})"


def _connector_process_state(launchd: ConnectorService) -> str:
    """Render process health without making status brittle."""

    try:
        service = launchd.service()
    except AppError as error:
        return f"unknown ({error.message})"
    if service is None:
        return "not loaded" if launchd.platform == "darwin" else "disabled and inactive"
    if service.running:
        return f"running pid {service.pid}"
    if service.status is None:
        return "registered but not running"
    prefix = "loaded" if launchd.platform == "darwin" else "enabled or active"
    return f"{prefix} but not running; last status {service.status}"


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
