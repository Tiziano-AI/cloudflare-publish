"""Offline diagnostic behavior under secret-bearing and incomplete local drift."""

from __future__ import annotations

import json
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Literal

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "cloudflare-publish"
    / "scripts"
    / "inspect-manager.sh"
)


def _inspect(
    tmp_path: Path,
    *,
    agent: bytes | None = None,
    state: str | None = None,
    python_mode: Literal["available", "missing", "unusable"] = "available",
    platform: str = "Darwin",
    service_metadata: str = "Id=cloudflare-publish.service\nActiveState=active\nMainPID=123\n",
    user_bus_available: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run against synthetic files and commands, never a host's real user service."""

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    linux = platform == "Linux"
    if agent is not None:
        agent_dir = (
            user_dir / ".config" / "systemd" / "user"
            if linux
            else user_dir / "Library" / "LaunchAgents"
        )
        agent_dir.mkdir(parents=True)
        filename = (
            "cloudflare-publish.service" if linux else "com.cloudflare-publish.cloudflared.plist"
        )
        (agent_dir / filename).write_bytes(agent)
    if state is not None:
        state_dir = (
            user_dir / ".local" / "state" / "cloudflare-publish"
            if linux
            else user_dir / "Library" / "Application Support" / "cloudflare-publish"
        )
        state_dir.mkdir(parents=True)
        (state_dir / "state.json").write_text(state, encoding="utf-8")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for command in ("awk", "ls", "head"):
        executable = shutil.which(command)
        assert executable is not None
        (binaries / command).symlink_to(executable)
    cli = binaries / "cloudflare-publish"
    cli.write_text(f'#!{sys.executable}\nprint("cloudflare-publish fixture")\n', encoding="utf-8")
    cli.chmod(0o755)
    if python_mode == "available":
        (binaries / "python3").symlink_to(sys.executable)
    elif python_mode == "unusable":
        interpreter = binaries / "python3"
        interpreter.write_text(
            '#!/bin/sh\nprintf "invoked\\n" >> "$HOME/python-preflight"\n'
            'printf "unexpected-python-output\\n" >&2\nexit 127\n',
            encoding="utf-8",
        )
        interpreter.chmod(0o755)
    launcher = binaries / "launchctl"
    launcher.write_text(
        "#!/bin/sh\nprintf '123\\t0\\tcom.cloudflare-publish.cloudflared\\n'\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    for command, body in {
        "uname": f"print({platform!r})",
        "id": "print('123')",
        "loginctl": "print('yes')",
        "systemctl": (
            "import sys\n"
            "assert sys.argv[1:] == ['--user', 'show', 'cloudflare-publish.service', "
            "'--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID']\n"
            f"print({service_metadata!r})\n"
            f"sys.exit({0 if user_bus_available else 1})"
        ),
    }.items():
        tool = binaries / command
        tool.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
        tool.chmod(0o755)
    return subprocess.run(
        ["/bin/bash", str(SCRIPT)],
        check=False,
        capture_output=True,
        cwd=tmp_path,
        env={
            "HOME": str(user_dir),
            "PATH": str(binaries),
        },
        text=True,
    )


@pytest.mark.parametrize("python_mode", ["missing", "unusable"])
def test_diagnostic_needs_no_path_python_for_working_cli(
    tmp_path: Path, python_mode: Literal["missing", "unusable"]
) -> None:
    """A uv-style CLI has its own interpreter; optional parsing must not add an install step."""

    completed = _inspect(
        tmp_path,
        python_mode=python_mode,
        agent=plistlib.dumps({"ProgramArguments": ["--token=private-agent-secret"]}),
        state='{"manager": {"api_token": "private-state-secret"}}',
    )
    cli = tmp_path / "bin" / "cloudflare-publish"
    cli_check = subprocess.run(
        [str(cli), "--version"],
        capture_output=True,
        check=False,
        env={"HOME": str(tmp_path / "user"), "PATH": str(cli.parent)},
        text=True,
    )
    assert cli_check.returncode == 0
    assert cli_check.stdout == "cloudflare-publish fixture\n"
    assert completed.returncode == 0, completed.stderr
    assert str(cli) in completed.stdout
    assert "metadata-only diagnosis remains available" in completed.stdout
    assert "launch_agent_parse=skipped" in completed.stdout
    assert "state_parse=skipped" in completed.stdout
    assert "123\t0\tcom.cloudflare-publish.cloudflared" in completed.stdout
    assert "state.json" in completed.stdout
    for secret in ("private-agent-secret", "private-state-secret", "unexpected-python-output"):
        assert secret not in completed.stdout + completed.stderr
    preflight = tmp_path / "user" / "python-preflight"
    if python_mode == "unusable":
        assert preflight.read_text() == "invoked\n"
    else:
        assert not preflight.exists()


@pytest.mark.parametrize("inline_form", [["--token", "inline-secret"], ["--token=inline-secret"]])
def test_diagnostic_withholds_noncanonical_plist_secrets(
    tmp_path: Path, inline_form: list[str]
) -> None:
    """Inspection must not trust stale launch arguments or environment as safe to print."""

    completed = _inspect(
        tmp_path,
        agent=plistlib.dumps(
            {
                "Label": "com.cloudflare-publish.cloudflared",
                "ProgramArguments": ["/opt/homebrew/bin/cloudflared", "tunnel", *inline_form],
                "EnvironmentVariables": {"CLOUDFLARE_API_TOKEN": "environment-secret"},
                "Unexpected": {"Secret": "unknown-field-secret"},
            }
        ),
    )
    assert completed.returncode == 0, completed.stderr
    assert "launch_agent_binary='/opt/homebrew/bin/cloudflared'" in completed.stdout
    assert "launch_agent_token_file_expected=False" in completed.stdout
    assert "launch_agent_inline_token_present=True" in completed.stdout
    assert "launch_agent_environment_present=True" in completed.stdout
    for secret in ("inline-secret", "environment-secret", "unknown-field-secret"):
        assert secret not in completed.stdout + completed.stderr


def test_diagnostic_identifies_expected_token_file_without_reading_it(tmp_path: Path) -> None:
    """Canonical command-shape evidence needs neither the token file nor its contents."""

    token_path = (
        tmp_path
        / "user"
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "tunnel-token.txt"
    )
    completed = _inspect(
        tmp_path,
        agent=plistlib.dumps(
            {
                "Label": "com.cloudflare-publish.cloudflared",
                "ProgramArguments": [
                    "/opt/homebrew/bin/cloudflared",
                    "tunnel",
                    "run",
                    "--token-file",
                    str(token_path),
                ],
            }
        ),
    )
    assert completed.returncode == 0, completed.stderr
    assert not token_path.exists()
    assert "launch_agent_label_expected=True" in completed.stdout
    assert "launch_agent_token_file_expected=True" in completed.stdout
    assert "launch_agent_inline_token_present=False" in completed.stdout


@pytest.mark.parametrize(
    "agent",
    [
        b"not a plist containing secret-invalid-data",
        b"<?xml version='1.0'?><plist><dict><key>secret-invalid-data</key>",
        plistlib.dumps(["secret-invalid-data"]),
        plistlib.dumps({"ProgramArguments": {"Secret": "secret-invalid-data"}}),
    ],
)
def test_diagnostic_handles_malformed_plist_without_dumping_it(
    tmp_path: Path, agent: bytes
) -> None:
    """A recovery diagnostic remains useful when the local plist is not canonical."""

    completed = _inspect(tmp_path, agent=agent)
    assert completed.returncode == 0, completed.stderr
    assert "contents withheld" in completed.stdout
    assert "secret-invalid-data" not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr


@pytest.mark.parametrize("python_mode", ["available", "missing", "unusable"])
def test_linux_diagnostic_is_metadata_only_and_withholds_drift(
    tmp_path: Path, python_mode: Literal["available", "missing", "unusable"]
) -> None:
    """Unknown unit/manager payloads cannot turn the inspector into a secret dump."""

    completed = _inspect(
        tmp_path,
        platform="Linux",
        python_mode=python_mode,
        agent=b"[Service]\nExecStart=/bin/tool --token=inline-secret\nEnvironment=api-secret\n",
        state='{"manager":{"api_token":"state-secret"},"publications":{}}',
        service_metadata=(
            "Id=unexpected-secret\nLoadState=loaded\nActiveState=active\n"
            "SubState=running\nUnitFileState=enabled\nMainPID=123\n"
            "Environment=unexpected-secret\nExecStart=unexpected-secret\n"
            "LoadState=unexpected-secret\nMainPID=unexpected-secret\n"
        ),
    )
    assert completed.returncode == 0, completed.stderr
    assert "unit_identity_expected=0" in completed.stdout
    assert "ActiveState=active" in completed.stdout
    assert "LoadState=unknown; contents withheld" in completed.stdout
    assert "MainPID=invalid; withheld" in completed.stdout
    assert "user_linger=yes" in completed.stdout
    assert ".config/systemd/user/cloudflare-publish.service" in completed.stdout
    assert "launch agent" not in completed.stdout
    for secret in ("inline-secret", "api-secret", "state-secret", "unexpected-secret"):
        assert secret not in completed.stdout + completed.stderr


def test_linux_diagnostic_reports_missing_user_bus_without_service_effects(tmp_path: Path) -> None:
    """Failure to read the user manager is a gap, not an invitation to start one."""

    completed = _inspect(tmp_path, platform="Linux", user_bus_available=False)
    assert completed.returncode == 0, completed.stderr
    assert "user_manager_metadata=unavailable" in completed.stdout
    assert "user unit missing" in completed.stdout
    assert "MainPID=" not in completed.stdout


def test_diagnostic_rejects_unsupported_platform_before_inspection(tmp_path: Path) -> None:
    """Do not accidentally inspect Mac or Linux state on another host."""

    completed = _inspect(tmp_path, platform="FreeBSD")
    assert completed.returncode == 1
    assert completed.stdout == "unsupported host platform; no manager files or services inspected\n"
    assert not completed.stderr


def test_diagnostic_describes_ssh_without_http_readiness_claims(tmp_path: Path) -> None:
    """SSH pins and signed-key-exchange scope are distinct from HTTP and origin TLS."""

    completed = _inspect(
        tmp_path,
        state=json.dumps(
            {
                "manager": None,
                "pending": {"kind": "setup", "phase": "started", "request": {"token": "secret"}},
                "publications": {
                    "mac": {
                        "spec": {
                            "kind": "ssh_public",
                            "hostname": "mac.example.com",
                            "audience": "machine",
                            "origin_url": "ssh://127.0.0.1:22",
                            "ssh_host_key": "ssh-ed25519 synthetic-public-key",
                        },
                        "state": {"service_token_client_secret": "secret"},
                    }
                },
            }
        ),
    )
    assert completed.returncode == 0, completed.stderr
    assert "manager_present: False" in completed.stdout
    assert "pending_transition_present: True" in completed.stdout
    assert "pending_kind: setup" in completed.stdout
    assert (
        "kind=ssh_public hostname=mac.example.com audience=machine origin=ssh://127.0.0.1:22"
    ) in completed.stdout
    assert "ssh_host_key_pin_configured=True" in completed.stdout
    assert "ssh_verification_scope=pinned signed key exchange (not performed)" in completed.stdout
    for inappropriate in ("public_verify_url", "verify_path", "origin_tls_verification", "secret"):
        assert inappropriate not in completed.stdout + completed.stderr


@pytest.mark.parametrize(
    "state",
    [
        '{"manager": {"secret-invalid-data":',
        '["secret-invalid-data"]',
        '{"manager": null, "publications": {"mac": null}}',
        '{"manager": null, "publications": null}',
        '{"publications": {"mac": {"spec": {"origin_url": "https://user:secret-invalid-data@example.com"}}}}',
    ],
)
def test_diagnostic_handles_incomplete_state_without_disclosing_payload(
    tmp_path: Path, state: str
) -> None:
    """Pending or broken local state must not crash or expose parse payloads."""

    completed = _inspect(tmp_path, state=state)
    assert completed.returncode == 0, completed.stderr
    assert "secret-invalid-data" not in completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr
