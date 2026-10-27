"""Service lifecycle coverage for the cloudflare-publish CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_service_status_is_safe_before_setup(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service status reports local lifecycle state without requiring manager bootstrap."""

    assert main(["service", "status"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "State file: missing" in captured.out
    assert "Manager: not bootstrapped" in captured.out
    assert "Launch agent loaded: no" in captured.out


def test_service_start_stop_restart_use_existing_launch_agent(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service lifecycle commands own local launchd state without touching remote resources."""

    assert _setup(fake_environment) == 0
    assert "com.cloudflare-publish.cloudflared" in fake_environment.launchd_labels()

    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 0
    assert "com.cloudflare-publish.cloudflared" not in fake_environment.launchd_labels()

    assert main(["service", "start"], repo_root=fake_environment.repo_root) == 0
    assert "com.cloudflare-publish.cloudflared" in fake_environment.launchd_labels()

    assert main(["service", "restart"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Connector restarted" in captured.out
    assert fake_environment.cleaned_tunnel_ids() == ()


def test_service_start_kickstarts_loaded_but_crashed_connector(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service start repairs a loaded launchd label whose process is not running."""

    assert _setup(fake_environment) == 0
    before = fake_environment.kickstart_count()
    fake_environment.crash_launchd_label("com.cloudflare-publish.cloudflared", status=78)

    assert main(["service", "start"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Connector started" in captured.out
    assert fake_environment.kickstart_count() == before + 1


def test_service_stop_fails_when_launchctl_bootout_fails(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service stop must not claim success after a launchctl bootout failure."""

    assert _setup(fake_environment) == 0
    fake_environment.fail_next_bootout()

    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Command failed: launchctl bootout" in captured.err
    assert "com.cloudflare-publish.cloudflared" in fake_environment.launchd_labels()


def test_service_start_requires_existing_connector_files(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service start fails closed when setup has not rendered a launch-agent plist."""

    assert _setup(fake_environment) == 0
    _canonical_launch_agent(fake_environment).unlink()

    assert main(["service", "start"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Canonical launch agent file is missing" in captured.err


def test_service_start_requires_launch_agent_binary(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service start fails before launchd load when the encoded connector binary is gone."""

    assert _setup(fake_environment) == 0
    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 0
    (fake_environment.bin_dir / "cloudflared").unlink()

    assert main(["service", "start"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "cloudflared binary is missing" in captured.err
    assert "com.cloudflare-publish.cloudflared" not in fake_environment.launchd_labels()


@pytest.mark.parametrize("command", ["start", "restart"])
def test_service_start_rejects_downgraded_launch_agent_binary(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    """Start/restart check the encoded binary's security floor before loading it."""

    assert _setup(fake_environment) == 0
    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 0
    fake_environment.set_cloudflared_version("cloudflared version 2026.10.2")

    assert main(["service", command], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "2026.10.3 or later is required" in captured.err
    assert "com.cloudflare-publish.cloudflared" not in fake_environment.launchd_labels()


def test_service_start_rejects_noncanonical_launch_agent_label(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service start rejects a valid plist that does not encode the canonical label."""

    assert _setup(fake_environment) == 0
    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 0
    path = _canonical_launch_agent(fake_environment)
    text = path.read_text(encoding="utf-8").replace(
        "com.cloudflare-publish.cloudflared",
        "com.cloudflare-publish.tampered",
    )
    _ = path.write_text(text, encoding="utf-8")

    assert main(["service", "start"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "wrong label" in captured.err
    assert "com.cloudflare-publish.tampered" not in fake_environment.launchd_labels()


def test_service_start_rejects_wrong_token_file_argument(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service start rejects a valid plist that points at the wrong token file."""

    assert _setup(fake_environment) == 0
    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 0
    path = _canonical_launch_agent(fake_environment)
    text = path.read_text(encoding="utf-8").replace("tunnel-token.txt", "other-token.txt")
    _ = path.write_text(text, encoding="utf-8")

    assert main(["service", "start"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "ProgramArguments do not match manager state" in captured.err


def test_service_restart_requires_loaded_connector(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service restart fails closed instead of silently starting an unloaded connector."""

    assert _setup(fake_environment) == 0
    assert main(["service", "stop"], repo_root=fake_environment.repo_root) == 0

    assert main(["service", "restart"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Connector is not loaded" in captured.err


def test_service_logs_print_recent_connector_logs(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service logs prints a bounded recent tail of stdout and stderr."""

    logs_dir = fake_environment.home / "Library" / "Logs" / "cloudflare-publish"
    logs_dir.mkdir(parents=True)
    _ = (logs_dir / "cloudflared.out.log").write_text(
        "out-1\nout-2\nout-3\n",
        encoding="utf-8",
    )
    _ = (logs_dir / "cloudflared.err.log").write_text(
        "err-1\nerr-2\nerr-3\n",
        encoding="utf-8",
    )

    assert main(["service", "logs", "--lines", "2"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "stdout> out-1" not in captured.out
    assert "stdout> out-2" in captured.out
    assert "stderr> err-3" in captured.out


def test_service_logs_reject_unbounded_line_counts(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service logs keeps the operator action bounded."""

    assert main(["service", "logs", "--lines", "0"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Log line count must be between 1 and 1000" in captured.err


def _setup(fake_environment: FakeEnvironment) -> int:
    """Run the common initial manager setup."""

    return main(
        [
            "setup",
            "--api-token",
            "token-1",
            "--account-id",
            "acc-123",
            "--zone",
            "example.com",
        ],
        repo_root=fake_environment.repo_root,
    )


def _canonical_launch_agent(fake_environment: FakeEnvironment) -> Path:
    """Return the canonical fake launch-agent file path."""

    return (
        fake_environment.home
        / "Library"
        / "LaunchAgents"
        / "com.cloudflare-publish.cloudflared.plist"
    )
