"""High-impact CLI confirmation and mutation coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_setup_takeover_requires_confirmation(fake_environment: FakeEnvironment) -> None:
    """Setup takeover refuses to mutate conflicting local state without --yes."""

    fake_environment.install_conflicting_local_state()

    assert (
        main(
            [
                "setup",
                "--takeover",
                "--api-token",
                "token-1",
                "--account-id",
                "acc-123",
                "--zone",
                "example.com",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 1
    )
    assert (fake_environment.home / ".cloudflared" / "config.yml").exists()


def test_tunnel_recover_rewrites_token_and_disconnects_connectors(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Tunnel recovery refreshes the token, restarts the agent, and disconnects all connectors."""

    assert _setup(fake_environment) == 0
    token_file = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "tunnel-token.txt"
    )
    assert token_file.read_text(encoding="utf-8").strip() == "token-tunnel-1"
    assert main(["tunnel", "recover", "apply", "--yes"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Disconnected every connector on the shared tunnel." in captured.out
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["cleaned_tunnel_ids"] == ["tunnel-1"]
    assert token_file.read_text(encoding="utf-8").strip() == "token-tunnel-1"


def test_tunnel_recover_requires_confirmation(fake_environment: FakeEnvironment) -> None:
    """Tunnel recovery rejects live mutation without --yes."""

    assert _setup(fake_environment) == 0
    assert main(["tunnel", "recover", "apply"], repo_root=fake_environment.repo_root) == 1
    assert fake_environment.cleaned_tunnel_ids() == ()


def test_tunnel_recover_requires_manager_state_after_confirmation(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Confirmed tunnel recovery fails cleanly when the manager is not bootstrapped."""

    assert main(["tunnel", "recover", "apply", "--yes"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Manager state is missing" in captured.err


def test_tunnel_recover_prefers_missing_manager_state_over_tool_checks(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Confirmed tunnel recovery reports missing manager state before local tool drift."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflared_version"] = "cloudflared version 2025.3.9"
    _write_tool_state(fake_environment, tool_state)

    assert main(["tunnel", "recover", "apply", "--yes"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Manager state is missing" in captured.err
    assert "2025.4.0 or later is required" not in captured.err


def test_token_rotate_and_guard_apply_require_confirmation(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Token rotation and guard apply mutate only after explicit confirmation."""

    assert _setup(fake_environment) == 0
    assert _publish_machine(fake_environment) == 0
    publication_state = json.loads(_state_path(fake_environment).read_text(encoding="utf-8"))[
        "publications"
    ]["grafana"]["state"]
    keychain_key = f"cloudflare-publish:{publication_state['service_token_keychain_account']}"
    before_secret = fake_environment.tool_state()["keychain"][keychain_key]
    assert main(["token", "rotate", "grafana"], repo_root=fake_environment.repo_root) == 1
    assert fake_environment.tool_state()["keychain"][keychain_key] == before_secret
    assert main(["token", "rotate", "grafana", "--yes"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Client ID: client-token-1" in captured.out
    assert "Client secret: secret-2" in captured.out
    rotated_state = json.loads(_state_path(fake_environment).read_text(encoding="utf-8"))[
        "publications"
    ]["grafana"]["state"]
    rotated_key = f"cloudflare-publish:{rotated_state['service_token_keychain_account']}"
    after_secret = fake_environment.tool_state()["keychain"][rotated_key]
    assert before_secret != after_secret
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["organization"]["deny_unmatched_requests_exempted_zone_names"] = [
        "public.example.com"
    ]
    _write_tool_state(fake_environment, tool_state)
    assert main(["guard", "apply"], repo_root=fake_environment.repo_root) == 1
    assert main(["guard", "apply", "--yes"], repo_root=fake_environment.repo_root) == 0
    assert (
        fake_environment.tool_state()["cloudflare"]["organization"]["deny_unmatched_requests"]
        is True
    )
    assert fake_environment.tool_state()["cloudflare"]["organization"][
        "deny_unmatched_requests_exempted_zone_names"
    ] == ["public.example.com"]


def test_teardown_removes_manager_and_remote_state(fake_environment: FakeEnvironment) -> None:
    """Teardown removes managed resources and local state only after --yes."""

    assert _setup(fake_environment) == 0
    assert _publish_machine(fake_environment) == 0
    assert main(["teardown"], repo_root=fake_environment.repo_root) == 1
    assert _state_path(fake_environment).exists()
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 0
    assert not _state_path(fake_environment).exists()
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["tunnels"] == {}
    assert tool_state["cloudflare"]["dns_records"] == {}


def test_guard_cannot_break_a_managed_public_publication(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Guard plan and apply fail before mutation while a public route needs no Access app."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "video-ingress",
                "--yes",
                "--hostname",
                "video-ingress.example.com",
                "--to",
                "http://127.0.0.1:4751",
                "--audience",
                "public",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["guard", "plan"], repo_root=fake_environment.repo_root) == 1
    assert main(["guard", "apply", "--yes"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Require-protection would block managed public publications" in captured.err
    assert (
        fake_environment.tool_state()["cloudflare"]["organization"]["deny_unmatched_requests"]
        is False
    )

    assert main(["--json", "guard", "status"], repo_root=fake_environment.repo_root) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["organization"]["guard_blocked_by_publications"] == ["video-ingress"]


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


def _publish_machine(fake_environment: FakeEnvironment) -> int:
    """Publish the common machine-only fixture."""

    return main(
        [
            "publish",
            "apply",
            "grafana",
            "--yes",
            "--hostname",
            "grafana.example.com",
            "--to",
            "http://127.0.0.1:3000",
            "--audience",
            "machine",
        ],
        repo_root=fake_environment.repo_root,
    )


def _state_path(fake_environment: FakeEnvironment) -> Path:
    """Return the manager state path."""

    return (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )


def _write_tool_state(fake_environment: FakeEnvironment, state: dict[str, object]) -> None:
    """Persist fake-binary state mutations for one test."""

    fake_environment.state_file.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
