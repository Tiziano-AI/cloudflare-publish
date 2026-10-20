"""Hermetic integration coverage for the cloudflare-publish CLI."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_setup_requires_takeover_for_conflicting_local_state(
    fake_environment: FakeEnvironment,
) -> None:
    """Setup fails closed when conflicting local `cloudflared` state is present."""

    fake_environment.install_conflicting_local_state()
    exit_code = main(
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
    assert exit_code == 1
    assert not (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    ).exists()


def test_setup_takeover_bootstraps_manager(fake_environment: FakeEnvironment) -> None:
    """Takeover backs up conflicting local files and installs the new manager."""

    fake_environment.install_conflicting_local_state()
    exit_code = main(
        [
            "setup",
            "--takeover",
            "--yes",
            "--api-token",
            "token-1",
            "--account-id",
            "acc-123",
            "--zone",
            "example.com",
        ],
        repo_root=fake_environment.repo_root,
    )
    assert exit_code == 0
    state_file = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )
    manifest = json.loads(state_file.read_text(encoding="utf-8"))
    assert manifest["manager"]["account_id"] == "acc-123"
    assert manifest["manager"]["zone_name"] == "example.com"
    assert manifest["backups"]
    assert manifest["backups"][0]["copied_paths"]
    assert not (fake_environment.home / ".cloudflared" / "config.yml").exists()
    assert not (
        fake_environment.home / "Library" / "LaunchAgents" / "com.cloudflare.cloudflared.plist"
    ).exists()
    assert (
        fake_environment.home
        / "Library"
        / "LaunchAgents"
        / "com.cloudflare-publish.cloudflared.plist"
    ).exists()
    tunnel_id = manifest["manager"]["tunnel_id"]
    assert fake_environment.tool_state()["cloudflare"]["tunnel_configurations"][tunnel_id] == {
        "config": {"ingress": [{"service": "http_status:404"}]},
        "version": 1,
    }
    assert "token-1" not in fake_environment.last_security_argv()


def test_setup_install_deps_uses_brew_when_cloudflared_is_missing(
    fake_environment: FakeEnvironment,
) -> None:
    """Setup installs cloudflared through fake Homebrew when requested."""

    (fake_environment.bin_dir / "cloudflared").unlink()
    exit_code = main(
        [
            "setup",
            "--install-deps",
            "--api-token",
            "token-1",
            "--account-id",
            "acc-123",
            "--zone",
            "example.com",
        ],
        repo_root=fake_environment.repo_root,
    )
    assert exit_code == 0
    assert fake_environment.tool_state()["brew_calls"] == 1


def test_setup_persists_manifest_before_launch_agent_bootstrap(
    fake_environment: FakeEnvironment,
) -> None:
    """A bootstrap failure leaves enough local state for a clean setup rerun."""

    tool_state = fake_environment.tool_state()
    tool_state["launchctl_fail_bootstrap_once"] = True
    _write_tool_state(fake_environment, tool_state)

    first_exit = _setup(fake_environment)
    assert first_exit == 1
    manifest = _load_manifest(fake_environment)
    assert manifest["manager"]["tunnel_id"] == "tunnel-1"
    assert _setup(fake_environment) == 0


def test_setup_persists_manifest_before_tunnel_config_push(
    fake_environment: FakeEnvironment,
) -> None:
    """A tunnel-config failure leaves enough local state for a clean setup rerun."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["fail_tunnel_config_put_once"] = True
    _write_tool_state(fake_environment, tool_state)

    first_exit = _setup(fake_environment)
    assert first_exit == 1
    manifest = _load_manifest(fake_environment)
    assert manifest["manager"]["tunnel_id"] == "tunnel-1"
    assert _setup(fake_environment) == 0


def test_setup_refresh_rejects_empty_foreign_tunnel_configuration(
    fake_environment: FakeEnvironment,
) -> None:
    """A malformed remote topology is not silently overwritten by ordinary refresh."""

    assert _setup(fake_environment) == 0
    manifest = _load_manifest(fake_environment)
    tunnel_id = manifest["manager"]["tunnel_id"]
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["tunnel_configurations"][tunnel_id] = {"config": {}}
    _write_tool_state(fake_environment, tool_state)

    writes_before = tool_state["cloudflare"]["write_history"]
    assert _setup(fake_environment) == 1
    assert fake_environment.tool_state()["cloudflare"]["tunnel_configurations"][tunnel_id] == {
        "config": {}
    }
    assert fake_environment.tool_state()["cloudflare"]["write_history"] == writes_before
    assert _load_manifest(fake_environment) == manifest


def test_setup_refresh_only_refuses_initial_bootstrap(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Refresh-only setup cannot create the initial remote manager."""

    exit_code = main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root)

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Setup refresh requires existing local manager state." in captured.err
    assert not (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    ).exists()


def test_setup_refresh_only_prefers_missing_manager_state_over_tool_checks(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Refresh-only setup reports missing manager state before local tool drift."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflared_version"] = "cloudflared version 2025.3.9"
    _write_tool_state(fake_environment, tool_state)

    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "Setup refresh requires existing local manager state." in captured.err
    assert "2025.4.0 or later is required" not in captured.err


def test_setup_refresh_only_repairs_existing_manager(
    fake_environment: FakeEnvironment,
) -> None:
    """Refresh-only setup repairs local token drift without replacing foreign topology."""

    assert _setup(fake_environment) == 0
    manifest = _load_manifest(fake_environment)
    tunnel_id = manifest["manager"]["tunnel_id"]
    token_path = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "tunnel-token.txt"
    )
    token_path.write_text("stale-local-token\n", encoding="utf-8")

    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 0
    repaired_state = fake_environment.tool_state()
    assert repaired_state["cloudflare"]["tunnel_configurations"][tunnel_id]["config"] == {
        "ingress": [{"service": "http_status:404"}]
    }
    assert token_path.read_text(encoding="utf-8") == "token-tunnel-1\n"
    assert _load_manifest(fake_environment)["pending"] is None


def test_setup_refresh_waits_for_launchd_bootout_settlement(
    fake_environment: FakeEnvironment,
) -> None:
    """Setup refresh waits until launchd unregisters the previous connector job."""

    assert _setup(fake_environment) == 0
    fake_environment.linger_after_bootout(2)

    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 0
    assert "com.cloudflare-publish.cloudflared" in fake_environment.launchd_labels()


def test_setup_rejects_unsupported_cloudflared_version(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Setup fails early when the installed cloudflared is too old for `--token-file`."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflared_version"] = "cloudflared version 2025.3.9"
    _write_tool_state(fake_environment, tool_state)

    assert _setup(fake_environment) == 1
    captured = capsys.readouterr()
    assert "2025.4.0 or later is required" in captured.err


def test_publish_update_remove_and_verify(fake_environment: FakeEnvironment) -> None:
    """Publish supports create, update, verify, and remove on one shared tunnel."""

    assert _setup(fake_environment) == 0
    assert (
        main(
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
        == 0
    )
    assert (
        main(
            [
                "publish",
                "apply",
                "dashboard",
                "--yes",
                "--hostname",
                "dashboard.example.com",
                "--to",
                "https://127.0.0.1:8443",
                "--audience",
                "mixed",
                "--allow-domain",
                "example.com",
                "--no-tls-verify",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    assert (
        main(
            [
                "publish",
                "apply",
                "grafana",
                "--yes",
                "--hostname",
                "grafana.example.com",
                "--to",
                "http://127.0.0.1:3001",
                "--audience",
                "mixed",
                "--allow-email",
                "ops@example.com",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    assert main(["verify", "--live"], repo_root=fake_environment.repo_root) == 0

    manifest = _load_manifest(fake_environment)
    assert set(manifest["publications"]) == {"grafana", "dashboard"}
    assert manifest["publications"]["grafana"]["spec"]["origin_url"] == "http://127.0.0.1:3001"
    tunnel_id = manifest["manager"]["tunnel_id"]
    tool_state = fake_environment.tool_state()
    ingress = tool_state["cloudflare"]["tunnel_configurations"][tunnel_id]["config"]["ingress"]
    assert [rule["hostname"] for rule in ingress[:-1]] == [
        "dashboard.example.com",
        "grafana.example.com",
    ]

    assert main(["rm", "apply", "dashboard", "--yes"], repo_root=fake_environment.repo_root) == 0
    manifest = _load_manifest(fake_environment)
    assert set(manifest["publications"]) == {"grafana"}
    ingress = fake_environment.tool_state()["cloudflare"]["tunnel_configurations"][tunnel_id][
        "config"
    ]["ingress"]
    assert [rule["hostname"] for rule in ingress[:-1]] == ["grafana.example.com"]


def test_verify_fails_when_cloudflared_is_too_old(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify surfaces unsupported cloudflared versions as failing checks."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflared_version"] = "cloudflared version 2025.3.9"
    _write_tool_state(fake_environment, tool_state)

    assert main(["verify"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "[FAIL] cloudflared supports --token-file" in captured.out
    assert "cloudflared version 2025.3.9" in captured.out


def test_publish_persists_manifest_before_tunnel_config_push(
    fake_environment: FakeEnvironment,
) -> None:
    """A tunnel-config failure leaves enough local state for a clean publish rerun."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["fail_tunnel_config_put_once"] = True
    _write_tool_state(fake_environment, tool_state)

    first_exit = main(
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
    assert first_exit == 1
    manifest = _load_manifest(fake_environment)
    assert "grafana" not in manifest["publications"]
    assert manifest["pending"]["target"] == "grafana"
    assert manifest["pending"]["candidate"]["state"]["dns_record_id"] == "dns-1"
    assert (
        main(
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
        == 0
    )
    assert _load_manifest(fake_environment)["pending"] is None
    assert (
        _load_manifest(fake_environment)["publications"]["grafana"]["state"]["dns_record_id"]
        == "dns-1"
    )


def test_guard_status_reports_exempted_zones(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Guard status surfaces exempted zones when they are present."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["organization"]["deny_unmatched_requests"] = True
    tool_state["cloudflare"]["organization"]["deny_unmatched_requests_exempted_zone_names"] = [
        "public.example.com"
    ]
    _write_tool_state(fake_environment, tool_state)

    assert main(["guard", "status"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Require Access protection: enabled" in captured.out
    assert "Exempted zones: public.example.com" in captured.out


def test_guard_status_reports_disabled_risk_and_plan_command(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Guard status warns when unmatched hostnames are not protected by default."""

    assert _setup(fake_environment) == 0
    _ = capsys.readouterr()

    assert main(["guard", "status"], repo_root=fake_environment.repo_root) == 0
    human = capsys.readouterr()
    assert "Require Access protection: disabled" in human.out
    assert "Risk: hostnames without a matching Access application" in human.out
    assert "Next: cloudflare-publish guard plan" in human.out
    assert "Apply: cloudflare-publish guard apply --yes" in human.out

    assert main(["--json", "guard", "status"], repo_root=fake_environment.repo_root) == 0
    payload = json.loads(capsys.readouterr().out)
    organization = payload["data"]["organization"]
    assert organization["deny_unmatched_requests"] is False
    assert organization["recommended_next_commands"] == [
        "cloudflare-publish guard plan",
        "cloudflare-publish guard apply --yes",
    ]


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


def _load_manifest(fake_environment: FakeEnvironment) -> dict[str, object]:
    """Load the current local manifest JSON."""

    state_file = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )
    return json.loads(state_file.read_text(encoding="utf-8"))


def _write_tool_state(fake_environment: FakeEnvironment, state: dict[str, object]) -> None:
    """Persist fake-binary state mutations for one test."""

    fake_environment.state_file.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
