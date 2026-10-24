"""Hermetic Linux CLI flows use native adapters, not a second workflow model.

Fake systemd and Cloudflare acceptance do not establish real user-manager,
logout/reboot, HTTPS/WSS, JWT or DGX readiness.
"""

from __future__ import annotations

import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.json_types import JsonObject, JsonValue, require_array, require_object
from cloudflare_publish.models import API_TOKEN_ACCOUNT, AppPaths, StateManifest
from cloudflare_publish.paths import build_paths
from cloudflare_publish.process import CommandRunner
from cloudflare_publish.secret_store import FileSecretStore
from cloudflare_publish.state import load_manifest
from tests.fake_environment import FakeEnvironment, make_fake_environment

_APPS = "/accounts/acc-123/access/apps"


@pytest.fixture
def linux_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeEnvironment]:
    """Select Linux by Python dependency injection, with no production environment switch."""

    yield from make_fake_environment(tmp_path, monkeypatch, platform="linux")


@pytest.mark.parametrize("failure", ["old-systemd", "user-bus", "linger", "lsof"])
def test_linux_preflight_precedes_remote_creation(
    linux_environment: FakeEnvironment, failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing unattended service prerequisites cannot leave remote bootstrap effects."""

    env = linux_environment
    state = env.tool_state()
    if failure == "old-systemd":
        state["systemd_version"] = "systemd 239"
    elif failure == "user-bus":
        state["systemd_bus_unavailable"] = True
    elif failure == "linger":
        state["systemd_linger_disabled"] = True
    else:
        (env.bin_dir / "lsof").unlink()
        original = CommandRunner.which

        def without_lsof(self: CommandRunner, program: str) -> Path | None:
            return None if program == "lsof" else original(self, program)

        monkeypatch.setattr(CommandRunner, "which", without_lsof)
    env.write_tool_state(state)

    assert _setup(env) == 1
    assert not _paths(env).state_file.exists()
    assert not (_paths(env).state_dir / "credentials").exists()
    assert not _cloudflare(env).get("requests")
    assert _cloudflare(env)["tunnels"] == {}
    assert env.tool_state()["brew_calls"] == 0
    assert not (env.home / "Library").exists()


@pytest.mark.parametrize("option", ["--install-deps", "--takeover"])
def test_linux_rejects_mac_only_setup_effects(
    linux_environment: FakeEnvironment, option: str
) -> None:
    """Neither package installation nor legacy takeover is silently adapted on Linux."""

    assert _setup(linux_environment, option, "--yes") == 1
    assert not _cloudflare(linux_environment).get("requests")
    assert linux_environment.tool_state()["brew_calls"] == 0


def test_linux_setup_uses_private_host_storage_and_an_owned_user_unit(
    linux_environment: FakeEnvironment,
) -> None:
    """Setup reaches the same manager contract without macOS stores or services."""

    env = linux_environment
    assert _setup(env) == 0
    paths = _paths(env)
    manifest = _manifest(env)
    assert manifest.pending is None
    assert manifest.manager.tunnel_id == "tunnel-1"
    assert paths.host_platform == "linux"
    assert paths.service_file == env.home / ".config/systemd/user/cloudflare-publish.service"
    assert paths.state_file == env.home / ".local/state/cloudflare-publish/state.json"
    assert (
        FileSecretStore(paths.state_dir / "credentials").load_secret(account=API_TOKEN_ACCOUNT)
        == "linux-api-token"
    )
    assert paths.tunnel_token_file.read_text(encoding="utf-8") == "token-tunnel-1\n"
    for directory in (paths.state_dir, paths.logs_dir, paths.state_dir / "credentials"):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for file in (
        paths.state_file,
        paths.tunnel_token_file,
        *(paths.state_dir / "credentials").iterdir(),
    ):
        assert stat.S_IMODE(file.stat().st_mode) == 0o600
        assert file.stat().st_nlink == 1
    assert "linux-api-token" not in paths.state_file.read_text(encoding="utf-8")
    assert "token-tunnel-1" not in paths.service_file.read_text(encoding="utf-8")
    assert "--token-file" in paths.service_file.read_text(encoding="utf-8")
    assert ["--user", "enable", "--now", "cloudflare-publish.service"] in _calls(
        env, "systemctl_calls"
    )
    assert env.tool_state()["keychain"] == {}
    assert _calls(env, "security_calls") == []
    assert _calls(env, "launchctl_calls") == []
    assert env.launchd_labels() == ()
    assert not (env.home / "Library").exists()


def test_linux_service_cycle_is_local_and_stopped_unit_remains_known(
    linux_environment: FakeEnvironment,
) -> None:
    """A loaded inactive definition is not a running connector or teardown requirement."""

    env = linux_environment
    assert _setup(env) == 0
    writes = _cloudflare(env).get("requests")
    assert _run(env, "service", "stop") == 0
    assert env.tool_state()["systemd_active"] is False
    assert env.tool_state()["systemd_enabled"] is False
    assert _paths(env).service_file.exists()
    assert "systemd_loaded_definition" in env.tool_state()
    assert _run(env, "service", "status") == 0
    assert _run(env, "service", "stop") == 0
    assert _run(env, "service", "start") == 0
    assert _run(env, "service", "restart") == 0
    assert env.tool_state()["systemd_active"] is True
    assert env.tool_state()["systemd_enabled"] is True
    assert _cloudflare(env).get("requests") == writes
    assert ["--user", "disable", "--now", "cloudflare-publish.service"] in _calls(
        env, "systemctl_calls"
    )
    assert ["--user", "restart", "cloudflare-publish.service"] in _calls(env, "systemctl_calls")
    assert env.launchd_labels() == ()
    assert env.tool_state()["keychain"] == {}
    assert _calls(env, "security_calls") == []
    assert _calls(env, "launchctl_calls") == []


def test_linux_origin_authenticated_public_route_owns_no_access_resources(
    linux_environment: FakeEnvironment,
) -> None:
    """The T3-compatible transport does not add browser login or service-token headers.

    This fake origin does not qualify T3 authentication; real negative API/WSS and
    paired-device acceptance remain separate host/application obligations.
    """

    env = linux_environment
    assert _setup(env) == 0
    assert _publish(env, audience="public") == 0
    manifest = _manifest(env)
    assert manifest.publications["backend"].spec.audience == "public"
    for key in ("access_apps", "access_policies", "service_tokens"):
        assert _cloudflare(env)[key] == {}
    assert len(tuple((_paths(env).state_dir / "credentials").iterdir())) == 1


def test_linux_publication_lost_response_requires_exact_recovery_without_duplicate_post(
    linux_environment: FakeEnvironment,
) -> None:
    """Linux credentials and service adapters preserve the existing unknown-effect fence."""

    env = linux_environment
    assert _setup(env) == 0
    env.inject_api_fault("POST", _APPS, mode="after")
    assert _publish(env) == 1
    pending = _manifest(env).pending
    assert pending is not None and pending.effect is not None
    assert pending.effect.kind == "access_application"
    assert len(_object(_cloudflare(env)["access_apps"])) == 1
    assert _publish(env) == 1
    assert _manifest(env).pending == pending
    assert _post_count(env, _APPS) == 1

    assert (
        _run(
            env,
            "repair",
            "resolve",
            "--operation",
            pending.operation_id,
            "--resource-id",
            "app-1",
            "--yes",
        )
        == 0
    )
    assert _publish(env) == 0
    manifest = _manifest(env)
    assert manifest.pending is None
    assert _post_count(env, _APPS) == 1
    assert len(_object(_cloudflare(env)["access_apps"])) == 1
    assert len(_object(_cloudflare(env)["service_tokens"])) == 1
    assert len(tuple((_paths(env).state_dir / "credentials").iterdir())) == 2
    credential_account = manifest.publications["backend"].state.service_token_keychain_account
    assert credential_account is not None
    assert FileSecretStore(_paths(env).state_dir / "credentials").load_secret(
        account=credential_account
    )


def test_linux_native_listener_evidence_supplies_only_a_missing_api_version(
    linux_environment: FakeEnvironment,
) -> None:
    """The real systemd PID adapter correlates the native loopback identity and config."""

    env = linux_environment
    assert _setup(env) == 0
    state = env.tool_state()
    state["omit_local_config_version"] = True
    env.write_tool_state(state)
    assert _publish(env) == 0
    assert _manifest(env).pending is None
    assert _calls(env, "lsof_calls")
    assert all(
        call == ["-nP", "-a", "-p", "1234", "-iTCP", "-sTCP:LISTEN", "-Fpn"]
        for call in _calls(env, "lsof_calls")
    )


def test_linux_stale_native_configuration_retains_publication_until_observed(
    linux_environment: FakeEnvironment,
) -> None:
    """A systemd start cannot substitute for the intended applied configuration version."""

    env = linux_environment
    assert _setup(env) == 0
    state = env.tool_state()
    state["omit_local_config_version"] = True
    _object(state["cloudflare"])["hold_local_config"] = True
    env.write_tool_state(state)
    assert _publish(env) == 1
    assert _manifest(env).pending is not None
    assert len(_object(_cloudflare(env)["access_apps"])) == 1
    assert _calls(env, "lsof_calls")
    state = env.tool_state()
    cf = _object(state["cloudflare"])
    cf["hold_local_config"] = False
    version = _object(_object(cf["tunnel_configurations"])["tunnel-1"])["version"]
    clients = require_array(_object(cf["tunnel_connections"])["tunnel-1"], message="clients")
    _object(clients[0])["config_version"] = version
    env.write_tool_state(state)
    assert _publish(env) == 0
    assert _manifest(env).pending is None
    assert len(_object(_cloudflare(env)["access_apps"])) == 1


@pytest.mark.parametrize("failure", ["systemd_fail_disable_once", "systemd_refuse_inactive"])
def test_linux_teardown_retains_protection_on_failed_stop_then_removes_exact_owned_resources(
    linux_environment: FakeEnvironment, failure: str
) -> None:
    """Neither rejected stop nor successful-but-active stop authorizes remote retirement."""

    env = linux_environment
    assert _setup(env) == 0
    assert _publish(env) == 0
    paths = _paths(env)
    other_unit = paths.service_dir / "other-product.service"
    _ = other_unit.write_text("unrelated unit\n", encoding="utf-8")
    other_state = env.home / ".local/state/other-product/keep"
    other_state.parent.mkdir()
    _ = other_state.write_text("unrelated state\n", encoding="utf-8")
    retained_manager_entry = paths.state_dir / "unrecognized-operator-material"
    _ = retained_manager_entry.write_text("retain this entry\n", encoding="utf-8")
    state = env.tool_state()
    cf = _object(state["cloudflare"])
    _object(cf["tunnels"])["foreign-tunnel"] = {"id": "foreign-tunnel", "name": "other"}
    _object(cf["tunnel_configurations"])["foreign-tunnel"] = {"config": {"ingress": []}}
    state[failure] = True
    env.write_tool_state(state)
    resources = {
        key: _cloudflare(env)[key]
        for key in ("tunnels", "dns_records", "access_apps", "service_tokens")
    }

    assert _run(env, "teardown", "--yes") == 1
    pending = _manifest(env).pending
    assert pending is not None and pending.kind == "teardown"
    assert {key: _cloudflare(env)[key] for key in resources} == resources
    assert paths.service_file.exists() and paths.tunnel_token_file.exists()
    assert len(tuple((paths.state_dir / "credentials").iterdir())) == 2
    state = env.tool_state()
    state[failure] = False
    env.write_tool_state(state)

    assert _run(env, "teardown", "--yes") == 0
    assert _cloudflare(env)["tunnels"] == {
        "foreign-tunnel": {"id": "foreign-tunnel", "name": "other"}
    }
    for key in ("dns_records", "access_apps", "service_tokens"):
        assert _cloudflare(env)[key] == {}
    assert not paths.state_file.exists()
    assert not paths.service_file.exists()
    assert not paths.tunnel_token_file.exists()
    assert not (paths.state_dir / "credentials").exists()
    assert (paths.state_dir / "manager.lock").exists()
    assert other_unit.read_text(encoding="utf-8") == "unrelated unit\n"
    assert other_state.read_text(encoding="utf-8") == "unrelated state\n"
    assert retained_manager_entry.read_text(encoding="utf-8") == "retain this entry\n"
    assert env.tool_state()["systemd_active"] is False
    assert env.tool_state()["systemd_enabled"] is False


def test_linux_teardown_unit_removal_reload_failure_resumes_without_remote_writes(
    linux_environment: FakeEnvironment,
) -> None:
    """After remote retirement, exact unit custody survives failed native unload readback."""

    env = linux_environment
    assert _setup(env) == 0
    assert _publish(env) == 0
    paths = _paths(env)
    retiring_unit = paths.service_file.with_name(".cloudflare-publish.service.retiring")
    owned_definition = paths.service_file.read_bytes()
    state = env.tool_state()
    state["systemd_fail_reload_once"] = True
    env.write_tool_state(state)

    assert _run(env, "teardown", "--yes") == 1
    pending = _manifest(env).pending
    assert pending is not None and pending.phase == "cleanup_complete"
    for key in ("tunnels", "dns_records", "access_apps", "service_tokens"):
        assert _cloudflare(env)[key] == {}
    requests = _cloudflare(env).get("requests")
    assert not paths.service_file.exists()
    assert retiring_unit.read_bytes() == owned_definition
    assert paths.tunnel_token_file.exists()

    # A replacement canonical pathname is not the retired owned definition.
    _ = paths.service_file.write_text("foreign replacement unit\n", encoding="utf-8")
    assert _run(env, "teardown", "--yes") == 1
    assert paths.service_file.read_text(encoding="utf-8") == "foreign replacement unit\n"
    assert _manifest(env).pending == pending
    assert _cloudflare(env).get("requests") == requests
    assert retiring_unit.read_bytes() == owned_definition
    paths.service_file.unlink()

    assert _run(env, "teardown", "--yes") == 0
    assert _cloudflare(env).get("requests") == requests
    assert not paths.state_file.exists()
    assert not paths.service_file.exists()
    assert not retiring_unit.exists()
    assert not paths.tunnel_token_file.exists()
    assert env.tool_state()["systemd_active"] is False
    assert env.tool_state()["systemd_enabled"] is False


def _paths(env: FakeEnvironment) -> AppPaths:
    return build_paths(env.repo_root, env.home, platform="linux")


def _manifest(env: FakeEnvironment) -> StateManifest:
    manifest = load_manifest(_paths(env).state_file)
    assert manifest is not None
    return manifest


def _object(value: JsonValue) -> JsonObject:
    return require_object(value, message="Expected fake state object.")


def _cloudflare(env: FakeEnvironment) -> JsonObject:
    return _object(env.tool_state()["cloudflare"])


def _calls(env: FakeEnvironment, key: str) -> list[JsonValue]:
    return require_array(env.tool_state().get(key, []), message="Expected fake call list.")


def _post_count(env: FakeEnvironment, path: str) -> int:
    return sum(
        _object(request)["method"] == "POST" and _object(request)["path"] == path
        for request in require_array(_cloudflare(env).get("requests", []), message="requests")
    )


def _run(env: FakeEnvironment, *args: str) -> int:
    return main(list(args), repo_root=env.repo_root)


def _setup(env: FakeEnvironment, *extra: str) -> int:
    return _run(
        env,
        "setup",
        "--api-token",
        "linux-api-token",
        "--account-id",
        "acc-123",
        "--zone",
        "example.com",
        *extra,
    )


def _publish(env: FakeEnvironment, *, audience: str = "machine") -> int:
    return _run(
        env,
        "publish",
        "apply",
        "backend",
        "--hostname",
        "backend.example.com",
        "--to",
        "http://127.0.0.1:3000",
        "--audience",
        audience,
        "--yes",
    )
