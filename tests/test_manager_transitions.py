"""Interrupted manager effects retain exact ownership and protection for recovery."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cloudflare_publish import setup_flow, teardown_flow
from cloudflare_publish.cli import main
from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import (
    ServiceTokenSecret,
    TunnelClientRef,
    TunnelConfigurationRef,
    TunnelRef,
)
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.models import PendingTransition
from cloudflare_publish.state import load_manifest, write_manifest
from cloudflare_publish.transitions import Mutation
from tests.fake_environment import FakeEnvironment


def test_setup_unknown_post_never_creates_a_second_tunnel(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An accepted create with a lost response cannot be retried as a fresh bootstrap."""

    original = CloudflareApi.create_tunnel

    def lose_response(self: CloudflareApi, *, account_id: str, name: str) -> TunnelRef:
        _ = original(self, account_id=account_id, name=name)
        raise AppError("Synthetic lost create response.")

    monkeypatch.setattr(CloudflareApi, "create_tunnel", lose_response)
    assert _setup(fake_environment) == 1
    manifest = _manifest(fake_environment)
    assert manifest.manager.tunnel_id == ""
    assert manifest.pending is not None
    assert manifest.pending.effect is not None
    assert manifest.pending.effect.kind == "tunnel"
    assert "token-1" not in _state_path(fake_environment).read_text(encoding="utf-8")
    assert len(fake_environment.tool_state()["cloudflare"]["tunnels"]) == 1
    monkeypatch.setattr(CloudflareApi, "create_tunnel", original)
    assert _setup(fake_environment) == 1
    assert len(fake_environment.tool_state()["cloudflare"]["tunnels"]) == 1
    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 1


def test_setup_persists_api_credential_before_tunnel_creation(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed API credential store leaves resumable intent, not an orphan remote tunnel."""

    original = Keychain.store_secret

    def fail_store(self: Keychain, *, account: str, secret: str) -> None:
        _ = self, account, secret
        raise AppError("Synthetic Keychain failure.")

    monkeypatch.setattr(Keychain, "store_secret", fail_store)
    assert _setup(fake_environment) == 1
    assert fake_environment.tool_state()["cloudflare"]["tunnels"] == {}
    assert _manifest(fake_environment).pending is not None
    monkeypatch.setattr(Keychain, "store_secret", original)
    assert _setup(fake_environment) == 0
    assert len(fake_environment.tool_state()["cloudflare"]["tunnels"]) == 1


@pytest.mark.parametrize("mismatch", ["id", "name", "remote_config", "deleted_at"])
def test_setup_does_not_adopt_an_unexpected_create_response(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    """Untrusted create identity keeps its saved effect instead of configuring another tunnel."""

    original = CloudflareApi.create_tunnel

    def wrong_tunnel(self: CloudflareApi, *, account_id: str, name: str) -> TunnelRef:
        tunnel = original(self, account_id=account_id, name=name)
        return _invalid_tunnel(tunnel, mismatch)

    monkeypatch.setattr(CloudflareApi, "create_tunnel", wrong_tunnel)
    assert _setup(fake_environment) == 1
    manifest = _manifest(fake_environment)
    assert manifest.manager.tunnel_id == ""
    assert manifest.pending.effect is not None
    configurations = fake_environment.tool_state()["cloudflare"]["tunnel_configurations"]
    assert configurations == {"tunnel-1": {"config": {}, "version": 0}}


def test_setup_retains_created_tunnel_when_token_fetch_fails(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later failure resumes the owned tunnel ID instead of colliding by name."""

    original = CloudflareApi.get_tunnel_token

    def fail_fetch(self: CloudflareApi, *, account_id: str, tunnel_id: str) -> str:
        _ = self, account_id, tunnel_id
        raise AppError("Synthetic token-fetch failure.")

    monkeypatch.setattr(CloudflareApi, "get_tunnel_token", fail_fetch)
    assert _setup(fake_environment) == 1
    assert _manifest(fake_environment).manager.tunnel_id == "tunnel-1"
    monkeypatch.setattr(CloudflareApi, "get_tunnel_token", original)
    assert _setup(fake_environment) == 0
    assert len(fake_environment.tool_state()["cloudflare"]["tunnels"]) == 1


def test_takeover_backup_is_owned_before_original_cleanup(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interruption after copying cannot lose where the retained takeover originals live."""

    fake_environment.install_conflicting_local_state()
    original = setup_flow.cleanup_conflicts

    def fail_cleanup(*args: object) -> None:
        _ = args
        raise AppError("Synthetic takeover interruption.")

    monkeypatch.setattr(setup_flow, "cleanup_conflicts", fail_cleanup)
    assert _setup(fake_environment, takeover=True) == 1
    manifest = _manifest(fake_environment)
    assert len(manifest.backups) == 1
    backup = manifest.backups[0]
    assert (backup.directory / ".cloudflared" / "config.yml").read_text() == "conflict-config\n"
    assert (fake_environment.home / ".cloudflared" / "config.yml").exists()
    assert fake_environment.tool_state()["cloudflare"]["tunnels"] == {}
    monkeypatch.setattr(setup_flow, "cleanup_conflicts", original)
    assert _setup(fake_environment) == 0
    assert _manifest(fake_environment).backups == manifest.backups


def test_resumed_takeover_preserves_new_legacy_file_edits(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing backup ownership does not authorize discarding a later original version."""

    fake_environment.install_conflicting_local_state()
    original_cleanup = setup_flow.cleanup_conflicts

    def fail_cleanup(*args: object) -> None:
        _ = args
        raise AppError("Synthetic takeover interruption.")

    monkeypatch.setattr(setup_flow, "cleanup_conflicts", fail_cleanup)
    assert _setup(fake_environment, takeover=True) == 1
    original = fake_environment.home / ".cloudflared" / "config.yml"
    original.write_text("a later operator edit\n", encoding="utf-8")
    monkeypatch.setattr(setup_flow, "cleanup_conflicts", original_cleanup)
    assert _setup(fake_environment) == 1
    assert original.read_text(encoding="utf-8") == "a later operator edit\n"
    assert fake_environment.tool_state()["cloudflare"]["tunnels"] == {}


def test_setup_refresh_cannot_resurrect_an_incomplete_removal(
    fake_environment: FakeEnvironment,
) -> None:
    """Refresh must refuse the conflicting operation rather than render retained old state."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    manifest = _manifest(fake_environment)
    write_manifest(
        _state_path(fake_environment),
        replace(
            manifest,
            pending=PendingTransition(
                operation_id="remove-operation",
                kind="remove",
                target="grafana",
                request={},
                route="withdrawn",
            ),
        ),
    )
    before = fake_environment.tool_state()["cloudflare"]["tunnel_configurations"]
    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 1
    assert fake_environment.tool_state()["cloudflare"]["tunnel_configurations"] == before


def test_setup_retains_pending_until_an_active_connector_applies_configuration(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stored config and a launchd start are not proof of connector application."""

    original = CloudflareApi.list_tunnel_connections

    def absent_connectors(
        self: CloudflareApi,
        *,
        account_id: str,
        tunnel_id: str,
    ) -> tuple[TunnelClientRef, ...]:
        _ = self, account_id, tunnel_id
        return ()

    monkeypatch.setattr(CloudflareApi, "list_tunnel_connections", absent_connectors)
    assert _setup(fake_environment) == 1
    assert _manifest(fake_environment).pending.phase == "installed"
    installed_count = fake_environment.kickstart_count()
    monkeypatch.setattr(CloudflareApi, "list_tunnel_connections", original)
    assert _setup(fake_environment) == 0
    assert fake_environment.kickstart_count() == installed_count


@pytest.mark.parametrize("stored_change", ["foreign_ingress", "new_version", "missing_version"])
def test_initial_setup_resume_reobserves_stored_configuration_before_completing(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    stored_change: str,
) -> None:
    """A connector reporting the earlier version cannot certify changed stored configuration."""

    original = CloudflareApi.list_tunnel_connections

    def fail_observation(
        self: CloudflareApi,
        *,
        account_id: str,
        tunnel_id: str,
    ) -> tuple[TunnelClientRef, ...]:
        _ = self, account_id, tunnel_id
        raise AppError("Synthetic connector observation interruption.")

    monkeypatch.setattr(CloudflareApi, "list_tunnel_connections", fail_observation)
    assert _setup(fake_environment) == 1
    manifest = _manifest(fake_environment)
    assert manifest.pending.phase == "installed"
    assert manifest.pending.configuration_version == 1
    installed_count = fake_environment.kickstart_count()
    monkeypatch.setattr(CloudflareApi, "list_tunnel_connections", original)

    state = fake_environment.tool_state()
    cloudflare = state["cloudflare"]
    stored = cloudflare["tunnel_configurations"]["tunnel-1"]
    if stored_change == "missing_version":
        del stored["version"]
    else:
        stored["version"] = 2
        if stored_change == "foreign_ingress":
            stored["config"]["ingress"].insert(
                0,
                {"hostname": "foreign.example.com", "service": "http://127.0.0.1:9999"},
            )
    cloudflare["hold_local_config"] = True
    fake_environment.write_tool_state(state)

    assert _setup(fake_environment) == 1
    assert fake_environment.tool_state()["cloudflare"] == cloudflare
    assert fake_environment.kickstart_count() == installed_count
    pending = _manifest(fake_environment).pending
    assert pending.phase == "installed"
    assert (
        pending.configuration_version
        == {
            "foreign_ingress": 1,
            "new_version": 2,
            "missing_version": None,
        }[stored_change]
    )

    if stored_change == "new_version":
        state = fake_environment.tool_state()
        state["cloudflare"]["tunnel_connections"]["tunnel-1"][0]["config_version"] = 2
        fake_environment.write_tool_state(state)
        assert _setup(fake_environment) == 0
        assert _manifest(fake_environment).pending is None
        assert fake_environment.kickstart_count() == installed_count


def test_setup_can_reobserve_a_missing_configuration_version_without_repeating_put(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing version preserves pending custody without permanently stranding bootstrap."""

    original_update = CloudflareApi.update_tunnel_configuration
    original_snapshot = CloudflareApi.get_tunnel_configuration_snapshot
    puts = 0

    def missing_update_version(
        self: CloudflareApi,
        *,
        account_id: str,
        tunnel_id: str,
        configuration: JsonObject,
    ) -> int | None:
        nonlocal puts
        puts += 1
        _ = original_update(
            self,
            account_id=account_id,
            tunnel_id=tunnel_id,
            configuration=configuration,
        )
        return None

    def missing_snapshot_version(
        self: CloudflareApi,
        *,
        account_id: str,
        tunnel_id: str,
    ) -> TunnelConfigurationRef:
        snapshot = original_snapshot(self, account_id=account_id, tunnel_id=tunnel_id)
        return replace(snapshot, version=None)

    monkeypatch.setattr(CloudflareApi, "update_tunnel_configuration", missing_update_version)
    monkeypatch.setattr(
        CloudflareApi, "get_tunnel_configuration_snapshot", missing_snapshot_version
    )
    assert _setup(fake_environment) == 1
    assert _manifest(fake_environment).pending.configuration_version is None
    monkeypatch.setattr(CloudflareApi, "get_tunnel_configuration_snapshot", original_snapshot)
    assert _setup(fake_environment) == 0
    assert puts == 1


def test_setup_refresh_refuses_foreign_global_tls_drift(fake_environment: FakeEnvironment) -> None:
    """Refresh is not authority to erase unknown remote configuration."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    state = fake_environment.tool_state()
    config = state["cloudflare"]["tunnel_configurations"]["tunnel-1"]["config"]
    config["originRequest"] = {"noTLSVerify": True}
    fake_environment.write_tool_state(state)
    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 1
    assert (
        fake_environment.tool_state()["cloudflare"]["tunnel_configurations"]["tunnel-1"]["config"]
        == config
    )
    assert _manifest(fake_environment).pending is None


@pytest.mark.parametrize("mismatch", ["id", "remote_config", "deleted_at"])
def test_setup_refresh_rejects_an_unexpected_tunnel_before_any_write(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    """A refresh GET cannot replace owned identity or resurrect an unsupported tunnel."""

    assert _setup(fake_environment) == 0
    original = CloudflareApi.get_tunnel

    def wrong_tunnel(self: CloudflareApi, *, account_id: str, tunnel_id: str) -> TunnelRef:
        tunnel = original(self, account_id=account_id, tunnel_id=tunnel_id)
        return _invalid_tunnel(tunnel, mismatch)

    monkeypatch.setattr(CloudflareApi, "get_tunnel", wrong_tunnel)
    before = fake_environment.tool_state()
    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 1
    assert fake_environment.tool_state() == before
    manifest = _manifest(fake_environment)
    assert manifest.manager.tunnel_id == "tunnel-1"
    assert manifest.pending is None


def test_setup_refresh_explicitly_upgrades_exact_owned_legacy_routes(
    fake_environment: FakeEnvironment,
) -> None:
    """Only the exact retained population without its derived JWT guard is upgradeable."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    state = fake_environment.tool_state()
    config = state["cloudflare"]["tunnel_configurations"]["tunnel-1"]["config"]
    route = config["ingress"][0]
    del route["originRequest"]["access"]
    del route["originRequest"]
    fake_environment.write_tool_state(state)
    assert main(["setup", "--refresh-only"], repo_root=fake_environment.repo_root) == 0
    guarded = fake_environment.tool_state()["cloudflare"]["tunnel_configurations"]["tunnel-1"][
        "config"
    ]["ingress"][0]
    assert guarded["originRequest"]["access"]["required"] is True
    assert len(fake_environment.tool_state()["cloudflare"]["access_apps"]) == 1


def test_teardown_retains_protection_when_local_bootout_fails(
    fake_environment: FakeEnvironment,
) -> None:
    """No DNS, Access or token deletion may precede stopping the serving tunnel."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    before = fake_environment.tool_state()["cloudflare"]
    fake_environment.fail_next_bootout()
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 1
    after = fake_environment.tool_state()["cloudflare"]
    for key in ("access_apps", "service_tokens", "dns_records", "tunnels"):
        assert after[key] == before[key]
    assert _manifest(fake_environment).pending.kind == "teardown"


@pytest.mark.parametrize("connection_known", [True, False])
def test_teardown_blocks_foreign_connectors_without_removing_access(
    fake_environment: FakeEnvironment,
    connection_known: bool,
) -> None:
    """An active replica on another machine is not authority to disconnect it."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    state = fake_environment.tool_state()
    foreign = {"id": "foreign", "config_version": 2}
    if connection_known:
        foreign["connections"] = [{"id": "edge-foreign", "is_pending_reconnect": False}]
    state["cloudflare"]["tunnel_connections"]["tunnel-1"].append(foreign)
    fake_environment.write_tool_state(state)
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 1
    after = fake_environment.tool_state()["cloudflare"]
    assert after["access_apps"]
    assert after["tunnels"]
    assert fake_environment.cleaned_tunnel_ids() == ()


def test_teardown_lost_delete_response_keeps_access_until_exact_confirmation(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful DELETE with a lost response resumes through an exact GET, not inference."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    original = CloudflareApi.delete_tunnel
    delete_calls = 0

    def lose_delete(
        self: CloudflareApi,
        *,
        account_id: str,
        tunnel_id: str,
        missing_ok: bool = False,
    ) -> None:
        nonlocal delete_calls
        delete_calls += 1
        original(self, account_id=account_id, tunnel_id=tunnel_id, missing_ok=missing_ok)
        raise AppError("Synthetic lost delete response.")

    monkeypatch.setattr(CloudflareApi, "delete_tunnel", lose_delete)
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 1
    assert fake_environment.tool_state()["cloudflare"]["access_apps"]
    assert _state_path(fake_environment).exists()
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 0
    assert delete_calls == 1
    assert not _state_path(fake_environment).exists()


def test_teardown_does_not_accept_delete_without_observed_deletion(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An API DELETE acknowledgement alone does not permit removing protection."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0

    def acknowledge_only(
        self: CloudflareApi,
        *,
        account_id: str,
        tunnel_id: str,
        missing_ok: bool = False,
    ) -> None:
        _ = self, account_id, tunnel_id, missing_ok

    monkeypatch.setattr(CloudflareApi, "delete_tunnel", acknowledge_only)
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 1
    assert fake_environment.tool_state()["cloudflare"]["access_apps"]
    assert _manifest(fake_environment).publications["grafana"].state.access_application_id


def test_teardown_local_cleanup_resumes_after_api_credential_is_retired(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Remote cleanup completion is durable before deleting credentials and local artifacts."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    original = teardown_flow.remove_local_manager_artifacts

    def fail_cleanup(*args: object) -> None:
        _ = args
        raise AppError("Synthetic local-cleanup failure.")

    monkeypatch.setattr(teardown_flow, "remove_local_manager_artifacts", fail_cleanup)
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 1
    assert _manifest(fake_environment).pending.phase == "cleanup_complete"
    assert fake_environment.tool_state()["keychain"] == {}
    monkeypatch.setattr(teardown_flow, "remove_local_manager_artifacts", original)
    _ = capsys.readouterr()
    assert main(["--json", "teardown", "--yes"], repo_root=fake_environment.repo_root) == 0
    assert json.loads(capsys.readouterr().out)["data"]["removed_manager"]["pending"] is None
    assert not _state_path(fake_environment).exists()


def test_token_rotation_lost_response_never_rotates_again(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reading a surviving token ID cannot recover the lost new secret or justify a retry."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    original = CloudflareApi.rotate_service_token
    rotations = 0

    def lose_rotation(
        self: CloudflareApi,
        *,
        account_id: str,
        service_token_id: str,
    ) -> ServiceTokenSecret:
        nonlocal rotations
        rotations += 1
        _ = original(self, account_id=account_id, service_token_id=service_token_id)
        raise AppError("Synthetic lost rotation response.")

    monkeypatch.setattr(CloudflareApi, "rotate_service_token", lose_rotation)
    assert _rotate(fake_environment) == 1
    manifest = _manifest(fake_environment)
    assert manifest.pending.effect.kind == "token_rotate"
    assert manifest.pending.effect.resource_id == "token-1"
    assert _rotate(fake_environment) == 1
    assert rotations == 1


def test_explicit_token_recovery_reissues_the_same_owned_token(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A human-authorized new secret is distinct from automatically retrying a lost POST."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    original = CloudflareApi.rotate_service_token

    def lose_rotation(
        self: CloudflareApi,
        *,
        account_id: str,
        service_token_id: str,
    ) -> ServiceTokenSecret:
        _ = original(self, account_id=account_id, service_token_id=service_token_id)
        raise AppError("Synthetic lost rotation response.")

    monkeypatch.setattr(CloudflareApi, "rotate_service_token", lose_rotation)
    assert _rotate(fake_environment) == 1
    owned_id = _manifest(fake_environment).publications["grafana"].state.service_token_id
    monkeypatch.setattr(CloudflareApi, "rotate_service_token", original)
    assert (
        main(
            [
                "token",
                "rotate",
                "grafana",
                "--recover",
                "--yes",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    manifest = _manifest(fake_environment)
    assert manifest.pending is None
    assert manifest.publications["grafana"].state.service_token_id == owned_id
    assert len(fake_environment.tool_state()["cloudflare"]["service_tokens"]) == 1


def test_explicit_token_recovery_without_unknown_rotation_does_not_post(
    fake_environment: FakeEnvironment,
) -> None:
    """The stronger flag is not an alternate unrestricted rotation path."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    before = fake_environment.tool_state()["cloudflare"]["service_tokens"]
    assert (
        main(
            [
                "token",
                "rotate",
                "grafana",
                "--recover",
                "--yes",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 1
    )
    assert fake_environment.tool_state()["cloudflare"]["service_tokens"] == before
    assert _manifest(fake_environment).pending is None


def test_token_rotation_resumes_stored_handoff_without_another_post(
    fake_environment: FakeEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interruption after storing the new secret resumes that exact completed rotation."""

    assert _setup(fake_environment) == 0
    assert _publish(fake_environment) == 0
    original = Mutation.finish

    def interrupt_finish(self: Mutation):
        if self.pending.kind == "token_rotate":
            raise AppError("Synthetic interruption before transition completion.")
        return original(self)

    monkeypatch.setattr(Mutation, "finish", interrupt_finish)
    assert _rotate(fake_environment) == 1
    manifest = _manifest(fake_environment)
    assert manifest.pending.phase == "rotated"
    assert manifest.pending.effect is None
    remote = fake_environment.tool_state()["cloudflare"]["service_tokens"]
    monkeypatch.setattr(Mutation, "finish", original)
    assert _rotate(fake_environment) == 0
    assert fake_environment.tool_state()["cloudflare"]["service_tokens"] == remote


def _setup(environment: FakeEnvironment, *, takeover: bool = False) -> int:
    args = [
        "setup",
        "--api-token",
        "token-1",
        "--account-id",
        "acc-123",
        "--zone",
        "example.com",
    ]
    if takeover:
        args.extend(["--takeover", "--yes"])
    return main(args, repo_root=environment.repo_root)


def _publish(environment: FakeEnvironment) -> int:
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
        repo_root=environment.repo_root,
    )


def _rotate(environment: FakeEnvironment) -> int:
    return main(["token", "rotate", "grafana", "--yes"], repo_root=environment.repo_root)


def _state_path(environment: FakeEnvironment) -> Path:
    return environment.home / "Library/Application Support/cloudflare-publish/state.json"


def _manifest(environment: FakeEnvironment):
    manifest = load_manifest(_state_path(environment))
    assert manifest is not None
    return manifest


def _invalid_tunnel(tunnel: TunnelRef, mismatch: str) -> TunnelRef:
    if mismatch == "id":
        return replace(tunnel, id="")
    if mismatch == "name":
        return replace(tunnel, name="another-operation")
    if mismatch == "remote_config":
        return replace(tunnel, remote_config=False)
    assert mismatch == "deleted_at"
    return replace(tunnel, deleted_at="2026-04-02T00:00:01Z")
