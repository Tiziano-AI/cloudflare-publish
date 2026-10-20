"""Operator boundary tests: bounded discovery, grouped evidence and single writers."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from unittest.mock import patch

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.errors import AppError
from cloudflare_publish.manager_lock import ManagerWriterLock
from cloudflare_publish.paths import build_paths
from cloudflare_publish.state import load_manifest, write_manifest
from tests.fake_environment import FakeEnvironment


def _setup(environment: FakeEnvironment) -> None:
    assert (
        main(
            ["setup", "--api-token", "token-1", "--account-id", "acc-123", "--zone", "example.com"],
            repo_root=environment.repo_root,
        )
        == 0
    )


def _publish(environment: FakeEnvironment) -> None:
    assert (
        main(
            [
                "publish",
                "apply",
                "app",
                "--yes",
                "--hostname",
                "app.example.com",
                "--to",
                "http://127.0.0.1:3000",
                "--audience",
                "machine",
            ],
            repo_root=environment.repo_root,
        )
        == 0
    )


def test_discover_tunnel_is_bounded_secret_free_and_nonmutating(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """Topology output excludes opaque fields, URL credentials and policy values."""

    _setup(fake_environment)
    _publish(fake_environment)
    state = fake_environment.tool_state()
    remote = state["cloudflare"]
    remote["tunnels"]["tunnel-1"]["token"] = "hidden-tunnel-token"
    remote["tunnel_configurations"]["tunnel-1"]["config"]["ingress"] = [
        {
            "hostname": "app.example.com",
            "path": "^/secret-path$",
            "service": "http://user:hidden-password@127.0.0.1:3000?secret-query",
            "extraSecret": "hidden-rule-secret",
            "originRequest": {
                "noTLSVerify": True,
                "access": {"clientSecret": "hidden-origin-secret"},
            },
        },
        {"hostname": "*.example.com", "service": "tcp://secret-user:secret-pass@127.0.0.1:22"},
        {"hostname": "status.example.com", "service": "http_status:404"},
        {"service": "http_status:404"},
    ]
    remote["tunnel_configurations"]["tunnel-1"]["config"]["warp-routing"] = {"enabled": True}
    remote["access_apps"]["app-1"]["client_secret"] = "hidden-app-secret"
    remote["access_apps"]["private-app"] = {
        "id": "private-app",
        "name": "Private",
        "type": "infrastructure",
        "destinations": [{"type": "private", "hostname": "internal"}],
        "client_secret": "hidden-private-secret",
    }
    remote["dns_records"]["unrelated"] = {
        "id": "unrelated",
        "name": "unrelated.example.com",
        "type": "TXT",
        "content": "hidden-dns-secret",
        "proxied": False,
        "zone_id": "zone-123",
    }
    remote["dns_records"]["same-name-txt"] = {
        "id": "same-name-txt",
        "name": "app.example.com",
        "type": "TXT",
        "content": "hidden-matching-dns-secret",
        "proxied": False,
        "zone_id": "zone-123",
    }
    for policy in remote["access_policies"].values():
        policy["include"] = [{"service_token": {"token_id": "hidden-policy-value"}}]
    fake_environment.write_tool_state(state)
    before = deepcopy(fake_environment.tool_state())
    _ = capsys.readouterr()

    assert (
        main(
            [
                "--json",
                "discover",
                "tunnel",
                "tunnel-1",
                "--account-id",
                "acc-123",
                "--zone-id",
                "zone-123",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)["data"]
    for secret in ("hidden-", "secret-path", "secret-query", "secret-user", "secret-pass"):
        assert secret not in captured.out
    assert captured.err == ""
    assert payload["tunnel"]["id"] == "tunnel-1"
    assert payload["ingress"][0]["service"] == "http://127.0.0.1:3000"
    assert payload["ingress"][0]["has_path"] is True
    assert payload["ingress"][1]["service"] is None
    codes = {item["code"] for item in payload["unsupported_topology"]}
    assert {
        "path_routing",
        "wildcard_hostname",
        "private_network_enabled",
        "unsupported_service",
        "noncanonical_origin_url",
        "unreported_ingress_fields",
        "unreported_origin_options",
        "non_cname_dns",
        "non_http_publication_service",
    } <= codes
    assert [app["id"] for app in payload["access"]] == ["app-1"]
    assert payload["access"][0]["policies"][0]["include_rule_kinds"] == ["service_token"]
    assert fake_environment.tool_state() == before


def test_discover_flags_access_destination_overrides_without_exposing_values(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """A path that bypasses Access cannot appear as ordinarily protected discovery."""

    _setup(fake_environment)
    _publish(fake_environment)
    state = fake_environment.tool_state()
    state["cloudflare"]["access_apps"]["app-1"]["destinations"] = [
        {
            "type": "public",
            "uri": "app.example.com",
            "overrides": [{"behavior": "public", "path_pattern": "/hidden-override/*"}],
        }
    ]
    fake_environment.write_tool_state(state)
    _ = capsys.readouterr()
    assert (
        main(
            [
                "--json",
                "discover",
                "tunnel",
                "tunnel-1",
                "--account-id",
                "acc-123",
                "--zone-id",
                "zone-123",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    output = capsys.readouterr().out
    payload = json.loads(output)["data"]
    assert payload["access"][0]["has_destination_overrides"] is True
    assert {"code": "access_destination_overrides", "scope": "access:app-1"} in payload[
        "unsupported_topology"
    ]
    assert "hidden-override" not in output
    assert "path_pattern" not in output


@pytest.mark.parametrize("constraint", ["require", "exclude"])
def test_access_constraints_are_disclosed_and_fail_managed_policy_parity(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    constraint: str,
) -> None:
    """Discovery admits omitted constraint semantics; verify cannot accept include-only parity."""

    _setup(fake_environment)
    _publish(fake_environment)
    state = fake_environment.tool_state()
    for policy in state["cloudflare"]["access_policies"].values():
        policy[constraint] = [{"email": {"email": "hidden-constraint@example.com"}}]
    fake_environment.write_tool_state(state)
    _ = capsys.readouterr()
    assert (
        main(
            [
                "--json",
                "discover",
                "tunnel",
                "tunnel-1",
                "--account-id",
                "acc-123",
                "--zone-id",
                "zone-123",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    output = capsys.readouterr().out
    payload = json.loads(output)["data"]
    assert payload["access"][0]["policies"][0]["has_additional_constraints"] is True
    assert "unreported_policy_constraints" in {
        item["code"] for item in payload["unsupported_topology"]
    }
    assert "hidden-constraint" not in output
    assert main(["--json", "verify", "app"], repo_root=fake_environment.repo_root) == 1
    payload = json.loads(capsys.readouterr().out)["data"]
    check = next(
        item for item in payload["checks"] if item["label"] == "app: Access policies match state"
    )
    assert check["ok"] is False
    assert check["group"] == "access"
    assert "additional_constraints=True" in check["detail"]


def test_discover_tunnel_rejects_mismatched_zone_scope(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """An explicit tunnel read does not silently use the manager's other zone."""

    _setup(fake_environment)
    _ = capsys.readouterr()
    assert (
        main(
            [
                "--json",
                "discover",
                "tunnel",
                "tunnel-1",
                "--account-id",
                "other-account",
                "--zone-id",
                "zone-123",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "discovery_scope_mismatch"


@pytest.mark.parametrize("deleted_at", [None, "2026-10-10T19:06:56.255287Z"])
def test_discovery_distinguishes_deletion_tombstones_and_preserves_residual_names(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    deleted_at: str | None,
) -> None:
    """A retained deleted GET is not local topology; residual DNS and Access remain visible."""

    _setup(fake_environment)
    _publish(fake_environment)
    state = fake_environment.tool_state()
    tunnel = state["cloudflare"]["tunnels"]["tunnel-1"]
    tunnel["remote_config"] = False
    tunnel["status"] = "down"
    tunnel["deleted_at"] = deleted_at
    tunnel["config_src"] = None
    del state["cloudflare"]["tunnel_configurations"]["tunnel-1"]
    fake_environment.write_tool_state(state)
    before = deepcopy(fake_environment.tool_state())
    _ = capsys.readouterr()
    with (
        patch(
            "cloudflare_publish.cloudflare_api.CloudflareApi.get_tunnel_configuration",
            side_effect=AssertionError("must not fetch obsolete or local configuration"),
        ),
        patch(
            "cloudflare_publish.cloudflare_api.CloudflareApi.get_tunnel_token",
            side_effect=AssertionError("discovery must not fetch a token"),
        ),
    ):
        assert (
            main(
                [
                    "--json",
                    "discover",
                    "tunnel",
                    "tunnel-1",
                    "--account-id",
                    "acc-123",
                    "--zone-id",
                    "zone-123",
                ],
                repo_root=fake_environment.repo_root,
            )
            == 0
        )
    payload = json.loads(capsys.readouterr().out)["data"]
    assert payload["tunnel"]["deleted_at"] == deleted_at
    assert payload["tunnel"]["status"] == "down"
    assert payload["ingress"] == []
    assert [record["name"] for record in payload["dns"]] == ["app.example.com"]
    assert [application["id"] for application in payload["access"]] == ["app-1"]
    codes = {item["code"] for item in payload["unsupported_topology"]}
    if deleted_at is None:
        assert codes == {"locally_managed_tunnel", "missing_ingress"}
        assert "tombstone" not in payload["coverage"]
    else:
        assert codes == {"deleted_tunnel"}
        assert "Deleted-tunnel tombstone" in payload["coverage"]
        assert "obsolete ingress configuration was not queried" in payload["coverage"]
    assert fake_environment.tool_state() == before
    assert (
        main(
            ["discover", "tunnels", "--account-id", "acc-123"],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    output = capsys.readouterr().out
    assert ("deleted_at=" in output) is (deleted_at is not None)


def test_grouped_verification_preserves_identity_failure_and_human_output(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unavailable origin and failed public probes stay readiness failures in typed groups."""

    _setup(fake_environment)
    _publish(fake_environment)
    _ = capsys.readouterr()
    assert main(["--json", "verify", "app", "--live"], repo_root=fake_environment.repo_root) == 0
    payload = json.loads(capsys.readouterr().out)["data"]
    assert [group["group"] for group in payload["groups"]] == [
        "manager",
        "routing",
        "origin",
        "access",
        "public_probe",
    ]
    for check in payload["checks"]:
        if check["publication_name"] is None:
            assert check["hostname"] is None
        else:
            assert check["publication_name"] == "app"
            assert check["hostname"] == "app.example.com"
    assert main(["verify", "app", "--live"], repo_root=fake_environment.repo_root) == 0
    text = capsys.readouterr().out
    for heading in ("Manager", "Routing", "Origin", "Access", "Public Probe"):
        assert f"== {heading} ==" in text
    paths = build_paths(fake_environment.repo_root, fake_environment.home)
    manifest = load_manifest(paths.state_file)
    assert manifest is not None
    with patch(
        "cloudflare_publish.verify_flow.CurlHttpClient.get",
        side_effect=AppError("Origin unavailable"),
    ):
        # Cloudflare calls use this transport too; all failures remain grouped evidence.
        assert (
            main(["--json", "verify", "app", "--live"], repo_root=fake_environment.repo_root) == 1
        )
    failed = json.loads(capsys.readouterr().out)
    assert failed["error"]["code"] == "verify_failed"
    assert (
        next(group for group in failed["data"]["groups"] if group["group"] == "origin")["failures"]
        == 1
    )
    assert (
        next(group for group in failed["data"]["groups"] if group["group"] == "public_probe")[
            "failures"
        ]
        == 2
    )


@pytest.mark.parametrize(
    "command",
    [
        ["setup", "--refresh-only"],
        [
            "publish",
            "apply",
            "app",
            "--yes",
            "--hostname",
            "app.example.com",
            "--to",
            "http://127.0.0.1:3000",
            "--audience",
            "machine",
        ],
        ["rm", "apply", "app", "--yes"],
        ["token", "rotate", "app", "--yes"],
        ["guard", "apply", "--yes"],
        ["tunnel", "recover", "apply", "--yes"],
        ["service", "start"],
        ["service", "stop"],
        ["service", "restart"],
        ["teardown", "--yes"],
    ],
)
def test_writer_exclusion_precedes_entire_workflow(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    """Every complete mutating command rejects contention before its first state change."""

    _setup(fake_environment)
    _publish(fake_environment)
    paths = build_paths(fake_environment.repo_root, fake_environment.home)
    before_remote = deepcopy(fake_environment.tool_state())
    before_manifest = paths.state_file.read_bytes()
    _ = capsys.readouterr()
    with ManagerWriterLock(paths):
        assert main(["--json", *command], repo_root=fake_environment.repo_root) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["error"]["code"] == "manager_busy"
        assert fake_environment.tool_state() == before_remote
        assert paths.state_file.read_bytes() == before_manifest
        assert main(["--json", "ls"], repo_root=fake_environment.repo_root) == 0
        _ = capsys.readouterr()
    assert main(["--json", "service", "status"], repo_root=fake_environment.repo_root) == 0


@pytest.mark.parametrize("failed_operation", ["os.fsync", "os.replace"])
def test_atomic_manifest_failure_preserves_previous_bytes_and_restricts_modes(
    fake_environment: FakeEnvironment, failed_operation: str
) -> None:
    """Failed atomic replacement cannot truncate the previous manifest or leak staging files."""

    _setup(fake_environment)
    paths = build_paths(fake_environment.repo_root, fake_environment.home)
    manifest = load_manifest(paths.state_file)
    assert manifest is not None
    before = paths.state_file.read_bytes()
    assert paths.state_file.stat().st_mode & 0o777 == 0o600
    previous_inode = paths.state_file.stat().st_ino
    write_manifest(paths.state_file, manifest)
    assert paths.state_file.stat().st_ino != previous_inode
    with (
        patch(f"cloudflare_publish.state.{failed_operation}", side_effect=OSError("disk failed")),
        pytest.raises(AppError, match="Could not persist state.json"),
    ):
        write_manifest(paths.state_file, manifest)
    assert paths.state_file.read_bytes() == before
    assert not list(paths.state_dir.glob(".state.json.*"))
    assert paths.state_file.stat().st_mode & 0o777 == 0o600
    assert paths.state_dir.stat().st_mode & 0o777 == 0o700


def test_teardown_keeps_lock_inode_and_releases_it(fake_environment: FakeEnvironment) -> None:
    """Deleting a held lock path cannot create a second writer domain during teardown."""

    _setup(fake_environment)
    paths = build_paths(fake_environment.repo_root, fake_environment.home)
    inode = (paths.state_dir / "manager.lock").stat().st_ino
    assert main(["teardown", "--yes"], repo_root=fake_environment.repo_root) == 0
    assert (paths.state_dir / "manager.lock").stat().st_ino == inode
    assert not paths.state_file.exists()
    with ManagerWriterLock(paths):
        assert (paths.state_dir / "manager.lock").stat().st_ino == inode


def test_lock_releases_after_failure(fake_environment: FakeEnvironment) -> None:
    """Process-owned lock release does not require manual stale-file removal."""

    paths = build_paths(fake_environment.repo_root, fake_environment.home)
    with pytest.raises(RuntimeError), ManagerWriterLock(paths):
        raise RuntimeError("workflow failed")
    with ManagerWriterLock(paths):
        assert os.stat(paths.state_dir / "manager.lock").st_mode & 0o777 == 0o600
