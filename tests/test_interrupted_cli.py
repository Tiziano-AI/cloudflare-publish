"""Consumer-path failure acceptance against the persisted hermetic vendor state.

The fake controls acceptance/response loss and connector observations; these tests
do not establish real Cloudflare propagation, JWT cryptography or session revocation.
Expected ownership and safety invariants are hand-authored, not rendered by product code.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment

_CONFIG_PATH = "/accounts/acc-123/cfd_tunnel/tunnel-1/configurations"
_TUNNEL_PATH = "/accounts/acc-123/cfd_tunnel/tunnel-1"
_APPS_PATH = "/accounts/acc-123/access/apps"


def test_setup_unknown_tunnel_post_retains_intent_before_a_tunnel_id_exists(
    fake_environment: FakeEnvironment,
) -> None:
    """An interrupted first setup owns its request without inventing a returned tunnel ID."""

    env = fake_environment
    path = "/accounts/acc-123/cfd_tunnel"
    env.inject_api_fault("POST", path, mode="after")
    assert _setup(env) == 1
    pending = deepcopy(_manifest(env)["pending"])
    assert pending is not None
    assert not _manifest(env)["manager"]["tunnel_id"]
    assert len(_cloudflare(env)["tunnels"]) == 1
    assert _setup(env) == 1
    assert _count_requests(env, "POST", path) == 1
    assert _manifest(env)["pending"] == pending
    assert (
        _run(
            env,
            "repair",
            "resolve",
            "--operation",
            pending["operation_id"],
            "--resource-id",
            "tunnel-1",
            "--yes",
        )
        == 0
    )
    assert _setup(env) == 0
    assert _manifest(env)["pending"] is None
    assert _manifest(env)["manager"]["tunnel_id"] == "tunnel-1"
    assert _count_requests(env, "POST", path) == 1


def test_remove_dns_failure_cannot_resurrect_route_on_setup_refresh(
    fake_environment: FakeEnvironment,
) -> None:
    """A retained removal excludes its route and blocks an incompatible refresh."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target") == 0
    assert _publish(env, "retained") == 0
    retained_before = deepcopy(_manifest(env)["publications"]["retained"])
    retained_rule = deepcopy(_rule(env, "retained.example.com"))
    target = _manifest(env)["publications"]["target"]
    dns_id = target["state"]["dns_record_id"]
    env.inject_api_fault("DELETE", f"/zones/zone-123/dns_records/{dns_id}")

    assert _run(env, "rm", "apply", "target", "--yes") == 1
    pending = _manifest(env)["pending"]
    assert pending is not None
    assert _rule(env, "target.example.com") is None
    requests_before = len(_cloudflare(env)["requests"])
    assert _run(env, "setup", "--refresh-only") == 1
    assert _rule(env, "target.example.com") is None
    writes = _cloudflare(env)["requests"][requests_before:]
    assert not [item for item in writes if item["method"] in {"POST", "PUT", "DELETE"}]
    assert _manifest(env)["pending"] == pending

    assert _run(env, "rm", "apply", "target", "--yes") == 0
    assert _manifest(env)["pending"] is None
    assert "target" not in _manifest(env)["publications"]
    assert _rule(env, "target.example.com") is None
    assert _manifest(env)["publications"]["retained"] == retained_before
    assert _rule(env, "retained.example.com") == retained_rule


def test_remove_keychain_delete_failure_keeps_cleanup_pending_until_retry(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """A revoked remote credential is not complete cleanup while its local secret remains."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target") == 0
    original = deepcopy(_manifest(env)["publications"]["target"])
    account = original["state"]["service_token_keychain_account"]
    key = f"cloudflare-publish:{account}"
    state = env.tool_state()
    state["security_fail_delete_once_account"] = key
    env.write_tool_state(state)
    _ = capsys.readouterr()

    assert _run(env, "--json", "rm", "apply", "target", "--yes") == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["error"]["code"] == "keychain_delete_failed"
    manifest = _manifest(env)
    assert manifest["pending"]["kind"] == "remove"
    assert manifest["pending"]["target"] == "target"
    assert manifest["publications"]["target"] == original
    assert key in env.tool_state()["keychain"]
    assert _rule(env, "target.example.com") is None
    assert _cloudflare(env)["service_tokens"] == {}

    assert _run(env, "rm", "apply", "target", "--yes") == 0
    assert _manifest(env)["pending"] is None
    assert "target" not in _manifest(env)["publications"]
    assert key not in env.tool_state()["keychain"]
    assert _rule(env, "target.example.com") is None


@pytest.mark.parametrize("mode", ["before", "after"])
def test_protected_to_public_interruption_never_removes_old_origin_protection(
    fake_environment: FakeEnvironment, mode: str
) -> None:
    """Rejected or response-lost cutover retains the old Access application."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target") == 0
    original = _manifest(env)["publications"]["target"]
    old_app = original["state"]["access_application_id"]
    old_rule = deepcopy(_rule(env, "target.example.com"))
    assert old_rule["originRequest"]["access"] == {
        "required": True,
        "teamName": "example",
        "audTag": [original["state"]["access_aud"]],
    }
    history_start = len(_cloudflare(env)["write_history"])
    env.inject_api_fault("PUT", _CONFIG_PATH, mode=mode)

    assert _publish(env, "target", audience="public", port=4000) == 1
    assert _manifest(env)["pending"] is not None
    assert old_app in _cloudflare(env)["access_apps"]
    for event in _cloudflare(env)["write_history"][history_start:]:
        rule = _rule_from_config(event["configurations"]["tunnel-1"], "target.example.com")
        if rule is not None and rule["service"] == "http://127.0.0.1:3000":
            assert old_app in event["apps"]
            assert rule["originRequest"]["access"]["required"] is True

    assert _publish(env, "target", audience="public", port=4000) == 0
    assert _manifest(env)["pending"] is None
    assert _rule(env, "target.example.com")["service"] == "http://127.0.0.1:4000"
    assert old_app not in _cloudflare(env)["access_apps"]


def test_authorization_boundary_replacement_gets_a_distinct_application_audience(
    fake_environment: FakeEnvironment,
) -> None:
    """New human authorization cannot inherit the old application's audience."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target", audience="human", email="old@example.com") == 0
    old = deepcopy(_manifest(env)["publications"]["target"])
    assert _publish(env, "target", audience="human", email="new@example.com", port=4000) == 0
    new = _manifest(env)["publications"]["target"]
    assert new["state"]["access_application_id"] != old["state"]["access_application_id"]
    assert new["state"]["access_aud"] != old["state"]["access_aud"]
    rule = _rule(env, "target.example.com")
    assert rule["service"] == "http://127.0.0.1:4000"
    assert rule["originRequest"]["access"]["audTag"] == [new["state"]["access_aud"]]
    policies = list(_cloudflare(env)["access_policies"].values())
    assert len(policies) == 1
    assert policies[0]["include"] == [{"email": {"email": "new@example.com"}}]


def test_connector_not_applying_cutover_prevents_cleanup_completion(
    fake_environment: FakeEnvironment,
) -> None:
    """Stored config is insufficient while an observed active connector is stale."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target") == 0
    old_app = _manifest(env)["publications"]["target"]["state"]["access_application_id"]
    state = env.tool_state()
    state["cloudflare"]["hold_local_config"] = True
    env.write_tool_state(state)

    assert _publish(env, "target", audience="public", port=4000) == 1
    assert _manifest(env)["pending"] is not None
    assert old_app in _cloudflare(env)["access_apps"]
    state = env.tool_state()
    cf = state["cloudflare"]
    cf["hold_local_config"] = False
    version = cf["tunnel_configurations"]["tunnel-1"]["version"]
    cf["tunnel_connections"]["tunnel-1"][0]["config_version"] = version
    env.write_tool_state(state)
    assert _publish(env, "target", audience="public", port=4000) == 0
    assert _manifest(env)["pending"] is None
    assert old_app not in _cloudflare(env)["access_apps"]


def test_accepted_post_response_loss_does_not_duplicate_an_application(
    fake_environment: FakeEnvironment,
) -> None:
    """Retry preserves an unknown POST outcome instead of creating a second app."""

    env = fake_environment
    assert _setup(env) == 0
    env.inject_api_fault("POST", _APPS_PATH, mode="after")
    assert _publish(env, "target", audience="human", email="person@example.com") == 1
    assert len(_cloudflare(env)["access_apps"]) == 1
    assert _manifest(env)["pending"] is not None
    pending_before = deepcopy(_manifest(env)["pending"])
    posts_before = _count_requests(env, "POST", _APPS_PATH)
    assert _publish(env, "target", audience="human", email="person@example.com") == 1
    assert len(_cloudflare(env)["access_apps"]) == 1
    assert _count_requests(env, "POST", _APPS_PATH) == posts_before
    assert _manifest(env)["pending"] == pending_before


def test_unknown_application_post_requires_exact_verified_resolution_before_resume(
    fake_environment: FakeEnvironment,
) -> None:
    """Only the pending operation's exact app can be adopted, without another POST."""

    env = fake_environment
    assert _setup(env) == 0
    env.inject_api_fault("POST", _APPS_PATH, mode="after")
    assert _publish(env, "target", audience="human", email="person@example.com") == 1
    pending = deepcopy(_manifest(env)["pending"])
    app_id = next(iter(_cloudflare(env)["access_apps"]))
    operation_id = pending["operation_id"]
    posts = _count_requests(env, "POST", _APPS_PATH)
    assert (
        _run(
            env,
            "repair",
            "resolve",
            "--operation",
            "unrelated-operation",
            "--resource-id",
            app_id,
            "--yes",
        )
        == 1
    )
    assert _manifest(env)["pending"] == pending

    # A real resource in the same account but for a different hostname/name is not ours.
    state = env.tool_state()
    wrong_app = {**state["cloudflare"]["access_apps"][app_id]}
    wrong_app.update(id="app-unrelated", name="someone-else", domain="someone.example.com")
    state["cloudflare"]["access_apps"]["app-unrelated"] = wrong_app
    env.write_tool_state(state)
    assert (
        _run(
            env,
            "repair",
            "resolve",
            "--operation",
            operation_id,
            "--resource-id",
            "app-unrelated",
            "--yes",
        )
        == 1
    )
    assert _manifest(env)["pending"] == pending

    assert (
        _run(
            env,
            "repair",
            "resolve",
            "--operation",
            operation_id,
            "--resource-id",
            app_id,
            "--yes",
        )
        == 0
    )
    assert _publish(env, "target", audience="human", email="person@example.com") == 0
    assert _manifest(env)["pending"] is None
    assert _manifest(env)["publications"]["target"]["state"]["access_application_id"] == app_id
    assert _count_requests(env, "POST", _APPS_PATH) == posts
    assert "app-unrelated" in _cloudflare(env)["access_apps"]


def test_process_death_after_accepted_post_retains_uncertainty_before_retry(
    fake_environment: FakeEnvironment,
) -> None:
    """The OS kills a CLI process between remote acceptance and local ID persistence."""

    env = fake_environment
    assert _setup(env) == 0
    env.inject_api_fault("POST", _APPS_PATH, mode="kill")
    arguments = _publish_arguments("target", audience="human", email="person@example.com")
    child_environment = dict(os.environ)
    child_environment["CLOUDFLARE_PUBLISH_TEST_ALLOW_KILL"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; import cloudflare_publish.paths as paths; "
            "from cloudflare_publish.host_platform import host_platform; "
            "paths.host_platform = lambda selected=None: host_platform(selected or 'darwin'); "
            "from cloudflare_publish.cli import main; "
            "raise SystemExit(main(sys.argv[2:], repo_root=Path(sys.argv[1])))",
            str(env.repo_root),
            *arguments,
        ],
        env=child_environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == -signal.SIGKILL
    assert len(_cloudflare(env)["access_apps"]) == 1
    pending = _manifest(env)["pending"]
    assert pending is not None
    assert pending["effect"] is not None
    posts = _count_requests(env, "POST", _APPS_PATH)
    assert _run(env, *arguments) == 1
    assert _count_requests(env, "POST", _APPS_PATH) == posts
    assert len(_cloudflare(env)["access_apps"]) == 1


@pytest.mark.parametrize("mode", ["before", "after"])
def test_absence_resolution_requires_no_matching_remote_creation(
    fake_environment: FakeEnvironment, mode: str
) -> None:
    """An empty scoped list permits replay; a matching accepted app forbids it."""

    env = fake_environment
    assert _setup(env) == 0
    env.inject_api_fault("POST", _APPS_PATH, mode=mode)
    assert _publish(env, "target", audience="human", email="person@example.com") == 1
    pending = deepcopy(_manifest(env)["pending"])
    operation_id = pending["operation_id"]
    result = _run(env, "repair", "resolve", "--operation", operation_id, "--absent", "--yes")
    if mode == "after":
        assert result == 1
        assert _manifest(env)["pending"] == pending
        assert _publish(env, "target", audience="human", email="person@example.com") == 1
        assert _count_requests(env, "POST", _APPS_PATH) == 1
    else:
        assert result == 0
        assert _publish(env, "target", audience="human", email="person@example.com") == 0
        assert _manifest(env)["pending"] is None
        assert len(_cloudflare(env)["access_apps"]) == 1
        assert _count_requests(env, "POST", _APPS_PATH) == 2


def test_lost_created_token_secret_requires_retirement_after_metadata_resolution(
    fake_environment: FakeEnvironment,
) -> None:
    """Finding a token ID does not recover its lost one-shot client secret."""

    env = fake_environment
    assert _setup(env) == 0
    token_path = "/accounts/acc-123/access/service_tokens"
    env.inject_api_fault("POST", token_path, mode="after")
    assert _publish(env, "target") == 1
    pending = _manifest(env)["pending"]
    token_id = next(iter(_cloudflare(env)["service_tokens"]))
    assert (
        _run(
            env,
            "repair",
            "resolve",
            "--operation",
            pending["operation_id"],
            "--resource-id",
            token_id,
            "--yes",
        )
        == 0
    )
    assert _manifest(env)["pending"]["effect"] is None
    assert _manifest(env)["pending"]["candidate"]["state"]["service_token_id"] == token_id
    assert _publish(env, "target") == 1
    assert _count_requests(env, "POST", token_path) == 1
    assert len(_cloudflare(env)["service_tokens"]) == 1
    assert (
        _run(
            env,
            "repair",
            "retire-token",
            "--operation",
            pending["operation_id"],
            "--resource-id",
            token_id,
            "--yes",
        )
        == 0
    )
    assert token_id not in _cloudflare(env)["service_tokens"]
    assert _publish(env, "target") == 0
    assert _manifest(env)["pending"] is None
    assert _count_requests(env, "POST", token_path) == 2
    assert len(_cloudflare(env)["service_tokens"]) == 1
    assert _manifest(env)["publications"]["target"]["state"]["service_token_id"] != token_id


@pytest.mark.parametrize("mode", ["before", "after"])
def test_teardown_retains_access_until_exact_tunnel_deletion_is_confirmed(
    fake_environment: FakeEnvironment, mode: str
) -> None:
    """Deletion rejection/lost response leaves protection and local custody intact."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target") == 0
    app_id = _manifest(env)["publications"]["target"]["state"]["access_application_id"]
    history_start = len(_cloudflare(env)["write_history"])
    env.inject_api_fault("DELETE", _TUNNEL_PATH, mode=mode)
    assert _run(env, "teardown", "--yes") == 1
    assert _state_path(env).exists()
    assert _manifest(env)["pending"] is not None
    assert app_id in _cloudflare(env)["access_apps"]
    assert _state_path(env).with_name("tunnel-token.txt").exists()
    assert _run(env, "teardown", "--yes") == 0
    assert not _state_path(env).exists()
    assert _cloudflare(env)["access_apps"] == {}
    writes = _cloudflare(env)["write_history"][history_start:]
    tunnel_delete = next(index for index, item in enumerate(writes) if item["path"] == _TUNNEL_PATH)
    access_delete = next(
        index for index, item in enumerate(writes) if item["path"] == f"{_APPS_PATH}/{app_id}"
    )
    assert tunnel_delete < access_delete


def test_foreign_replica_blocks_teardown_without_revoking_access(
    fake_environment: FakeEnvironment,
) -> None:
    """Local connector stop is not authority to disconnect a different replica."""

    env = fake_environment
    assert _setup(env) == 0
    assert _publish(env, "target") == 0
    app_id = _manifest(env)["publications"]["target"]["state"]["access_application_id"]
    env.add_foreign_connector()
    assert _run(env, "teardown", "--yes") == 1
    cf = _cloudflare(env)
    assert "tunnel-1" in cf["tunnels"]
    assert app_id in cf["access_apps"]
    assert _manifest(env)["pending"] is not None
    assert cf["cleaned_tunnel_ids"] == []
    assert _count_requests(env, "DELETE", _TUNNEL_PATH) == 0
    assert cf["tunnel_connections"]["tunnel-1"] == [
        {
            "id": "foreign-client",
            "config_version": 1,
            "conns": [{"id": "foreign-connection", "is_pending_reconnect": False}],
        }
    ]


def _run(env: FakeEnvironment, *arguments: str) -> int:
    return main(list(arguments), repo_root=env.repo_root)


def _setup(env: FakeEnvironment) -> int:
    return _run(
        env, "setup", "--api-token", "token-1", "--account-id", "acc-123", "--zone", "example.com"
    )


def _publish(
    env: FakeEnvironment,
    name: str,
    *,
    audience: str = "machine",
    port: int = 3000,
    email: str | None = None,
) -> int:
    return _run(env, *_publish_arguments(name, audience=audience, port=port, email=email))


def _publish_arguments(
    name: str,
    *,
    audience: str = "machine",
    port: int = 3000,
    email: str | None = None,
) -> list[str]:
    arguments = [
        "publish",
        "apply",
        name,
        "--yes",
        "--hostname",
        f"{name}.example.com",
        "--to",
        f"http://127.0.0.1:{port}",
        "--audience",
        audience,
    ]
    if email is not None:
        arguments.extend(("--allow-email", email))
    return arguments


def _state_path(env: FakeEnvironment) -> Path:
    return env.home / "Library" / "Application Support" / "cloudflare-publish" / "state.json"


def _manifest(env: FakeEnvironment):
    return json.loads(_state_path(env).read_text(encoding="utf-8"))


def _cloudflare(env: FakeEnvironment):
    return env.tool_state()["cloudflare"]


def _rule(env: FakeEnvironment, hostname: str):
    return _rule_from_config(_cloudflare(env)["tunnel_configurations"]["tunnel-1"], hostname)


def _rule_from_config(configuration, hostname: str):
    return next(
        (rule for rule in configuration["config"]["ingress"] if rule.get("hostname") == hostname),
        None,
    )


def _count_requests(env: FakeEnvironment, method: str, path: str) -> int:
    return sum(item == {"method": method, "path": path} for item in _cloudflare(env)["requests"])
