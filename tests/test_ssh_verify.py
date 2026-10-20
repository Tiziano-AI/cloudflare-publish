"""Hermetic SSH verification and Access fail-closed integration coverage."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.cloudflare_contract import access_application_from_object
from cloudflare_publish.errors import AppError
from tests.fake_environment import FakeEnvironment

HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"


def test_verify_ssh_checks_pinned_identity_without_claiming_login(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Direct and public probes prove pinned SSH transport and reveal no token secret."""

    _setup_and_publish(fake_environment)
    _ = capsys.readouterr()

    assert _verify(fake_environment) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    checks = {item["label"]: item for item in result["data"]["checks"]}
    assert checks["mac: SSH origin host key verified"]["ok"] is True
    assert checks["mac: public SSH host key verified"]["ok"] is True
    assert checks["mac: anonymous request denied"]["detail"] == "HTTP 401"
    assert not any("authenticated request succeeds" in label for label in checks)
    state = fake_environment.tool_state()
    assert state["ssh_probe_calls"] == [
        {"transport": "origin", "host": "127.0.0.1"},
        {"transport": "public", "host": "mac.example.com"},
    ]
    assert state["ssh_proxy_calls"] == [
        {"hostname": "mac.example.com", "has_client_id": True, "has_client_secret": True}
    ]
    assert all(
        token["client_secret"] not in output
        for token in state["cloudflare"]["service_tokens"].values()
    )


@pytest.mark.parametrize(
    "drift", ["strict_false", "strict_missing", "policy_allow", "policy_extra", "constraints"]
)
def test_verify_ssh_blocks_proxy_when_access_contract_drifts(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    drift: str,
) -> None:
    """Read-only verification does not launch a headless client under unsafe Access drift."""

    _setup_and_publish(fake_environment)
    _ = capsys.readouterr()
    state = fake_environment.tool_state()
    app = next(iter(state["cloudflare"]["access_apps"].values()))
    policy = next(iter(state["cloudflare"]["access_policies"].values()))
    if drift == "strict_false":
        app["service_auth_401_redirect"] = False
    elif drift == "strict_missing":
        del app["service_auth_401_redirect"]
    elif drift == "policy_allow":
        policy["decision"] = "allow"
    elif drift == "constraints":
        policy["require"] = [{"email": {"email": "extra@example.com"}}]
    else:
        state["cloudflare"]["access_policies"]["extra-policy"] = {
            **policy,
            "id": "extra-policy",
            "decision": "bypass",
        }
    fake_environment.write_tool_state(state)

    assert _verify(fake_environment) == 1
    checks = json.loads(capsys.readouterr().out)["data"]["checks"]
    public = next(item for item in checks if item["label"] == "mac: public SSH host key verified")
    assert public["ok"] is False
    assert "not started" in public["detail"]
    assert fake_environment.tool_state().get("ssh_proxy_calls", []) == []
    assert fake_environment.tool_state()["ssh_probe_calls"] == [
        {"transport": "origin", "host": "127.0.0.1"}
    ]


def test_verify_ssh_rejects_wrong_origin_and_public_pin(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Access authorization does not substitute for the pinned SSH server identity."""

    _setup_and_publish(fake_environment)
    _ = capsys.readouterr()
    state = fake_environment.tool_state()
    state["ssh_host_key"] = "ssh-ed25519 a-different-server-key"
    fake_environment.write_tool_state(state)

    assert _verify(fake_environment) == 1
    checks = json.loads(capsys.readouterr().out)["data"]["checks"]
    ssh_checks = [item for item in checks if "SSH" in item["label"]]
    assert len(ssh_checks) == 2
    assert all(item["ok"] is False for item in ssh_checks)


def test_verify_ssh_rejects_wrong_service_token_secret(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed proxy authorization cannot pass from a direct SSH-origin success."""

    _setup_and_publish(fake_environment)
    _ = capsys.readouterr()
    state = fake_environment.tool_state()
    token = next(iter(state["cloudflare"]["service_tokens"].values()))
    token["client_secret"] = "changed-remote-secret-not-in-output"
    fake_environment.write_tool_state(state)

    assert _verify(fake_environment) == 1
    output = capsys.readouterr().out
    checks = {item["label"]: item for item in json.loads(output)["data"]["checks"]}
    assert checks["mac: SSH origin host key verified"]["ok"] is True
    assert checks["mac: public SSH host key verified"]["ok"] is False
    assert "changed-remote-secret-not-in-output" not in output


def test_verify_combines_http_and_ssh_on_the_shared_tunnel(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Adding SSH preserves HTTP routes, HTTP probes, and shared grouped checks."""

    _setup_and_publish(fake_environment)
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
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["--json", "verify", "--live"], repo_root=fake_environment.repo_root) == 0
    checks = json.loads(capsys.readouterr().out)["data"]["checks"]
    assert any(
        item["label"] == "app: authenticated request succeeds" and item["ok"] for item in checks
    )
    assert any(
        item["label"] == "mac: public SSH host key verified" and item["ok"] for item in checks
    )
    assert all(
        item["group"] in {"manager", "routing", "origin", "access", "public_probe"}
        for item in checks
    )


@pytest.mark.parametrize("value", [True, False, None])
def test_access_application_decodes_exact_optional_strict_flag(value: bool | None) -> None:
    """Missing/false strict application metadata remains distinct from true."""

    app = access_application_from_object(
        {
            "id": "app",
            "name": "app",
            "domain": "mac.example.com",
            "aud": "aud",
            "service_auth_401_redirect": value,
        }
    )
    assert app.service_auth_401_redirect is value


@pytest.mark.parametrize("value", ["true", 1, [], {}])
def test_access_application_rejects_nonboolean_strict_flag(value: object) -> None:
    """Coercing truthy strings or numeric values cannot authorize a headless probe."""

    with pytest.raises(AppError, match="boolean or null"):
        access_application_from_object(
            {
                "id": "app",
                "name": "app",
                "domain": "mac.example.com",
                "aud": "aud",
                "service_auth_401_redirect": value,
            }
        )


def _setup_and_publish(environment: FakeEnvironment) -> None:
    """Create one machine-only SSH publication using hermetic API and process adapters."""

    assert (
        main(
            ["setup", "--api-token", "token-1", "--account-id", "acc-123", "--zone", "example.com"],
            repo_root=environment.repo_root,
        )
        == 0
    )
    state = environment.tool_state()
    state["ssh_host_key"] = HOST_KEY
    environment.write_tool_state(state)
    assert (
        main(
            [
                "publish",
                "apply",
                "mac",
                "--yes",
                "--hostname",
                "mac.example.com",
                "--to",
                "ssh://127.0.0.1:22",
                "--audience",
                "machine",
                "--ssh-host-key",
                HOST_KEY,
            ],
            repo_root=environment.repo_root,
        )
        == 0
    )


def _verify(environment: FakeEnvironment) -> int:
    """Collect public and direct SSH evidence through the operator entry point."""

    return main(["--json", "verify", "mac", "--live"], repo_root=environment.repo_root)
