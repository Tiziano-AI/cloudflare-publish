"""Protocol-specific inspect, discovery and shared-tunnel rendering coverage."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.cli_output import publication_spec_to_object
from cloudflare_publish.models import (
    ManagedPublication,
    OriginOptions,
    PublicationRemoteState,
    PublicationSpec,
)
from cloudflare_publish.paths import build_paths
from cloudflare_publish.render import build_tunnel_configuration
from cloudflare_publish.state import load_manifest, write_manifest
from tests.fake_environment import FakeEnvironment

_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"


def test_ssh_inspect_json_exposes_native_client_trust_not_http_probe_fields(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """SSH inspect describes public trust material without claiming HTTP semantics."""

    _install_ssh_publication(fake_environment)
    _ = capsys.readouterr()

    assert main(["--json", "inspect", "mac"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["output_class"] == "public_diagnostic"
    spec = payload["data"]["publication"]["spec"]
    assert spec["kind"] == "ssh_public"
    assert spec["origin_url"] == "ssh://127.0.0.1:22"
    assert spec["public_verify_url"] is None
    assert spec["verify_path"] is None
    assert spec["expect_status"] is None
    assert spec["origin_options"] is None
    assert spec["ssh_host_key"] == _HOST_KEY
    assert spec["ssh_client"] == {
        "proxy_command": "cloudflared access ssh --hostname %h --loglevel error",
        "known_hosts_line": f"mac.example.com {_HOST_KEY}",
        "host_key_algorithms": "ssh-ed25519",
        "strict_host_key_checking": "yes",
        "service_token_environment": ["TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET"],
    }
    assert "client_secret" not in captured.out
    assert "secret-" not in captured.out
    assert captured.err == ""


def test_ssh_inspect_human_has_no_http_or_origin_tls_claims(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """The human view distinguishes transport, host trust and operator-owned login."""

    _install_ssh_publication(fake_environment)
    _ = capsys.readouterr()

    assert main(["inspect", "mac"], repo_root=fake_environment.repo_root) == 0
    output = capsys.readouterr().out
    assert f"Pinned SSH host key: {_HOST_KEY}" in output
    assert f"SSH known_hosts line: mac.example.com {_HOST_KEY}" in output
    assert "SSH HostKeyAlgorithms: ssh-ed25519" in output
    assert "SSH StrictHostKeyChecking: yes" in output
    assert "SSH login user and private key remain operator-managed." in output
    assert "--loglevel error" in output
    for label in (
        "Public verify URL:",
        "Verify path:",
        "Expect status:",
        "Origin Host header:",
        "Origin server name:",
        "Origin TLS verification:",
    ):
        assert label not in output
    assert "secret-" not in output


def test_http_inspect_serialization_preserves_http_contract() -> None:
    """Adding SSH does not change the existing HTTP recipe and probe fields."""

    spec = publication_spec_to_object(_http_publication().spec)
    assert spec["public_verify_url"] == "https://web.example.com/healthz"
    assert spec["origin_options"] == {
        "http_host_header": "web.internal",
        "origin_server_name": "origin.internal",
        "no_tls_verify": True,
    }
    assert "ssh_client" not in spec
    assert "ssh_host_key" not in spec


def test_shared_tunnel_config_preserves_http_and_ssh_and_one_catch_all() -> None:
    """Mixed routing keeps HTTP options on HTTP and carries native SSH unchanged."""

    ssh = _ssh_publication()
    http = _http_publication()
    assert build_tunnel_configuration(
        {"web": http, "mac": ssh}, auth_domain="example.cloudflareaccess.com"
    ) == {
        "config": {
            "ingress": [
                {
                    "hostname": "mac.example.com",
                    "service": "ssh://127.0.0.1:22",
                    "originRequest": {
                        "access": {
                            "required": True,
                            "teamName": "example",
                            "audTag": [ssh.state.access_aud],
                        }
                    },
                },
                {
                    "hostname": "web.example.com",
                    "service": "https://127.0.0.1:8443",
                    "originRequest": {
                        "httpHostHeader": "web.internal",
                        "originServerName": "origin.internal",
                        "noTLSVerify": True,
                        "access": {
                            "required": True,
                            "teamName": "example",
                            "audTag": [http.state.access_aud],
                        },
                    },
                },
                {"service": "http_status:404"},
            ]
        }
    }


def test_ssh_render_never_attaches_http_options() -> None:
    """Even an invalid in-memory spec cannot leak HTTP connection options into SSH."""

    ssh = _ssh_publication()
    ssh = replace(
        ssh, spec=replace(ssh.spec, origin_options=_http_publication().spec.origin_options)
    )
    config = build_tunnel_configuration({"mac": ssh}, auth_domain="example.cloudflareaccess.com")
    assert config["config"]["ingress"][0] == {
        "hostname": "mac.example.com",
        "service": "ssh://127.0.0.1:22",
        "originRequest": {
            "access": {"required": True, "teamName": "example", "audTag": [ssh.state.access_aud]}
        },
    }


def test_ssh_discovery_sanitizes_service_and_keeps_other_protocols_unsupported(
    fake_environment: FakeEnvironment, capsys: pytest.CaptureFixture[str]
) -> None:
    """Remote SSH metadata is reported, not adopted or confused with generic TCP."""

    _setup(fake_environment)
    state = fake_environment.tool_state()
    state["cloudflare"]["tunnel_configurations"]["tunnel-1"]["config"]["ingress"] = [
        {"hostname": "mac.example.com", "service": "ssh://127.0.0.1:22"},
        {
            "hostname": "other.example.com",
            "service": "ssh://hidden-user:hidden-password@[::1]:2222/hidden-path?hidden-query#hidden-fragment",
            "originRequest": {"httpHostHeader": "hidden-http-header", "noTLSVerify": True},
        },
        {"hostname": "tcp.example.com", "service": "tcp://hidden-tcp-user@127.0.0.1:5000"},
        {"service": "http_status:404"},
    ]
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
    data = json.loads(captured.out)["data"]
    assert data["ingress"][0]["service"] == "ssh://127.0.0.1:22"
    assert data["ingress"][1]["service"] == "ssh://[::1]:2222"
    assert data["ingress"][1]["origin_options"] == {}
    assert data["ingress"][2]["service"] is None
    codes = {item["code"] for item in data["unsupported_topology"]}
    assert codes == {"noncanonical_origin_url", "http_origin_options_on_ssh", "unsupported_service"}
    assert "SSH hostname metadata only" in data["coverage"]
    assert "hidden-" not in captured.out
    assert captured.err == ""
    assert fake_environment.tool_state() == before
    paths = build_paths(repo_root=fake_environment.repo_root, home=fake_environment.home)
    manifest = load_manifest(paths.state_file)
    assert manifest is not None
    assert manifest.publications == {}


def _setup(environment: FakeEnvironment) -> None:
    """Create only a hermetic managed tunnel for the focused surface tests."""

    assert (
        main(
            ["setup", "--api-token", "token-1", "--account-id", "acc-123", "--zone", "example.com"],
            repo_root=environment.repo_root,
        )
        == 0
    )


def _install_ssh_publication(environment: FakeEnvironment) -> None:
    """Seed typed local ownership without exercising another worker's publish flow."""

    _setup(environment)
    paths = build_paths(repo_root=environment.repo_root, home=environment.home)
    manifest = load_manifest(paths.state_file)
    assert manifest is not None
    write_manifest(paths.state_file, replace(manifest, publications={"mac": _ssh_publication()}))


def _ssh_publication() -> ManagedPublication:
    """Build the minimal accepted SSH publication fixture."""

    return ManagedPublication(
        spec=PublicationSpec(
            kind="ssh_public",
            name="mac",
            hostname="mac.example.com",
            origin_url="ssh://127.0.0.1:22",
            audience="machine",
            allowed_emails=(),
            allowed_email_domains=(),
            verify_path=None,
            expect_status=None,
            origin_options=OriginOptions(None, None, False),
            ssh_host_key=_HOST_KEY,
        ),
        state=PublicationRemoteState(
            dns_record_id="dns-mac",
            access_application_id="app-mac",
            access_aud="aud-mac",
            policy_ids=("policy-mac",),
            service_token_id="token-mac",
            service_token_client_id="client-mac",
            service_token_keychain_account="service-token:mac",
            updated_at="2026-10-20T00:00:00Z",
        ),
    )


def _http_publication() -> ManagedPublication:
    """Build a full existing HTTPS contract for regression and mixed-config tests."""

    ssh = _ssh_publication()
    return replace(
        ssh,
        spec=replace(
            ssh.spec,
            kind="http_public",
            name="web",
            hostname="web.example.com",
            origin_url="https://127.0.0.1:8443",
            verify_path="/healthz",
            expect_status="200-204",
            origin_options=OriginOptions("web.internal", "origin.internal", True),
            ssh_host_key=None,
        ),
    )
