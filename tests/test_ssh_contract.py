"""SSH publication input and persistence boundaries beside existing HTTP state."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from cloudflare_publish.cli_parser import parse_args
from cloudflare_publish.errors import AppError
from cloudflare_publish.models import (
    ManagedPublication,
    ManagerConfig,
    PublicationRemoteState,
    PublishRequest,
)
from cloudflare_publish.publication_contract import build_publication_spec
from cloudflare_publish.state import (
    build_initial_manifest,
    load_manifest,
    replace_publications,
    write_manifest,
)

PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
).decode("ascii")


def _request(**changes: object) -> PublishRequest:
    request = PublishRequest(
        name="mac",
        hostname="mac.example.com",
        origin_url="ssh://127.0.0.1:22",
        audience="machine",
        allowed_emails=(),
        allowed_email_domains=(),
        verify_path=None,
        expect_status=None,
        http_host_header=None,
        origin_server_name=None,
        no_tls_verify=False,
        ssh_host_key=PUBLIC_KEY,
    )
    return replace(request, **changes)


def test_ssh_spec_and_parser_use_native_ssh_contract() -> None:
    args = parse_args(
        [
            "publish",
            "plan",
            "mac",
            "--hostname",
            "mac.example.com",
            "--to",
            "ssh://127.0.0.1:22",
            "--audience",
            "machine",
            "--ssh-host-key",
            PUBLIC_KEY,
        ]
    )
    assert args.ssh_host_key == PUBLIC_KEY
    spec = build_publication_spec(_request(ssh_host_key=PUBLIC_KEY + " local host key"))
    assert spec.kind == "ssh_public"
    assert spec.verify_path is None and spec.expect_status is None
    assert spec.ssh_host_key == PUBLIC_KEY


@pytest.mark.parametrize(
    "changes",
    [
        {"ssh_host_key": None},
        {"ssh_host_key": "ssh-ed25519 invalid"},
        {"audience": "public"},
        {"audience": "human"},
        {"audience": "mixed"},
        {"allowed_emails": ("ops@example.com",)},
        {"allowed_email_domains": ("example.com",)},
        {"verify_path": "/"},
        {"expect_status": "200-399"},
        {"http_host_header": "localhost"},
        {"origin_server_name": "localhost"},
        {"no_tls_verify": True},
        {"origin_url": "ssh://user:secret@localhost:22"},
        {"origin_url": "ssh://localhost:0"},
        {"origin_url": "ssh://localhost:65536"},
        {"origin_url": "ssh://localhost:22/path"},
        {"origin_url": "ssh://localhost:22?secret=yes"},
        {"origin_url": "tcp://localhost:22"},
        {"origin_url": "ssh://[invalid"},
    ],
)
def test_ssh_input_fails_closed(changes: dict[str, object]) -> None:
    with pytest.raises(AppError):
        build_publication_spec(_request(**changes))


def test_http_rejects_ssh_pin_and_keeps_its_probe_defaults() -> None:
    with pytest.raises(AppError, match="only valid for SSH"):
        build_publication_spec(_request(origin_url="http://localhost:3000"))
    spec = build_publication_spec(_request(origin_url="http://localhost:3000", ssh_host_key=None))
    assert spec.kind == "http_public"
    assert (spec.verify_path, spec.expect_status) == ("/", "200-399")
    assert spec.ssh_host_key is None


def _state_file(tmp_path: Path) -> Path:
    manifest = build_initial_manifest(
        manager=ManagerConfig(
            account_id="acc-1",
            account_name="Example",
            zone_id="zone-1",
            zone_name="example.com",
            auth_domain="example.cloudflareaccess.com",
            tunnel_name="manager",
            tunnel_id="tunnel-1",
            api_token_keychain_account="api-token",
        )
    )
    remote = PublicationRemoteState(
        dns_record_id="dns-1",
        access_application_id="app-1",
        access_aud="aud-1",
        policy_ids=("policy-1",),
        service_token_id="token-1",
        service_token_client_id="client-1",
        service_token_keychain_account="service-token:mac",
        updated_at="2026-10-20T00:00:00Z",
    )
    ssh = ManagedPublication(spec=build_publication_spec(_request()), state=remote)
    http = ManagedPublication(
        spec=build_publication_spec(
            _request(
                name="web",
                hostname="web.example.com",
                origin_url="http://127.0.0.1:3000",
                ssh_host_key=None,
            )
        ),
        state=replace(remote, dns_record_id="dns-2"),
    )
    manifest = replace_publications(manifest, publications={"mac": ssh, "web": http})
    path = tmp_path / "state.json"
    write_manifest(path, manifest)
    assert load_manifest(path) == manifest
    return path


def test_mixed_state_preserves_old_http_manifest_without_pin(tmp_path: Path) -> None:
    path = _state_file(tmp_path)
    payload = json.loads(path.read_text())
    del payload["publications"]["web"]["spec"]["ssh_host_key"]
    path.write_text(json.dumps(payload))
    manifest = load_manifest(path)
    assert manifest is not None
    assert manifest.publications["web"].spec.verify_path == "/"
    assert manifest.publications["mac"].spec.ssh_host_key == PUBLIC_KEY


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "http_public"},
        {"kind": "arbitrary"},
        {"ssh_host_key": None},
        {"audience": "public"},
        {"verify_path": "/"},
    ],
)
def test_state_rejects_invalid_ssh_contract(tmp_path: Path, changes: dict[str, object]) -> None:
    path = _state_file(tmp_path)
    payload = json.loads(path.read_text())
    payload["publications"]["mac"]["spec"].update(changes)
    path.write_text(json.dumps(payload))
    with pytest.raises(AppError):
        load_manifest(path)
