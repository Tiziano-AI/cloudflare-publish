"""Recovery reaches the provider adapter and changes only verified ownership."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import override

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.cli_parser import parse_args
from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient, HttpConnectToEntry, HttpResponse
from cloudflare_publish.json_types import JsonArray, JsonObject, JsonValue, require_object
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.models import (
    ManagedPublication,
    ManagerConfig,
    OriginOptions,
    PendingEffect,
    PendingTransition,
    PublicationRemoteState,
    PublicationSpec,
    StateManifest,
)
from cloudflare_publish.process import CommandRunner
from cloudflare_publish.repair_flow import (
    pending_effect_candidates,
    resolve_pending_effect,
    retire_candidate_token,
)
from cloudflare_publish.state import build_initial_manifest, load_manifest, write_manifest
from tests.fake_environment import FakeEnvironment

_ROOT = "https://api.cloudflare.com/client/v4"
_ACCOUNT = "/accounts/account"
_APPS = _ACCOUNT + "/access/apps"
_TOKENS = _ACCOUNT + "/access/service_tokens"
_TUNNELS = _ACCOUNT + "/cfd_tunnel"
_DNS = "/zones/zone/dns_records"
_OPERATION = "operation-123"
_MARKER = f"demo:{_OPERATION}"
_HOSTNAME = "demo.example.com"
_PAGE = "?page=1&per_page=1000"


class _Http(CurlHttpClient):
    """Use actual API decoding and URL scoping, never a replacement recovery model."""

    def __init__(self) -> None:
        super().__init__(CommandRunner())
        self.responses: dict[tuple[str, str], list[HttpResponse]] = {}
        self.requests: list[tuple[str, str]] = []

    def queue(self, method: str, path: str, result: JsonObject | JsonArray) -> None:
        self.responses.setdefault((method, _ROOT + path), []).append(
            HttpResponse(status_code=200, body=json.dumps({"success": True, "result": result}))
        )

    @override
    def request(
        self,
        *,
        url: str,
        method: str,
        headers: dict[str, str],
        json_body: str | None,
        max_time: int,
        follow_redirects: bool,
        insecure: bool,
        connect_to: tuple[HttpConnectToEntry, ...],
    ) -> HttpResponse:
        del json_body, max_time, follow_redirects, insecure, connect_to
        assert headers == {"Authorization": "Bearer api-token"}
        self.requests.append((method, url))
        return self.responses[(method, url)].pop(0)


class _Keychain(Keychain):
    def __init__(self) -> None:
        super().__init__(CommandRunner())
        self.deleted_accounts: list[str] = []

    @override
    def delete_secret(self, *, account: str) -> None:
        self.deleted_accounts.append(account)


def _manifest(kind: str, *, audience: str = "machine") -> StateManifest:
    manager = ManagerConfig(
        account_id="account",
        account_name="Example",
        zone_id="zone",
        zone_name="example.com",
        auth_domain="example.cloudflareaccess.com",
        tunnel_name="manager",
        tunnel_id="tunnel",
        api_token_keychain_account="api-token",
    )
    candidate = ManagedPublication(
        spec=PublicationSpec(
            kind="http_public",
            name="demo",
            hostname=_HOSTNAME,
            origin_url="http://127.0.0.1:8000",
            audience=audience,
            allowed_emails=("alice@example.com",),
            allowed_email_domains=(),
            verify_path="/",
            expect_status="200-399",
            origin_options=OriginOptions(None, None, False),
        ),
        state=PublicationRemoteState(
            dns_record_id="",
            access_application_id=None,
            access_aud=None,
            policy_ids=(),
            service_token_id=None,
            service_token_client_id=None,
            service_token_keychain_account=None,
            updated_at="2026-10-20T00:00:00Z",
        ),
    )
    name = _HOSTNAME if kind == "dns" else _MARKER
    pending = PendingTransition(
        operation_id=_OPERATION,
        kind="publish",
        target="demo",
        request={"name": "demo"},
        candidate=candidate,
        effect=PendingEffect(kind=kind, resource_name=name),
    )
    if kind == "tunnel":
        manager = replace(manager, tunnel_id="")
        pending = replace(
            pending,
            kind="setup",
            target="manager",
            candidate=None,
            effect=PendingEffect(kind="tunnel", resource_name=f"manager:{_OPERATION}"),
        )
    return replace(build_initial_manifest(manager=manager), pending=pending)


def _resolve(
    tmp_path: Path,
    manifest: StateManifest,
    http: _Http,
    resource_id: str | None,
    *,
    absent: bool = False,
) -> StateManifest:
    path = tmp_path / "state.json"
    write_manifest(path, manifest)
    result = resolve_pending_effect(
        path=path,
        manifest=manifest,
        api=CloudflareApi(http, "api-token"),
        operation_id=_OPERATION,
        resource_id=resource_id,
        absent=absent,
    )
    assert load_manifest(path) == result
    assert result.pending is not None
    return result


def _app(**changes: JsonValue) -> JsonObject:
    result: JsonObject = {
        "id": "app-id",
        "name": _MARKER,
        "aud": "new-aud",
        "domain": _HOSTNAME,
        "type": "self_hosted",
        "service_auth_401_redirect": True,
        "destinations": [{"type": "public", "uri": _HOSTNAME}],
    }
    result.update(changes)
    return result


def test_exact_application_adoption_records_id_and_aud_without_completing(tmp_path: Path) -> None:
    http = _Http()
    http.queue("GET", _APPS + "/app-id", _app())
    http.queue("GET", _APPS + _PAGE, [_app()])
    result = _resolve(tmp_path, _manifest("access_application"), http, "app-id")
    assert result.pending is not None and result.pending.candidate is not None
    assert result.pending.candidate.state.access_application_id == "app-id"
    assert result.pending.candidate.state.access_aud == "new-aud"
    assert result.pending.effect is None
    assert result.publications == {}
    assert all(method == "GET" for method, _ in http.requests)


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "different-id"},
        {"name": "another-operation"},
        {"domain": "other.example.com"},
        {"aud": ""},
        {"service_auth_401_redirect": False},
        {"type": "ssh"},
        {"destinations": [{"type": "private", "uri": _HOSTNAME}]},
        {"destinations": [{"type": "public", "uri": "other.example.com"}]},
        {"destinations": [{"type": "public", "uri": _HOSTNAME, "overrides": {"x": True}}]},
    ],
)
def test_application_metadata_or_topology_mismatch_keeps_original_custody(
    tmp_path: Path,
    changes: JsonObject,
) -> None:
    manifest = _manifest("access_application")
    path = tmp_path / "state.json"
    write_manifest(path, manifest)
    http = _Http()
    http.queue("GET", _APPS + "/app-id", _app(**changes))
    http.queue("GET", _APPS + _PAGE, [_app(**changes)])
    with pytest.raises(AppError):
        _ = _resolve(tmp_path, manifest, http, "app-id")
    assert load_manifest(path) == manifest


def test_operation_mismatch_and_path_injection_fail_before_provider_read(tmp_path: Path) -> None:
    manifest = _manifest("access_application")
    http = _Http()
    for operation, resource in [("other", "app-id"), (_OPERATION, "../other")]:
        with pytest.raises(AppError):
            _ = resolve_pending_effect(
                path=tmp_path / "state.json",
                manifest=manifest,
                api=CloudflareApi(http, "api-token"),
                operation_id=operation,
                resource_id=resource,
            )
    assert http.requests == []


def test_exact_tunnel_adoption_requires_operation_marker_and_live_remote_config(
    tmp_path: Path,
) -> None:
    http = _Http()
    http.queue(
        "GET",
        _TUNNELS + "/created-tunnel",
        {
            "id": "created-tunnel",
            "name": f"manager:{_OPERATION}",
            "created_at": "2026-10-20T00:00:00Z",
            "remote_config": True,
        },
    )
    result = _resolve(tmp_path, _manifest("tunnel"), http, "created-tunnel")
    assert result.manager.tunnel_id == "created-tunnel"
    assert result.pending is not None and result.pending.phase == "tunnel_created"
    assert result.pending.effect is None


@pytest.mark.parametrize(
    "record",
    [
        {
            "id": "dns-id",
            "name": _HOSTNAME,
            "type": "A",
            "content": "tunnel.cfargotunnel.com",
            "proxied": True,
        },
        {
            "id": "dns-id",
            "name": _HOSTNAME,
            "type": "CNAME",
            "content": "foreign.cfargotunnel.com",
            "proxied": True,
        },
        {
            "id": "dns-id",
            "name": _HOSTNAME,
            "type": "CNAME",
            "content": "tunnel.cfargotunnel.com",
            "proxied": False,
        },
    ],
)
def test_dns_wrong_type_target_or_proxy_flag_cannot_be_adopted(
    tmp_path: Path, record: JsonObject
) -> None:
    http = _Http()
    http.queue("GET", _DNS + _PAGE + "&name=" + _HOSTNAME, [record])
    with pytest.raises(AppError):
        _ = _resolve(tmp_path, _manifest("dns"), http, "dns-id")


def test_dns_adoption_checks_exact_owned_zone_hostname_cname_and_proxy(tmp_path: Path) -> None:
    http = _Http()
    http.queue(
        "GET",
        _DNS + _PAGE + "&name=" + _HOSTNAME,
        [
            {
                "id": "dns-id",
                "name": _HOSTNAME,
                "type": "CNAME",
                "content": "tunnel.cfargotunnel.com",
                "proxied": True,
            }
        ],
    )
    result = _resolve(tmp_path, _manifest("dns"), http, "dns-id")
    assert result.pending is not None and result.pending.candidate is not None
    assert result.pending.candidate.state.dns_record_id == "dns-id"


def _policy_manifest() -> StateManifest:
    manifest = _manifest("policy")
    assert manifest.pending is not None and manifest.pending.candidate is not None
    candidate = replace(
        manifest.pending.candidate,
        state=replace(
            manifest.pending.candidate.state,
            access_application_id="app-id",
            access_aud="aud",
            service_token_id="token-id",
            service_token_client_id="client-id",
        ),
    )
    return replace(
        manifest,
        pending=replace(
            manifest.pending,
            candidate=candidate,
            effect=PendingEffect(
                kind="policy", resource_name=f"{_MARKER}:machine", resource_id="app-id"
            ),
        ),
    )


def _policy(**changes: JsonValue) -> JsonObject:
    result: JsonObject = {
        "id": "policy-id",
        "name": f"{_MARKER}:machine",
        "decision": "non_identity",
        "include": [{"service_token": {"token_id": "token-id"}}],
        "precedence": 2,
    }
    result.update(changes)
    return result


def test_policy_adoption_checks_parent_order_and_authorization(tmp_path: Path) -> None:
    http = _Http()
    http.queue("GET", _APPS + "/app-id/policies?page=1&per_page=200", [_policy()])
    result = _resolve(tmp_path, _policy_manifest(), http, "policy-id")
    assert result.pending is not None and result.pending.candidate is not None
    assert result.pending.candidate.state.policy_ids == ("policy-id",)


@pytest.mark.parametrize(
    "changes",
    [
        {"decision": "allow"},
        {"precedence": 1},
        {"include": [{"everyone": None}]},
        {"require": [{"email": {"email": "other@example.com"}}]},
    ],
)
def test_policy_authorization_drift_cannot_be_adopted(tmp_path: Path, changes: JsonObject) -> None:
    http = _Http()
    http.queue("GET", _APPS + "/app-id/policies?page=1&per_page=200", [_policy(**changes)])
    with pytest.raises(AppError):
        _ = _resolve(tmp_path, _policy_manifest(), http, "policy-id")


def test_service_token_resolution_retains_metadata_not_an_invented_secret(tmp_path: Path) -> None:
    http = _Http()
    http.queue(
        "GET",
        _TOKENS + "/token-id",
        {
            "id": "token-id",
            "name": _MARKER,
            "client_id": "client-id",
            "client_secret": "ignored",
        },
    )
    result = _resolve(tmp_path, _manifest("service_token"), http, "token-id")
    assert result.pending is not None and result.pending.candidate is not None
    state = result.pending.candidate.state
    assert state.service_token_id == "token-id"
    assert state.service_token_client_id == "client-id"
    assert state.service_token_keychain_account == f"service-token:demo:{_OPERATION}"
    assert "ignored" not in (tmp_path / "state.json").read_text()
    assert result.pending.effect is None


def test_absence_uses_complete_marker_scope_and_only_clears_unknown_effect(tmp_path: Path) -> None:
    http = _Http()
    http.queue("GET", _APPS + _PAGE, [_app(name="different-operation")])
    manifest = _manifest("access_application")
    assert manifest.pending is not None
    result = _resolve(tmp_path, manifest, http, None, absent=True)
    assert result.pending == replace(manifest.pending, effect=None)
    assert result.publications == manifest.publications


def test_present_marker_refuses_absence_even_when_resource_is_not_adoptable(tmp_path: Path) -> None:
    http = _Http()
    http.queue("GET", _APPS + _PAGE, [_app(type="foreign")])
    with pytest.raises(AppError, match="still exists"):
        _ = _resolve(tmp_path, _manifest("access_application"), http, None, absent=True)


def test_list_failure_cannot_turn_unknown_into_absent(tmp_path: Path) -> None:
    http = _Http()
    http.responses[("GET", _ROOT + _APPS + _PAGE)] = [HttpResponse(status_code=403, body="denied")]
    manifest = _manifest("access_application")
    with pytest.raises(AppError):
        _ = _resolve(tmp_path, manifest, http, None, absent=True)
    assert load_manifest(tmp_path / "state.json") == manifest


def test_absence_requires_the_last_page_of_the_exact_marker_scope(tmp_path: Path) -> None:
    manifest = _manifest("access_application")
    http = _Http()
    for page, entries in [(1, [_app(id="unrelated", name="other")]), (2, [_app()])]:
        path = _ROOT + _APPS + f"?page={page}&per_page=1000"
        http.responses[("GET", path)] = [
            HttpResponse(
                status_code=200,
                body=json.dumps(
                    {
                        "success": True,
                        "result": entries,
                        "result_info": {"total_pages": 2},
                    }
                ),
            )
        ]
    with pytest.raises(AppError, match="still exists"):
        _ = _resolve(tmp_path, manifest, http, None, absent=True)
    assert len(http.requests) == 2
    assert load_manifest(tmp_path / "state.json") == manifest


def test_pending_candidates_are_secret_free_marked_metadata_not_adoption(tmp_path: Path) -> None:
    manifest = _manifest("service_token")
    http = _Http()
    http.queue(
        "GET",
        _TOKENS + _PAGE,
        [
            {
                "id": "token-id",
                "name": _MARKER,
                "client_id": "client-id",
                "client_secret": "ignored",
            },
            {"id": "other", "name": "other-operation", "client_id": "other-client"},
        ],
    )
    write_manifest(tmp_path / "state.json", manifest)
    candidates = pending_effect_candidates(manifest=manifest, api=CloudflareApi(http, "api-token"))
    assert candidates == ({"id": "token-id", "name": _MARKER, "type": "service_token"},)
    assert load_manifest(tmp_path / "state.json") == manifest


def _candidate_token_manifest(*, retiring: bool = False) -> StateManifest:
    manifest = _manifest("service_token")
    assert manifest.pending is not None and manifest.pending.candidate is not None
    candidate = replace(
        manifest.pending.candidate,
        state=replace(
            manifest.pending.candidate.state,
            service_token_id="token-id",
            service_token_client_id="client-id",
            service_token_keychain_account=f"service-token:demo:{_OPERATION}",
        ),
    )
    effect = (
        PendingEffect(kind="token_retire", resource_name=_MARKER, resource_id="token-id")
        if retiring
        else None
    )
    return replace(manifest, pending=replace(manifest.pending, candidate=candidate, effect=effect))


@pytest.mark.parametrize("phase", ["started", "routing", "routed", "cleanup"])
def test_exact_lost_candidate_token_retirement_confirms_remote_absence(
    tmp_path: Path,
    phase: str,
) -> None:
    manifest = _candidate_token_manifest()
    assert manifest.pending is not None
    manifest = replace(manifest, pending=replace(manifest.pending, phase=phase))
    assert manifest.pending is not None
    http = _Http()
    http.queue(
        "GET", _TOKENS + _PAGE, [{"id": "token-id", "name": _MARKER, "client_id": "client-id"}]
    )
    http.queue("DELETE", _TOKENS + "/token-id", {})
    http.queue("GET", _TOKENS + _PAGE, [])
    keychain = _Keychain()
    result = retire_candidate_token(
        path=tmp_path / "state.json",
        manifest=manifest,
        api=CloudflareApi(http, "api-token"),
        keychain=keychain,
        operation_id=_OPERATION,
        resource_id="token-id",
    )
    assert result.pending is not None and result.pending.candidate is not None
    assert result.pending.candidate.state.service_token_id is None
    assert result.pending.effect is None
    assert result.pending.phase == ("started" if phase == "started" else "credentials_retired")
    assert result.pending.route == manifest.pending.route
    assert keychain.deleted_accounts == [f"service-token:demo:{_OPERATION}"]
    assert result.publications == {}


def test_retirement_response_lost_retains_fence_then_resolves_by_complete_absence(
    tmp_path: Path,
) -> None:
    manifest = _candidate_token_manifest()
    assert manifest.pending is not None
    http = _Http()
    http.queue(
        "GET", _TOKENS + _PAGE, [{"id": "token-id", "name": _MARKER, "client_id": "client-id"}]
    )
    http.responses[("DELETE", _ROOT + _TOKENS + "/token-id")] = [
        HttpResponse(status_code=502, body="unknown")
    ]
    keychain = _Keychain()
    path = tmp_path / "state.json"
    with pytest.raises(AppError):
        _ = retire_candidate_token(
            path=path,
            manifest=manifest,
            api=CloudflareApi(http, "api-token"),
            keychain=keychain,
            operation_id=_OPERATION,
            resource_id="token-id",
        )
    retained = load_manifest(path)
    assert retained is not None and retained.pending is not None
    assert retained.pending.effect is not None and retained.pending.effect.kind == "token_retire"
    assert retained.pending.candidate == manifest.pending.candidate
    assert keychain.deleted_accounts == []
    http.queue("GET", _TOKENS + _PAGE, [])
    http.queue("GET", _TOKENS + _PAGE, [])
    result = retire_candidate_token(
        path=path,
        manifest=retained,
        api=CloudflareApi(http, "api-token"),
        keychain=keychain,
        operation_id=_OPERATION,
        resource_id="token-id",
    )
    assert result.pending is not None and result.pending.effect is None
    assert [method for method, _ in http.requests].count("DELETE") == 1


def test_retire_cannot_delete_a_canonical_publication_token(tmp_path: Path) -> None:
    manifest = _candidate_token_manifest()
    assert manifest.pending is not None and manifest.pending.candidate is not None
    manifest = replace(
        manifest,
        publications={
            "original": replace(
                manifest.pending.candidate,
                spec=replace(manifest.pending.candidate.spec, name="original"),
            )
        },
    )
    http = _Http()
    with pytest.raises(AppError, match="already owned"):
        _ = retire_candidate_token(
            path=tmp_path / "state.json",
            manifest=manifest,
            api=CloudflareApi(http, "api-token"),
            keychain=_Keychain(),
            operation_id=_OPERATION,
            resource_id="token-id",
        )
    assert http.requests == []


def test_interrupted_policy_retirement_preserves_human_policy_and_token_custody(
    tmp_path: Path,
) -> None:
    manifest = _candidate_token_manifest()
    assert manifest.pending is not None and manifest.pending.candidate is not None
    candidate = replace(
        manifest.pending.candidate,
        spec=replace(manifest.pending.candidate.spec, audience="mixed"),
        state=replace(
            manifest.pending.candidate.state,
            access_application_id="app-id",
            access_aud="aud",
            policy_ids=("human-policy", "policy-id"),
        ),
    )
    manifest = replace(manifest, pending=replace(manifest.pending, candidate=candidate))
    human: JsonObject = {
        "id": "human-policy",
        "name": f"{_MARKER}:human",
        "decision": "allow",
        "include": [{"email": {"email": "alice@example.com"}}],
        "precedence": 1,
    }
    token: JsonObject = {"id": "token-id", "name": _MARKER, "client_id": "client-id"}
    policies_path = _APPS + "/app-id/policies?page=1&per_page=200"
    delete_path = _APPS + "/app-id/policies/policy-id"
    http = _Http()
    http.queue("GET", _TOKENS + _PAGE, [token])
    http.queue("GET", policies_path, [human, _policy()])
    http.responses[("DELETE", _ROOT + delete_path)] = [
        HttpResponse(status_code=502, body="unknown")
    ]
    keychain = _Keychain()
    state_path = tmp_path / "state.json"
    with pytest.raises(AppError):
        _ = retire_candidate_token(
            path=state_path,
            manifest=manifest,
            api=CloudflareApi(http, "api-token"),
            keychain=keychain,
            operation_id=_OPERATION,
            resource_id="token-id",
        )
    retained = load_manifest(state_path)
    assert retained is not None and retained.pending is not None
    assert retained.pending.effect is not None and retained.pending.effect.kind == "token_retire"
    assert retained.pending.candidate == candidate
    http.queue("GET", _TOKENS + _PAGE, [token])
    http.queue("GET", policies_path, [human])
    http.queue("DELETE", _TOKENS + "/token-id", {})
    http.queue("GET", _TOKENS + _PAGE, [])
    result = retire_candidate_token(
        path=state_path,
        manifest=retained,
        api=CloudflareApi(http, "api-token"),
        keychain=keychain,
        operation_id=_OPERATION,
        resource_id="token-id",
    )
    assert result.pending is not None and result.pending.candidate is not None
    assert result.pending.candidate.state.policy_ids == ("human-policy",)
    assert result.pending.candidate.state.service_token_id is None
    assert [(method, path) for method, path in http.requests if method == "DELETE"] == [
        ("DELETE", _ROOT + delete_path),
        ("DELETE", _ROOT + _TOKENS + "/token-id"),
    ]


def test_parser_separates_explicit_resolution_absence_retirement_and_rotation_reissue() -> None:
    args = parse_args(
        ["repair", "resolve", "--operation", _OPERATION, "--resource-id", "app-id", "--yes"]
    )
    assert (args.operation_id, args.resource_id, args.absent, args.yes) == (
        _OPERATION,
        "app-id",
        False,
        True,
    )
    absent = parse_args(["repair", "resolve", "--operation", _OPERATION, "--absent", "--yes"])
    assert absent.absent and absent.resource_id is None
    retire = parse_args(
        ["repair", "retire-token", "--operation", _OPERATION, "--resource-id", "token-id", "--yes"]
    )
    assert retire.repair_command == "retire-token"
    recover = parse_args(["token", "rotate", "demo", "--recover", "--yes"])
    assert recover.recover and recover.yes
    with pytest.raises(AppError):
        _ = parse_args(
            ["repair", "resolve", "--operation", _OPERATION, "--absent", "--resource-id", "id"]
        )


@pytest.mark.parametrize("audience", ["machine", "mixed"])
def test_late_routing_secret_loss_can_retire_then_resume_exact_publication(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    audience: str,
) -> None:
    """Credential retirement invalidates preparation, not the guarded route checkpoint."""

    env = fake_environment
    state_path = env.home / "Library" / "Application Support" / "cloudflare-publish" / "state.json"
    assert (
        main(
            ["setup", "--api-token", "token-1", "--account-id", "acc-123", "--zone", "example.com"],
            repo_root=env.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()
    state = env.tool_state()
    cf = require_object(state["cloudflare"], message="fake Cloudflare state missing")
    cf["hold_local_config"] = True
    env.write_tool_state(state)
    arguments = [
        "--json",
        "publish",
        "apply",
        "target",
        "--yes",
        "--hostname",
        "target.example.com",
        "--to",
        "http://127.0.0.1:3000",
        "--audience",
        audience,
    ]
    if audience == "mixed":
        arguments.extend(["--allow-email", "alice@example.com"])
    assert main(arguments, repo_root=env.repo_root) == 1
    _ = capsys.readouterr()
    stalled = load_manifest(state_path)
    assert stalled is not None and stalled.pending is not None
    pending = stalled.pending
    assert pending.phase == "routing" and pending.route == "candidate"
    assert pending.candidate is not None
    original = pending.candidate.state
    assert original.service_token_id is not None
    assert original.service_token_keychain_account is not None
    state = env.tool_state()
    keychain = require_object(state["keychain"], message="fake Keychain state missing")
    _ = keychain.pop(f"cloudflare-publish:{original.service_token_keychain_account}")
    cf = require_object(state["cloudflare"], message="fake Cloudflare state missing")
    configurations = require_object(cf["tunnel_configurations"], message="fake configs missing")
    routed_config = require_object(configurations["tunnel-1"], message="fake tunnel config missing")
    routed_body = json.dumps(routed_config["config"], sort_keys=True)
    connections = require_object(cf["tunnel_connections"], message="fake clients missing")
    clients = connections["tunnel-1"]
    assert isinstance(clients, list) and clients
    client = require_object(clients[0], message="fake local client missing")
    client["config_version"] = routed_config["version"]
    cf["hold_local_config"] = False
    env.write_tool_state(state)
    assert (
        main(
            [
                "--json",
                "repair",
                "retire-token",
                "--operation",
                pending.operation_id,
                "--resource-id",
                original.service_token_id,
                "--yes",
            ],
            repo_root=env.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()
    retired = load_manifest(state_path)
    assert retired is not None and retired.pending is not None
    assert retired.pending.phase == "credentials_retired"
    assert retired.pending.route == "candidate"
    assert retired.pending.candidate is not None
    retired_state = retired.pending.candidate.state
    assert retired_state.service_token_id is None
    assert retired_state.access_application_id == original.access_application_id
    assert retired_state.access_aud == original.access_aud
    assert retired_state.dns_record_id == original.dns_record_id
    assert retired_state.policy_ids == (original.policy_ids[:1] if audience == "mixed" else ())
    assert main(arguments, repo_root=env.repo_root) == 0
    _ = capsys.readouterr()
    completed = load_manifest(state_path)
    assert completed is not None and completed.pending is None
    publication = completed.publications["target"]
    assert publication.state.service_token_id != original.service_token_id
    assert publication.state.service_token_id is not None
    assert publication.state.access_application_id == original.access_application_id
    assert publication.state.access_aud == original.access_aud
    assert publication.state.dns_record_id == original.dns_record_id
    assert len(publication.state.policy_ids) == (2 if audience == "mixed" else 1)
    if audience == "mixed":
        assert publication.state.policy_ids[0] == original.policy_ids[0]
    state = env.tool_state()
    cf = require_object(state["cloudflare"], message="fake Cloudflare state missing")
    tokens = require_object(cf["service_tokens"], message="fake tokens missing")
    assert original.service_token_id not in tokens
    assert publication.state.service_token_id in tokens
    configurations = require_object(cf["tunnel_configurations"], message="fake configs missing")
    config = require_object(configurations["tunnel-1"], message="fake tunnel config missing")
    assert json.dumps(config["config"], sort_keys=True) == routed_body
    ingress = require_object(config["config"], message="fake ingress config missing")["ingress"]
    assert isinstance(ingress, list)
    target = require_object(ingress[0], message="fake target route missing")
    options = require_object(target["originRequest"], message="fake guard missing")
    assert options["access"] == {
        "required": True,
        "teamName": "example",
        "audTag": [original.access_aud],
    }
    keychain = require_object(state["keychain"], message="fake Keychain state missing")
    secret = keychain[f"cloudflare-publish:{publication.state.service_token_keychain_account}"]
    assert isinstance(secret, str) and secret
