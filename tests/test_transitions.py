"""Canonical custody survives reload and projects the intended routes."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cloudflare_publish.cli_runtime import build_cli_runtime
from cloudflare_publish.cli_write_commands import _publication_credential_handoff
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
    replace_backups,
    replace_manager,
    replace_publications,
    write_manifest,
)
from cloudflare_publish.transitions import Mutation, effective_publications


def _manifest():
    return build_initial_manifest(
        manager=ManagerConfig(
            account_id="account",
            account_name="Account",
            zone_id="zone",
            zone_name="example.com",
            auth_domain="example.cloudflareaccess.com",
            tunnel_name="manager",
            tunnel_id="tunnel",
            api_token_keychain_account="api-token",
        )
    )


def _publication(name="target", port=3000):
    return ManagedPublication(
        spec=build_publication_spec(
            PublishRequest(
                name=name,
                hostname=f"{name}.example.com",
                origin_url=f"http://127.0.0.1:{port}",
                audience="machine",
                allowed_emails=(),
                allowed_email_domains=(),
                verify_path="/",
                expect_status="200-399",
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            )
        ),
        state=PublicationRemoteState(
            dns_record_id="dns",
            access_application_id="app",
            access_aud="aud",
            policy_ids=("policy",),
            service_token_id="token",
            service_token_client_id="client",
            service_token_keychain_account="isolated-token-account",
            updated_at="observed",
        ),
    )


def test_custody_roundtrip_fences_unknown_effect_and_preserves_unrelated_routes(tmp_path):
    path = tmp_path / "state.json"
    old, other, candidate = _publication(), _publication("other"), _publication(port=4000)
    manifest = replace_publications(_manifest(), publications={"target": old, "other": other})
    mutation = Mutation(
        path=path,
        manifest=manifest,
        kind="publish",
        target="target",
        request={"origin": candidate.spec.origin_url},
        candidate=candidate,
    )
    mutation.save(pending=replace(mutation.pending, phase="withdrawing", route="withdrawn"))
    mutation.before_effect(kind="access_application", resource_name="target:operation")
    persisted = load_manifest(path)
    assert persisted == mutation.manifest
    assert path.stat().st_mode & 0o777 == 0o600
    assert effective_publications(persisted) == {"other": other}
    assert persisted.publications == {"target": old, "other": other}
    resumed = Mutation(
        path=path,
        manifest=persisted,
        kind="publish",
        target="target",
        request={"origin": candidate.spec.origin_url},
    )
    with pytest.raises(AppError) as error:
        resumed.before_effect(kind="access_application", resource_name="target:operation")
    assert error.value.code == "outcome_unknown"
    assert load_manifest(path) == persisted
    with pytest.raises(AppError) as error:
        Mutation(path=path, manifest=persisted, kind="remove", target="other", request={})
    assert error.value.code == "transition_pending"
    assert load_manifest(path) == persisted
    resumed.observed(candidate=candidate)
    resumed.save(pending=replace(resumed.pending, route="candidate", phase="routed"))
    assert effective_publications(resumed.manifest) == {"target": candidate, "other": other}
    assert resumed.pending.effect is None
    assert resumed.pending.operation_id == persisted.pending.operation_id
    for changed in (
        replace_publications(resumed.manifest, publications=resumed.manifest.publications),
        replace_manager(resumed.manifest, manager=resumed.manifest.manager),
        replace_backups(resumed.manifest, manager=resumed.manifest.manager, backups=()),
    ):
        assert changed.pending == resumed.pending
    resumed.manifest = replace_publications(
        resumed.manifest, publications=effective_publications(resumed.manifest)
    )
    assert resumed.finish().pending is None
    assert load_manifest(path).publications == {"target": candidate, "other": other}


@pytest.mark.parametrize("schema", [True, 0, 2, "1"])
def test_unknown_schema_is_not_silently_rewritten(tmp_path, schema):
    path = tmp_path / "state.json"
    write_manifest(path, _manifest())
    payload = json.loads(path.read_text())
    payload["schema_version"] = schema
    original = json.dumps(payload)
    path.write_text(original)
    with pytest.raises(AppError):
        load_manifest(path)
    assert path.read_text() == original


@pytest.mark.parametrize("version", [True, -1, "3", 1.5])
def test_malformed_pending_version_keeps_file_untouched(tmp_path, version):
    path = tmp_path / "state.json"
    Mutation(path=path, manifest=_manifest(), kind="remove", target="target", request={})
    payload = json.loads(path.read_text())
    payload["pending"]["configuration_version"] = version
    original = json.dumps(payload)
    path.write_text(original)
    with pytest.raises(AppError):
        load_manifest(path)
    assert path.read_text() == original


def test_legacy_manifest_without_pending_still_loads(tmp_path):
    path = tmp_path / "state.json"
    write_manifest(path, _manifest())
    payload = json.loads(path.read_text())
    del payload["pending"]
    path.write_text(json.dumps(payload))
    loaded = load_manifest(path)
    assert loaded.pending is None
    assert loaded.manager == _manifest().manager
    assert loaded.publications == {}


def test_final_cli_handoff_loss_reports_already_applied_state(tmp_path: Path, monkeypatch):
    runtime = build_cli_runtime(repo_root=tmp_path, home=tmp_path)

    def unavailable(**kwargs):
        raise AppError("Secret unavailable")

    monkeypatch.setattr(runtime.keychain, "load_secret", unavailable)
    with pytest.raises(AppError) as error:
        _publication_credential_handoff(publication=_publication(), runtime=runtime)
    assert error.value.code == "credential_handoff_unavailable"
    assert error.value.data == {"publication_applied": True, "publication_name": "target"}
    assert "token rotate target --yes" in error.value.hints[0]
