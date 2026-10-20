"""Resource custody and authorization-boundary regressions for publication changes."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.cloudflare_contract import ServiceTokenSecret
from cloudflare_publish.errors import AppError
from cloudflare_publish.models import (
    ManagedPublication,
    ManagerConfig,
    OriginOptions,
    PublicationRemoteState,
    PublicationSpec,
)
from cloudflare_publish.publication_remote import (
    _ensure_token,
    authorization_boundary_matches,
    delete_publication_remote,
    preflight_publication_credentials,
    publication_candidate,
    publication_request,
)
from cloudflare_publish.state import build_initial_manifest, load_manifest
from cloudflare_publish.transitions import Mutation
from tests.fake_environment import FakeEnvironment


def _publication() -> ManagedPublication:
    return ManagedPublication(
        spec=PublicationSpec(
            kind="http_public",
            name="target",
            hostname="target.example.com",
            origin_url="http://127.0.0.1:3000",
            audience="machine",
            allowed_emails=(),
            allowed_email_domains=(),
            verify_path="/",
            expect_status="200-399",
            origin_options=OriginOptions(None, None, False),
        ),
        state=PublicationRemoteState(
            dns_record_id="dns-old",
            access_application_id="app-old",
            access_aud="aud-old",
            policy_ids=("policy-old",),
            service_token_id="token-old",
            service_token_client_id="client-old",
            service_token_keychain_account="token:old",
            updated_at="2026-10-20T00:00:00Z",
        ),
    )


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


def test_origin_only_change_keeps_existing_authorization_identities() -> None:
    """An unchanged boundary does not needlessly recreate apps, policy or credentials."""

    old = _publication()
    spec = replace(old.spec, origin_url="http://127.0.0.1:4000")
    candidate = publication_candidate(spec, old)
    assert candidate.spec == spec
    assert candidate.state is old.state


@pytest.mark.parametrize(
    "change",
    [
        {"hostname": "other.example.com"},
        {"audience": "mixed", "allowed_emails": ("person@example.com",)},
        {"allowed_emails": ("person@example.com",)},
        {"allowed_email_domains": ("example.com",)},
    ],
)
def test_authorization_boundary_changes_cannot_reuse_application_audience(change) -> None:
    old = _publication()
    spec = replace(old.spec, **change)
    assert not authorization_boundary_matches(old.spec, spec)
    candidate = publication_candidate(spec, old)
    assert candidate.state.access_application_id is None
    assert candidate.state.access_aud is None
    assert not candidate.state.policy_ids
    # A machine token remains the same client identity, but can acquire a JWT
    # for the replacement audience only through that new application's policy.
    assert candidate.state.service_token_id == "token-old"


def test_allow_rule_order_does_not_replace_an_application() -> None:
    old = replace(
        _publication().spec, audience="human", allowed_emails=("one@example.com", "two@example.com")
    )
    reordered = replace(old, allowed_emails=tuple(reversed(old.allowed_emails)))
    assert authorization_boundary_matches(old, reordered)


class _RetirementApi:
    def __init__(self, *, fail_dns=False):
        self.events = []
        self.fail_dns = fail_dns

    def delete_dns_record(self, **kwargs):
        self.events.append(("dns", kwargs["record_id"]))
        assert kwargs["missing_ok"]
        if self.fail_dns:
            raise AppError("DNS deletion failed")

    def delete_access_application(self, **kwargs):
        self.events.append(("access", kwargs["application_id"]))
        assert kwargs["missing_ok"]

    def delete_service_token(self, **kwargs):
        self.events.append(("token", kwargs["service_token_id"]))
        assert kwargs["missing_ok"]


class _RetirementKeychain:
    def __init__(self):
        self.events = []

    def delete_secret(self, **kwargs):
        self.events.append(kwargs["account"])


def test_dns_retirement_failure_keeps_access_token_and_local_secret() -> None:
    api = _RetirementApi(fail_dns=True)
    keychain = _RetirementKeychain()
    with pytest.raises(AppError, match="DNS deletion failed"):
        delete_publication_remote(
            api=api, keychain=keychain, manifest=_manifest(), publication=_publication()
        )
    assert api.events == [("dns", "dns-old")]
    assert not keychain.events


def test_update_cleanup_preserves_reused_dns_and_token() -> None:
    old = _publication()
    candidate = replace(
        old,
        state=replace(
            old.state,
            access_application_id="app-new",
            access_aud="aud-new",
            policy_ids=("policy-new",),
        ),
    )
    api = _RetirementApi()
    keychain = _RetirementKeychain()
    delete_publication_remote(
        api=api, keychain=keychain, manifest=_manifest(), publication=old, preserve=candidate
    )
    assert api.events == [("access", "app-old")]
    assert not keychain.events


class _TokenApi:
    def __init__(self):
        self.created = 0

    def create_service_token(self, *, account_id, name):
        assert account_id == "account"
        self.created += 1
        return ServiceTokenSecret(
            id="returned-token",
            name=name,
            client_id="returned-client",
            client_secret="only-returned-once",
        )


class _FailedStorage:
    def store_secret(self, *, account, secret):
        assert secret == "only-returned-once"
        raise AppError("Keychain storage failed")

    def load_secret(self, *, account):
        raise AppError("No stored secret")


def test_token_identity_survives_keychain_failure_and_retry_does_not_create_or_rotate(
    tmp_path: Path,
) -> None:
    """A returned token ID is not lost, and rediscovery is not secret recovery."""

    manifest = _manifest()
    spec = _publication().spec
    path = tmp_path / "state.json"
    mutation = Mutation(
        path=path,
        manifest=manifest,
        kind="publish",
        target=spec.name,
        request=publication_request(spec),
        candidate=publication_candidate(spec, None),
    )
    api = _TokenApi()
    keychain = _FailedStorage()
    with pytest.raises(AppError, match="Keychain storage failed"):
        _ = _ensure_token(api=api, keychain=keychain, mutation=mutation)
    retained = load_manifest(path)
    assert retained is not None and retained.pending is not None
    assert retained.pending.effect is None
    candidate = retained.pending.candidate
    assert candidate is not None
    assert candidate.state.service_token_id == "returned-token"
    assert candidate.state.service_token_client_id == "returned-client"
    assert candidate.state.service_token_keychain_account == (
        f"service-token:target:{retained.pending.operation_id}"
    )
    assert "only-returned-once" not in path.read_text()
    resumed = Mutation(
        path=path,
        manifest=retained,
        kind="publish",
        target=spec.name,
        request=publication_request(spec),
    )
    with pytest.raises(AppError) as caught:
        _ = _ensure_token(api=api, keychain=keychain, mutation=resumed)
    assert caught.value.code == "credential_recovery_required"
    assert api.created == 1
    assert load_manifest(path).pending.candidate == candidate


class _StaleCanonicalStorage:
    def __init__(self):
        self.values = {"service-token:target": "stale-retired-token-secret"}
        self.loaded_accounts = []

    def store_secret(self, *, account, secret):
        assert secret == "only-returned-once"
        raise AppError("Keychain storage failed")

    def load_secret(self, *, account):
        self.loaded_accounts.append(account)
        if account in self.values:
            return self.values[account]
        raise AppError("No stored secret")


def test_failed_new_token_store_cannot_reuse_stale_canonical_secret(tmp_path: Path) -> None:
    """Old local residue must not count as custody of a newly returned token secret."""

    spec = _publication().spec
    path = tmp_path / "state.json"
    mutation = Mutation(
        path=path,
        manifest=_manifest(),
        kind="publish",
        target=spec.name,
        request=publication_request(spec),
        candidate=publication_candidate(spec, None),
    )
    api = _TokenApi()
    keychain = _StaleCanonicalStorage()
    with pytest.raises(AppError, match="Keychain storage failed"):
        _ = _ensure_token(api=api, keychain=keychain, mutation=mutation)
    retained = load_manifest(path)
    assert retained is not None and retained.pending is not None
    candidate = retained.pending.candidate
    assert candidate is not None
    account = candidate.state.service_token_keychain_account
    assert account == f"service-token:target:{retained.pending.operation_id}"
    resumed = Mutation(
        path=path,
        manifest=retained,
        kind="publish",
        target=spec.name,
        request=publication_request(spec),
    )
    with pytest.raises(AppError) as caught:
        _ = _ensure_token(api=api, keychain=keychain, mutation=resumed)
    assert caught.value.code == "credential_recovery_required"
    assert keychain.loaded_accounts == [account]
    assert keychain.values == {"service-token:target": "stale-retired-token-secret"}
    assert api.created == 1
    assert load_manifest(path).pending.candidate == candidate


def test_missing_reused_secret_preflight_leaves_no_pending_operation() -> None:
    """Explicit ordinary token rotation remains available after a rejected preflight."""

    publication = _publication()
    manifest = replace(_manifest(), publications={publication.spec.name: publication})
    candidate = publication_candidate(
        replace(publication.spec, origin_url="http://127.0.0.1:4000"), publication
    )
    with pytest.raises(AppError) as caught:
        preflight_publication_credentials(
            keychain=_FailedStorage(), manifest=manifest, candidate=candidate
        )
    assert caught.value.code == "credential_recovery_required"
    assert "token rotate target --yes" in caught.value.hints[0]
    assert manifest.pending is None


def test_pending_reused_token_does_not_need_secret_to_complete_configuration(
    tmp_path: Path,
) -> None:
    """A vanished reused secret does not authorize rotation or block route recovery."""

    publication = _publication()
    manifest = replace(_manifest(), publications={publication.spec.name: publication})
    spec = replace(publication.spec, origin_url="http://127.0.0.1:4000")
    mutation = Mutation(
        path=tmp_path / "state.json",
        manifest=manifest,
        kind="publish",
        target=spec.name,
        request=publication_request(spec),
        candidate=publication_candidate(spec, publication),
    )
    api = _TokenApi()
    candidate = _ensure_token(api=api, keychain=_FailedStorage(), mutation=mutation)
    assert candidate.state.service_token_id == "token-old"
    assert candidate.state.service_token_client_id == "client-old"
    assert candidate.state.service_token_keychain_account == "token:old"
    assert api.created == 0


def test_resume_finishes_routing_without_vanished_reused_secret_and_reports_handoff_gap(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The exact pending route can finish before an explicit credential-recovery mutation."""

    env = fake_environment
    assert (
        main(
            [
                "--json",
                "setup",
                "--api-token",
                "token-1",
                "--account-id",
                "acc-123",
                "--zone",
                "example.com",
            ],
            repo_root=env.repo_root,
        )
        == 0
    )
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
        "machine",
    ]
    assert main(arguments, repo_root=env.repo_root) == 0
    _ = capsys.readouterr()
    state_path = env.home / "Library/Application Support/cloudflare-publish/state.json"
    original = load_manifest(state_path)
    assert original is not None
    old = original.publications["target"]
    arguments[arguments.index("http://127.0.0.1:3000")] = "http://127.0.0.1:4000"
    env.inject_api_fault("PUT", "/accounts/acc-123/cfd_tunnel/tunnel-1/configurations")
    assert main(arguments, repo_root=env.repo_root) == 1
    _ = capsys.readouterr()
    pending = load_manifest(state_path)
    assert pending is not None and pending.pending is not None
    state = env.tool_state()
    del state["keychain"][f"cloudflare-publish:{old.state.service_token_keychain_account}"]
    env.write_tool_state(state)

    assert main(arguments, repo_root=env.repo_root) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "credential_handoff_unavailable"
    assert payload["data"] == {"publication_applied": True, "publication_name": "target"}
    assert "token rotate target --yes" in payload["error"]["hints"][0]
    retained = load_manifest(state_path)
    assert retained is not None and retained.pending is None
    assert retained.publications["target"].spec.origin_url == "http://127.0.0.1:4000"
    assert retained.publications["target"].state.service_token_id == old.state.service_token_id
    assert len(env.tool_state()["cloudflare"]["service_tokens"]) == 1
    assert main(["--json", "token", "rotate", "target", "--yes"], repo_root=env.repo_root) == 0
