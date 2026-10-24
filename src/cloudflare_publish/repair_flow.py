"""Exact, explicit reconciliation of an interrupted resource creation."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Never

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import (
    AccessPolicyRef,
    policy_include_signature,
    tunnel_cname,
)
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.json_types import JsonArray, JsonObject
from cloudflare_publish.models import (
    AppPaths,
    ManagedPublication,
    PendingEffect,
    PendingTransition,
    StateManifest,
)
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.state import now_rfc3339, write_manifest
from cloudflare_publish.workflow_support import load_api_token, require_manifest


def run_repair_resolve(
    *,
    paths: AppPaths,
    keychain: SecretStore,
    http: CurlHttpClient,
    operation_id: str,
    resource_id: str | None,
    absent: bool = False,
    api_token: str | None = None,
) -> StateManifest:
    """Resolve only the exact pending effect, never complete its enclosing mutation."""

    manifest = require_manifest(paths)
    _ = _pending(manifest, operation_id)
    api = _api(paths, keychain, http, manifest, api_token)
    return resolve_pending_effect(
        path=paths.state_file,
        manifest=manifest,
        api=api,
        operation_id=operation_id,
        resource_id=resource_id,
        absent=absent,
    )


def resolve_pending_effect(
    *,
    path: Path,
    manifest: StateManifest,
    api: CloudflareApi,
    operation_id: str,
    resource_id: str | None,
    absent: bool = False,
) -> StateManifest:
    """Adopt one verified identity, or prove its scoped absence before permitting retry."""

    pending = _pending(manifest, operation_id)
    effect = pending.effect
    if effect is None:
        _reject("This operation has no unknown resource creation to resolve.")
    if absent == (resource_id is not None):
        _reject("Choose exactly one resource ID or --absent.")
    if absent:
        _require_absence(api, manifest, pending, effect)
        return _save(path, manifest, replace(pending, effect=None))
    assert resource_id is not None
    _require_resource_id(resource_id)
    _require_unowned(manifest, effect.kind, resource_id)
    if effect.kind == "tunnel":
        if pending.kind != "setup" or manifest.manager.tunnel_id:
            _reject("Only an incomplete initial setup can adopt a tunnel.")
        if effect.resource_name != f"{manifest.manager.tunnel_name}:{pending.operation_id}":
            _reject("The tunnel creation marker does not belong to this operation.")
        tunnel = api.get_tunnel(account_id=manifest.manager.account_id, tunnel_id=resource_id)
        if (
            tunnel.id != resource_id
            or tunnel.name != effect.resource_name
            or not tunnel.remote_config
            or tunnel.deleted_at
        ):
            _reject("The tunnel does not match the saved live remotely managed creation.")
        manifest = replace(manifest, manager=replace(manifest.manager, tunnel_id=tunnel.id))
        pending = replace(pending, phase="tunnel_created", effect=None)
        return _save(path, manifest, pending)

    candidate = _candidate(pending)
    account_id = manifest.manager.account_id
    operation_name = _operation_name(pending)
    state = candidate.state
    if effect.kind == "access_application":
        if effect.resource_name != operation_name or state.access_application_id is not None:
            _reject("The saved application creation does not match an unowned candidate slot.")
        application = api.get_access_application(account_id=account_id, application_id=resource_id)
        discovery = tuple(
            item
            for item in api.list_access_discovery(account_id=account_id)
            if item.id == resource_id
        )
        if (
            application.id != resource_id
            or application.name != effect.resource_name
            or application.domain != candidate.spec.hostname
            or not application.aud
            or application.service_auth_401_redirect is not True
            or len(discovery) != 1
        ):
            _reject("The Access application does not match the saved exact hostname and intent.")
        topology = discovery[0]
        if (
            topology.name != effect.resource_name
            or topology.application_type != "self_hosted"
            or topology.domains != (candidate.spec.hostname,)
            or topology.has_private_destinations
            or topology.has_destination_overrides
        ):
            _reject("The Access application has unsupported type or destination topology.")
        state = replace(state, access_application_id=application.id, access_aud=application.aud)
    elif effect.kind == "service_token":
        if (
            effect.resource_name != operation_name
            or state.service_token_id is not None
            or candidate.spec.audience not in {"machine", "mixed"}
        ):
            _reject("The saved token creation does not match an unowned machine-token slot.")
        token = api.get_service_token(account_id=account_id, service_token_id=resource_id)
        if token.id != resource_id or token.name != effect.resource_name or not token.client_id:
            _reject("The service token does not match the saved operation identity.")
        state = replace(
            state,
            service_token_id=token.id,
            service_token_client_id=token.client_id,
            service_token_keychain_account=f"service-token:{pending.target}:{operation_id}",
        )
    elif effect.kind == "policy":
        _require_policy_parent(pending, effect, candidate)
        assert effect.resource_id is not None
        policies = api.list_access_policies(
            account_id=account_id, application_id=effect.resource_id
        )
        matches = tuple(policy for policy in policies if policy.id == resource_id)
        if len(matches) != 1:
            _reject("The exact policy was not found under its saved parent application.")
        _require_policy(matches[0], pending, candidate, effect)
        state = replace(state, policy_ids=(*state.policy_ids, resource_id))
    elif effect.kind == "dns":
        if effect.resource_name != candidate.spec.hostname or state.dns_record_id:
            _reject("The saved DNS creation does not match an unowned candidate slot.")
        records = api.list_dns_records(
            zone_id=manifest.manager.zone_id, name=candidate.spec.hostname
        )
        matches = tuple(record for record in records if record.id == resource_id)
        if len(matches) != 1:
            _reject("The exact DNS record was not found in the owned zone.")
        record = matches[0]
        if (
            record.name != candidate.spec.hostname
            or record.record_type != "CNAME"
            or record.content != tunnel_cname(manifest.manager.tunnel_id)
            or record.proxied is not True
        ):
            _reject("The DNS record is not the saved proxied CNAME to the owned tunnel.")
        state = replace(state, dns_record_id=record.id)
    else:
        _reject("This effect cannot be resolved by adopting metadata; use its explicit recovery.")
    candidate = replace(candidate, state=replace(state, updated_at=now_rfc3339()))
    return _save(path, manifest, replace(pending, candidate=candidate, effect=None))


def _require_absence(
    api: CloudflareApi,
    manifest: StateManifest,
    pending: PendingTransition,
    effect: PendingEffect,
) -> None:
    """Only a complete scoped list can establish absence; failures retain custody."""

    account_id = manifest.manager.account_id
    if effect.kind == "tunnel":
        if pending.kind != "setup" or manifest.manager.tunnel_id:
            _reject("Only an unowned initial tunnel creation can be reconciled as absent.")
        if effect.resource_name != f"{manifest.manager.tunnel_name}:{pending.operation_id}":
            _reject("The tunnel creation marker does not belong to this operation.")
        present = any(
            item.name == effect.resource_name and not item.deleted_at
            for item in api.list_tunnels(account_id=account_id)
        )
    else:
        candidate = _candidate(pending)
        if effect.kind == "access_application":
            if effect.resource_name != _operation_name(pending):
                _reject("The application marker does not match this operation.")
            present = any(
                item.name == effect.resource_name
                for item in api.list_access_discovery(account_id=account_id)
            )
        elif effect.kind == "service_token":
            if effect.resource_name != _operation_name(pending):
                _reject("The token marker does not match this operation.")
            present = any(
                item.name == effect.resource_name
                for item in api.list_service_tokens(account_id=account_id)
            )
        elif effect.kind == "policy":
            _require_policy_parent(pending, effect, candidate)
            assert effect.resource_id is not None
            present = any(
                item.name == effect.resource_name
                for item in api.list_access_policies(
                    account_id=account_id, application_id=effect.resource_id
                )
            )
        elif effect.kind == "dns":
            if effect.resource_name != candidate.spec.hostname:
                _reject("The DNS hostname does not match the candidate.")
            present = any(
                item.name == effect.resource_name
                for item in api.list_dns_records(
                    zone_id=manifest.manager.zone_id, name=effect.resource_name
                )
            )
        else:
            _reject("This effect is not a resource creation and cannot be cleared as absent.")
    if present:
        _reject("A resource with the saved creation marker still exists; resolve its exact ID.")


def run_repair_retire_token(
    *,
    paths: AppPaths,
    keychain: SecretStore,
    http: CurlHttpClient,
    operation_id: str,
    resource_id: str,
    api_token: str | None = None,
) -> StateManifest:
    """Retire only a candidate's lost token, preserving the original publication."""

    manifest = require_manifest(paths)
    _ = _pending(manifest, operation_id)
    api = _api(paths, keychain, http, manifest, api_token)
    return retire_candidate_token(
        path=paths.state_file,
        manifest=manifest,
        api=api,
        keychain=keychain,
        operation_id=operation_id,
        resource_id=resource_id,
    )


def retire_candidate_token(
    *,
    path: Path,
    manifest: StateManifest,
    api: CloudflareApi,
    keychain: SecretStore,
    operation_id: str,
    resource_id: str,
) -> StateManifest:
    """Fence retirement before DELETE, confirm absence, and keep retry custody on errors."""

    _require_resource_id(resource_id)
    pending = _pending(manifest, operation_id)
    candidate = _candidate(pending)
    if pending.effect is not None and pending.effect.kind == "service_token":
        manifest = resolve_pending_effect(
            path=path,
            manifest=manifest,
            api=api,
            operation_id=operation_id,
            resource_id=resource_id,
        )
        pending = _pending(manifest, operation_id)
        candidate = _candidate(pending)
    effect = pending.effect
    if effect is not None and (effect.kind != "token_retire" or effect.resource_id != resource_id):
        _reject("Another unresolved effect must be reconciled before token retirement.")
    if candidate.state.service_token_id != resource_id:
        _reject("The token ID is not owned by this operation's candidate.")
    if candidate.spec.audience not in {"machine", "mixed"}:
        _reject("Only a machine-access candidate can own the token being retired.")
    account = candidate.state.service_token_keychain_account
    if account is not None and account != f"service-token:{pending.target}:{operation_id}":
        _reject("The candidate credential account is not isolated to this operation.")
    _require_unowned(manifest, "service_token", resource_id, exclude_candidate=True)
    account_id = manifest.manager.account_id
    tokens = tuple(
        token for token in api.list_service_tokens(account_id=account_id) if token.id == resource_id
    )
    if len(tokens) > 1:
        _reject("Cloudflare returned ambiguous token identities.")
    if tokens:
        token = tokens[0]
        if (
            token.name != _operation_name(pending)
            or token.client_id != candidate.state.service_token_client_id
        ):
            _reject("The token metadata does not match this operation's exact candidate.")
    elif effect is None:
        _reject("Token absence cannot establish an unrecorded retirement.")
    pending = replace(
        pending,
        effect=PendingEffect(
            kind="token_retire", resource_name=_operation_name(pending), resource_id=resource_id
        ),
    )
    manifest = _save(path, manifest, pending)
    # Policies are removed only if they are owned and refer to this exact token.
    application_id = candidate.state.access_application_id
    if application_id is not None:
        policies = api.list_access_policies(account_id=account_id, application_id=application_id)
        for policy_id in candidate.state.policy_ids:
            matches = tuple(policy for policy in policies if policy.id == policy_id)
            if len(matches) > 1:
                _reject("Cloudflare returned ambiguous policy identities.")
            if matches and _is_machine_policy(matches[0], pending, resource_id):
                api.delete_access_policy(
                    account_id=account_id, application_id=application_id, policy_id=policy_id
                )
            elif matches:
                _require_policy(
                    matches[0],
                    pending,
                    replace(candidate, state=replace(candidate.state, policy_ids=())),
                    PendingEffect(
                        kind="policy",
                        resource_name=(f"{_operation_name(pending)}:human"),
                        resource_id=application_id,
                    ),
                )
                continue
            candidate = replace(
                candidate,
                state=replace(
                    candidate.state,
                    policy_ids=tuple(
                        identity for identity in candidate.state.policy_ids if identity != policy_id
                    ),
                ),
            )
            pending = replace(pending, candidate=candidate)
            manifest = _save(path, manifest, pending)
    if tokens:
        api.delete_service_token(account_id=account_id, service_token_id=resource_id)
    if any(token.id == resource_id for token in api.list_service_tokens(account_id=account_id)):
        _reject("Cloudflare still reports the retired token; recovery custody is retained.")
    if account is not None:
        keychain.delete_secret(account=account)
    candidate = replace(
        candidate,
        state=replace(
            candidate.state,
            service_token_id=None,
            service_token_client_id=None,
            service_token_keychain_account=None,
            updated_at=now_rfc3339(),
        ),
    )
    # Late publication phases skip candidate preparation. Retiring its machine
    # credential invalidates that checkpoint, but not the route or any completed
    # old-boundary withdrawal. Keep the same guarded app/AUD and route projection;
    # resume only candidate preparation, never replay the old destructive phases.
    phase = (
        "credentials_retired"
        if pending.phase in {"routing", "routed", "cleanup"}
        else pending.phase
    )
    return _save(path, manifest, replace(pending, candidate=candidate, effect=None, phase=phase))


def _is_machine_policy(policy: AccessPolicyRef, pending: PendingTransition, token_id: str) -> bool:
    if policy.name != f"{_operation_name(pending)}:machine":
        return False
    if (
        policy.decision != "non_identity"
        or policy.precedence != 2
        or policy.has_additional_constraints
        or policy.include != policy_include_signature([{"service_token": {"token_id": token_id}}])
    ):
        _reject("The candidate machine policy has drift; refusing token retirement.")
    return True


def _require_policy_parent(
    pending: PendingTransition,
    effect: PendingEffect,
    candidate: ManagedPublication,
) -> None:
    if (
        effect.resource_id is None
        or effect.resource_id != candidate.state.access_application_id
        or effect.resource_name
        not in {f"{_operation_name(pending)}:human", f"{_operation_name(pending)}:machine"}
    ):
        _reject("The policy does not match this operation's owned parent application.")


def _require_policy(
    policy: AccessPolicyRef,
    pending: PendingTransition,
    candidate: ManagedPublication,
    effect: PendingEffect,
) -> None:
    spec = candidate.spec
    expected: list[tuple[str, str, tuple[str, ...], int]] = []
    if spec.audience in {"human", "mixed"}:
        human_include: JsonArray = [{"email": {"email": email}} for email in spec.allowed_emails]
        human_include.extend(
            {"email_domain": {"domain": domain}} for domain in spec.allowed_email_domains
        )
        expected.append(
            (
                f"{_operation_name(pending)}:human",
                "allow",
                policy_include_signature(human_include),
                1,
            )
        )
    if spec.audience in {"machine", "mixed"}:
        token_id = candidate.state.service_token_id
        if token_id is None:
            _reject("A machine policy cannot be adopted without its owned token.")
        expected.append(
            (
                f"{_operation_name(pending)}:machine",
                "non_identity",
                policy_include_signature([{"service_token": {"token_id": token_id}}]),
                2,
            )
        )
    index = len(candidate.state.policy_ids)
    if index >= len(expected) or effect.resource_name != expected[index][0]:
        _reject("The policy is not the next creation in the saved candidate's policy order.")
    if (policy.name, policy.decision, policy.include, policy.precedence) != expected[index] or (
        policy.has_additional_constraints
    ):
        _reject("The policy authorization does not exactly match the saved candidate.")


def _pending(manifest: StateManifest, operation_id: str) -> PendingTransition:
    pending = manifest.pending
    if pending is None or pending.operation_id != operation_id:
        _reject("The operation ID does not match the current incomplete mutation.")
    return pending


def _candidate(pending: PendingTransition) -> ManagedPublication:
    if pending.kind != "publish" or pending.candidate is None:
        _reject("This resolution requires the current publication candidate.")
    if pending.candidate.spec.name != pending.target:
        _reject("The candidate does not match the operation target.")
    return pending.candidate


def _operation_name(pending: PendingTransition) -> str:
    return f"{pending.target}:{pending.operation_id}"


def _require_resource_id(resource_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", resource_id):
        _reject("The resource ID must be a single nonempty Cloudflare identity.")


def _require_unowned(
    manifest: StateManifest,
    kind: str,
    resource_id: str,
    *,
    exclude_candidate: bool = False,
) -> None:
    publications = list(manifest.publications.values())
    if not exclude_candidate and manifest.pending is not None and manifest.pending.candidate:
        publications.append(manifest.pending.candidate)
    for publication in publications:
        state = publication.state
        ids = {
            "dns": (state.dns_record_id,),
            "access_application": (state.access_application_id,),
            "service_token": (state.service_token_id,),
            "policy": state.policy_ids,
        }.get(kind, ())
        if resource_id in ids:
            _reject("This resource ID is already owned; it is not an unresolved creation.")


def _save(path: Path, manifest: StateManifest, pending: PendingTransition) -> StateManifest:
    updated = replace(manifest, pending=pending, updated_at=now_rfc3339())
    write_manifest(path, updated)
    return updated


def _api(
    paths: AppPaths,
    keychain: SecretStore,
    http: CurlHttpClient,
    manifest: StateManifest,
    token: str | None,
) -> CloudflareApi:
    return CloudflareApi(
        http,
        load_api_token(keychain=keychain, manifest=manifest, home=paths.home, explicit_token=token),
    )


def pending_effect_candidates(
    *,
    manifest: StateManifest,
    api: CloudflareApi,
) -> tuple[JsonObject, ...]:
    """Return credential-free exact-marker candidates for the repair plan, not ownership."""

    pending = manifest.pending
    if pending is None or pending.effect is None:
        return ()
    effect = pending.effect
    account_id = manifest.manager.account_id
    if effect.kind in {"token_rotate", "token_retire"}:
        if effect.resource_id is None:
            _reject("The pending token operation has no exact token identity.")
        token = api.get_service_token(account_id=account_id, service_token_id=effect.resource_id)
        return ({"id": token.id, "name": token.name, "type": "service_token"},)
    if effect.kind == "tunnel":
        if (
            pending.kind != "setup"
            or effect.resource_name != f"{manifest.manager.tunnel_name}:{pending.operation_id}"
        ):
            _reject("The tunnel creation marker does not belong to this operation.")
        return tuple(
            {"id": item.id, "name": item.name, "type": "tunnel"}
            for item in api.list_tunnels(account_id=account_id)
            if item.name == effect.resource_name and not item.deleted_at
        )
    candidate = _candidate(pending)
    if effect.kind == "access_application":
        if effect.resource_name != _operation_name(pending):
            _reject("The application creation marker does not belong to this operation.")
        return tuple(
            {"id": item.id, "name": item.name, "type": "access_application"}
            for item in api.list_access_discovery(account_id=account_id)
            if item.name == effect.resource_name
        )
    if effect.kind == "service_token":
        if effect.resource_name != _operation_name(pending):
            _reject("The token creation marker does not belong to this operation.")
        return tuple(
            {"id": item.id, "name": item.name, "type": "service_token"}
            for item in api.list_service_tokens(account_id=account_id)
            if item.name == effect.resource_name
        )
    if effect.kind == "policy":
        _require_policy_parent(pending, effect, candidate)
        assert effect.resource_id is not None
        return tuple(
            {"id": item.id, "name": item.name, "type": "policy"}
            for item in api.list_access_policies(
                account_id=account_id, application_id=effect.resource_id
            )
            if item.name == effect.resource_name
        )
    if effect.kind == "dns":
        if effect.resource_name != candidate.spec.hostname:
            _reject("The saved DNS creation does not match its candidate hostname.")
        return tuple(
            {"id": item.id, "name": item.name, "type": item.record_type}
            for item in api.list_dns_records(
                zone_id=manifest.manager.zone_id, name=effect.resource_name
            )
            if item.name == effect.resource_name
        )
    _reject("The pending effect does not have a supported resource candidate lookup.")


def _reject(message: str) -> Never:
    raise AppError(
        message,
        code="repair_resolution_refused",
        hints=("Run cloudflare-publish --json repair plan; custody has not been forgotten.",),
    )
