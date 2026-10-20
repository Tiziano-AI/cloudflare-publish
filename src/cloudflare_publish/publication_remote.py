"""Recoverable publication effects, guarded routing and owned-resource retirement."""

from __future__ import annotations

from dataclasses import replace
from typing import Literal

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import tunnel_cname
from cloudflare_publish.config_application import require_configuration_applied
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonArray, JsonObject
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.local_connector_observation import LocalConnectorObserver
from cloudflare_publish.models import (
    ManagedPublication,
    PublicationRemoteState,
    PublicationSpec,
    StateManifest,
)
from cloudflare_publish.publication_contract import service_token_keychain_account
from cloudflare_publish.render import build_tunnel_configuration, compare_tunnel_configuration
from cloudflare_publish.state import now_rfc3339
from cloudflare_publish.transitions import Mutation, effective_publications
from cloudflare_publish.verify_support import (
    build_expected_policy_contracts,
    serialize_policy_contract,
)


def publication_request(spec: PublicationSpec) -> JsonObject:
    """Keep the normalized request, without credentials, for exact resumption."""

    return {
        "name": spec.name,
        "kind": spec.kind,
        "hostname": spec.hostname,
        "origin_url": spec.origin_url,
        "audience": spec.audience,
        "allowed_emails": list(spec.allowed_emails),
        "allowed_email_domains": list(spec.allowed_email_domains),
        "verify_path": spec.verify_path,
        "expect_status": spec.expect_status,
        "ssh_host_key": spec.ssh_host_key,
        "http_host_header": spec.origin_options.http_host_header,
        "origin_server_name": spec.origin_options.origin_server_name,
        "no_tls_verify": spec.origin_options.no_tls_verify,
    }


def authorization_boundary_matches(left: PublicationSpec, right: PublicationSpec) -> bool:
    """An application audience is reusable only within one authorization boundary."""

    return (
        left.hostname == right.hostname
        and left.audience == right.audience
        and set(left.allowed_emails) == set(right.allowed_emails)
        and set(left.allowed_email_domains) == set(right.allowed_email_domains)
    )


def publication_candidate(
    spec: PublicationSpec, existing: ManagedPublication | None
) -> ManagedPublication:
    """Allocate empty ownership, retaining only resources safe to reuse."""

    if existing is not None and authorization_boundary_matches(existing.spec, spec):
        return replace(existing, spec=spec)
    reuse_dns = existing is not None and existing.spec.hostname == spec.hostname
    reuse_token = (
        existing is not None
        and existing.spec.audience in {"machine", "mixed"}
        and spec.audience in {"machine", "mixed"}
    )
    return ManagedPublication(
        spec=spec,
        state=PublicationRemoteState(
            dns_record_id=existing.state.dns_record_id if reuse_dns and existing else "",
            access_application_id=None,
            access_aud=None,
            policy_ids=(),
            service_token_id=existing.state.service_token_id if reuse_token and existing else None,
            service_token_client_id=(
                existing.state.service_token_client_id if reuse_token and existing else None
            ),
            service_token_keychain_account=(
                existing.state.service_token_keychain_account if reuse_token and existing else None
            ),
            updated_at=now_rfc3339(),
        ),
    )


def preflight_publication_credentials(
    *, keychain: Keychain, manifest: StateManifest, candidate: ManagedPublication
) -> None:
    """Keep an initially missing reused credential outside pending mutation custody."""

    if not _reuses_service_token(manifest=manifest, candidate=candidate):
        return
    account = candidate.state.service_token_keychain_account
    try:
        if account is None:
            raise AppError("The reused service token has no Keychain account.")
        _ = keychain.load_secret(account=account)
    except AppError:
        raise AppError(
            "The existing service-token secret is unavailable; no publication change was started.",
            code="credential_recovery_required",
            hints=(
                f"Run cloudflare-publish token rotate {candidate.spec.name} --yes "
                + "to explicitly issue and store a replacement secret, then retry publication.",
            ),
        ) from None


def _reuses_service_token(*, manifest: StateManifest, candidate: ManagedPublication) -> bool:
    existing = manifest.publications.get(candidate.spec.name)
    state = candidate.state
    return (
        existing is not None
        and state.service_token_id is not None
        and state.service_token_id == existing.state.service_token_id
        and state.service_token_client_id == existing.state.service_token_client_id
        and state.service_token_keychain_account == existing.state.service_token_keychain_account
    )


def sync_publication(
    *,
    api: CloudflareApi,
    keychain: Keychain,
    mutation: Mutation,
    local_observer: LocalConnectorObserver,
) -> ManagedPublication:
    """Resume fixed publication phases; never repeat an uncertain resource POST."""

    _require_known_effect(mutation)
    candidate = _candidate(mutation)
    existing = mutation.manifest.publications.get(candidate.spec.name)
    replace_access = existing is not None and not authorization_boundary_matches(
        existing.spec, candidate.spec
    )
    if replace_access and mutation.pending.phase in {"started", "withdrawing"}:
        apply_transition_configuration(
            api=api,
            mutation=mutation,
            route="withdrawn",
            phase="withdrawing",
            local_observer=local_observer,
        )
        mutation.save(pending=replace(mutation.pending, phase="withdrawal_applied"))
    if replace_access and mutation.pending.phase == "withdrawal_applied":
        # The old route is absent on every observed active connector before its
        # application can disappear or its hostname can be reused with a new AUD.
        assert existing is not None
        apply_transition_configuration(
            api=api,
            mutation=mutation,
            route="withdrawn",
            phase="withdrawal_applied",
            local_observer=local_observer,
        )
        _delete_access_application(api=api, manifest=mutation.manifest, publication=existing)
        mutation.save(pending=replace(mutation.pending, phase="access_retired"))
    if mutation.pending.phase not in {"routing", "routed", "cleanup"}:
        candidate = _ensure_access(api=api, mutation=mutation)
        candidate = _ensure_token(api=api, keychain=keychain, mutation=mutation)
        candidate = _ensure_policies(api=api, mutation=mutation)
        candidate = _ensure_dns(api=api, mutation=mutation)
        _require_candidate_access(api=api, manifest=mutation.manifest, publication=candidate)
        mutation.save(pending=replace(mutation.pending, phase="candidate_ready"))
    if mutation.pending.phase in {"candidate_ready", "routing"}:
        _require_candidate_access(
            api=api, manifest=mutation.manifest, publication=_candidate(mutation)
        )
        apply_transition_configuration(
            api=api,
            mutation=mutation,
            route="candidate",
            phase="routing",
            local_observer=local_observer,
        )
        mutation.save(pending=replace(mutation.pending, phase="routed"))
    # A previous barrier is not a perpetual assertion about dashboard writers or
    # newly appearing replicas. Reobserve before dropping any old ownership.
    _require_candidate_access(api=api, manifest=mutation.manifest, publication=_candidate(mutation))
    apply_transition_configuration(
        api=api,
        mutation=mutation,
        route="candidate",
        phase="cleanup",
        local_observer=local_observer,
    )
    candidate = _candidate(mutation)
    if existing is not None:
        delete_publication_remote(
            api=api,
            keychain=keychain,
            manifest=mutation.manifest,
            publication=existing,
            preserve=candidate,
        )
    return candidate


def require_known_tunnel_configuration(*, api: CloudflareApi, manifest: StateManifest) -> None:
    """Reject dashboard/foreign drift rather than overwriting it during a mutation."""

    actual = api.get_tunnel_configuration(
        account_id=manifest.manager.account_id, tunnel_id=manifest.manager.tunnel_id
    )
    _require_admitted_configuration(actual=actual, manifest=manifest)


def _require_admitted_configuration(*, actual: JsonObject, manifest: StateManifest) -> None:
    projections = [manifest.publications]
    if manifest.pending is not None and manifest.pending.kind in {"publish", "remove"}:
        withdrawn = dict(manifest.publications)
        _ = withdrawn.pop(manifest.pending.target, None)
        projections.append(withdrawn)
        if manifest.pending.route == "candidate":
            projections.append(effective_publications(manifest))
    comparison_detail: str | None = None
    for publications in projections:
        expected = build_tunnel_configuration(
            publications, auth_domain=manifest.manager.auth_domain
        )
        comparison = compare_tunnel_configuration(actual=actual, expected=expected)
        if comparison.matches:
            return
        comparison_detail = comparison.detail
    raise AppError(
        "The shared tunnel configuration has unmanaged or unexpected drift.",
        code="configuration_drift",
        hints=(comparison_detail or "Inspect the remote configuration before changing it.",),
    )


def apply_transition_configuration(
    *,
    api: CloudflareApi,
    mutation: Mutation,
    route: Literal["withdrawn", "candidate"],
    phase: str,
    local_observer: LocalConnectorObserver,
) -> None:
    """Persist the route target before PUT and observe every active connector."""

    pending = mutation.pending
    if pending.route != route or pending.phase != phase:
        mutation.save(
            pending=replace(pending, route=route, phase=phase, configuration_version=None)
        )
    manifest = mutation.manifest
    snapshot = api.get_tunnel_configuration_snapshot(
        account_id=manifest.manager.account_id, tunnel_id=manifest.manager.tunnel_id
    )
    _require_admitted_configuration(actual=snapshot.config, manifest=manifest)
    expected = build_tunnel_configuration(
        effective_publications(manifest), auth_domain=manifest.manager.auth_domain
    )
    if compare_tunnel_configuration(actual=snapshot.config, expected=expected).matches:
        # A lost PUT response is resolved by the exact desired body and the
        # version returned by GET, not by inventing a version or repeating POST.
        version = snapshot.version
    else:
        _ = api.update_tunnel_configuration(
            account_id=manifest.manager.account_id,
            tunnel_id=manifest.manager.tunnel_id,
            configuration=expected,
        )
        applied_snapshot = api.get_tunnel_configuration_snapshot(
            account_id=manifest.manager.account_id,
            tunnel_id=manifest.manager.tunnel_id,
        )
        comparison = compare_tunnel_configuration(actual=applied_snapshot.config, expected=expected)
        if not comparison.matches:
            raise AppError(
                "The stored configuration changed before connector application was observed.",
                code="configuration_drift",
                hints=(comparison.detail or "Inspect the exact remote configuration.",),
            )
        version = applied_snapshot.version
    mutation.save(pending=replace(mutation.pending, configuration_version=version))
    _ = require_configuration_applied(
        api,
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
        expected_version=version,
        local_observer=local_observer,
    )


def validate_publication_remote_slot(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    spec: PublicationSpec,
) -> None:
    """Reject unowned hostname resources before any publication effects."""

    existing = manifest.publications.get(spec.name)
    candidate = None if manifest.pending is None else manifest.pending.candidate
    owned = tuple(item for item in (existing, candidate) if item is not None)
    for publication in manifest.publications.values():
        if publication.spec.name != spec.name and publication.spec.hostname == spec.hostname:
            raise AppError(
                f"Hostname {spec.hostname!r} is already managed by {publication.spec.name!r}."
            )
    _require_public_audience_reachable(api=api, manifest=manifest, spec=spec)
    dns_ids = {item.state.dns_record_id for item in owned}
    if any(
        record.id not in dns_ids
        for record in api.list_dns_records(zone_id=manifest.manager.zone_id, name=spec.hostname)
    ):
        raise AppError(
            f"Remote DNS record for {spec.hostname!r} already exists and is not managed locally."
        )
    app_ids = {item.state.access_application_id for item in owned}
    if any(
        app.id not in app_ids
        for app in api.list_access_applications(account_id=manifest.manager.account_id)
        if app.domain == spec.hostname
    ):
        raise AppError(f"Remote Access application for {spec.hostname!r} is not managed locally.")


def delete_publication_remote(
    *,
    api: CloudflareApi,
    keychain: Keychain,
    manifest: StateManifest,
    publication: ManagedPublication,
    preserve: ManagedPublication | None = None,
) -> None:
    """Idempotently retire owned refs after withdrawal, keeping all refs on failure."""

    state = publication.state
    retained = None if preserve is None else preserve.state
    # DNS failure must not strand a still-resurrectable hostname without Access.
    if state.dns_record_id and (retained is None or state.dns_record_id != retained.dns_record_id):
        api.delete_dns_record(
            zone_id=manifest.manager.zone_id, record_id=state.dns_record_id, missing_ok=True
        )
    if retained is None or state.access_application_id != retained.access_application_id:
        _delete_access_application(api=api, manifest=manifest, publication=publication)
    if state.service_token_id is not None and (
        retained is None or state.service_token_id != retained.service_token_id
    ):
        api.delete_service_token(
            account_id=manifest.manager.account_id,
            service_token_id=state.service_token_id,
            missing_ok=True,
        )
    if state.service_token_keychain_account is not None and (
        retained is None
        or state.service_token_keychain_account != retained.service_token_keychain_account
    ):
        keychain.delete_secret(account=state.service_token_keychain_account)


def push_tunnel_configuration(*, api: CloudflareApi, manifest: StateManifest) -> int | None:
    """Render the one effective route projection for other manager-owned workflows."""

    return api.update_tunnel_configuration(
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
        configuration=build_tunnel_configuration(
            effective_publications(manifest), auth_domain=manifest.manager.auth_domain
        ),
    )


def _require_known_effect(mutation: Mutation) -> None:
    effect = mutation.pending.effect
    if effect is not None:
        raise AppError(
            f"Operation {mutation.pending.operation_id} has an unknown {effect.kind} result.",
            code="outcome_unknown",
            hints=("Resolve the exact resource with repair resolve before resuming.",),
        )


def _candidate(mutation: Mutation) -> ManagedPublication:
    candidate = mutation.pending.candidate
    if candidate is None:
        raise AppError("Pending publication has no candidate ownership.")
    return candidate


def _own(mutation: Mutation, **changes: str | tuple[str, ...] | None) -> ManagedPublication:
    """Record returned resource identity before allowing another external effect."""

    candidate = _candidate(mutation)
    candidate = replace(
        candidate, state=replace(candidate.state, updated_at=now_rfc3339(), **changes)
    )
    mutation.observed(candidate=candidate)
    return candidate


def _operation_name(mutation: Mutation) -> str:
    return f"{mutation.pending.target}:{mutation.pending.operation_id}"


def _ensure_access(*, api: CloudflareApi, mutation: Mutation) -> ManagedPublication:
    candidate = _candidate(mutation)
    if candidate.spec.audience == "public" or candidate.state.access_application_id is not None:
        return candidate
    name = _operation_name(mutation)
    mutation.before_effect(kind="access_application", resource_name=name)
    application = api.create_access_application(
        account_id=mutation.manifest.manager.account_id, name=name, hostname=candidate.spec.hostname
    )
    return _own(mutation, access_application_id=application.id, access_aud=application.aud)


def _ensure_token(
    *,
    api: CloudflareApi,
    keychain: Keychain,
    mutation: Mutation,
) -> ManagedPublication:
    candidate = _candidate(mutation)
    if candidate.spec.audience not in {"machine", "mixed"}:
        return candidate
    state = candidate.state
    if state.service_token_id is not None:
        if _reuses_service_token(manifest=mutation.manifest, candidate=candidate):
            # Routing and policy ownership need the known token identity, not
            # its secret. A credential disappearing during an interrupted
            # change must not deadlock that change behind another mutation.
            return candidate
        if state.service_token_keychain_account is not None:
            try:
                _ = keychain.load_secret(account=state.service_token_keychain_account)
                return candidate
            except AppError:
                pass
        raise AppError(
            "The owned service token has no recoverable local secret.",
            code="credential_recovery_required",
            hints=("Retire and reissue the exact token deliberately; do not repeat its POST.",),
        )
    name = _operation_name(mutation)
    # A canonical account may retain a credential from an earlier retired token.
    # A unique account makes absence after a failed store unambiguous on resume.
    account = (
        f"{service_token_keychain_account(candidate.spec.name)}:{mutation.pending.operation_id}"
    )
    mutation.before_effect(kind="service_token", resource_name=name)
    token = api.create_service_token(account_id=mutation.manifest.manager.account_id, name=name)
    candidate = _own(
        mutation,
        service_token_id=token.id,
        service_token_client_id=token.client_id,
        service_token_keychain_account=account,
    )
    keychain.store_secret(account=account, secret=token.client_secret)
    return candidate


def _ensure_policies(*, api: CloudflareApi, mutation: Mutation) -> ManagedPublication:
    candidate = _candidate(mutation)
    application_id = candidate.state.access_application_id
    if application_id is None:
        return candidate
    policies: list[tuple[str, str, JsonArray, int]] = []
    if candidate.spec.audience in {"human", "mixed"}:
        policies.append(("human", "allow", _human_policy_include(candidate.spec), 1))
    if candidate.spec.audience in {"machine", "mixed"}:
        token_id = candidate.state.service_token_id
        if token_id is None:
            raise AppError("Machine-access publication is missing a service token.")
        policies.append(("machine", "non_identity", [{"service_token": {"token_id": token_id}}], 2))
    for kind, decision, include, precedence in policies[len(candidate.state.policy_ids) :]:
        name = f"{_operation_name(mutation)}:{kind}"
        mutation.before_effect(kind="policy", resource_name=name, resource_id=application_id)
        policy = api.create_access_policy(
            account_id=mutation.manifest.manager.account_id,
            application_id=application_id,
            name=name,
            decision=decision,
            include=include,
            precedence=precedence,
        )
        candidate = _own(mutation, policy_ids=(*candidate.state.policy_ids, policy.id))
    return candidate


def _ensure_dns(*, api: CloudflareApi, mutation: Mutation) -> ManagedPublication:
    candidate = _candidate(mutation)
    if candidate.state.dns_record_id:
        records = api.list_dns_records(
            zone_id=mutation.manifest.manager.zone_id, name=candidate.spec.hostname
        )
        if len(records) != 1 or (
            records[0].id != candidate.state.dns_record_id
            or records[0].name != candidate.spec.hostname
            or records[0].record_type != "CNAME"
            or records[0].content != tunnel_cname(mutation.manifest.manager.tunnel_id)
            or not records[0].proxied
        ):
            raise AppError("The owned DNS record has unexpected drift.", code="dns_drift")
        return candidate
    manager = mutation.manifest.manager
    mutation.before_effect(kind="dns", resource_name=candidate.spec.hostname)
    record = api.create_dns_record(
        zone_id=manager.zone_id, hostname=candidate.spec.hostname, tunnel_id=manager.tunnel_id
    )
    return _own(mutation, dns_record_id=record.id)


def _require_candidate_access(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    publication: ManagedPublication,
) -> None:
    """Do not route a candidate over changed application or policy semantics."""

    application_id = publication.state.access_application_id
    if application_id is None:
        if publication.spec.audience != "public":
            raise AppError("Protected publication is missing its owned Access application.")
        return
    application = api.get_access_application(
        account_id=manifest.manager.account_id, application_id=application_id
    )
    if (
        application.domain != publication.spec.hostname
        or application.aud != publication.state.access_aud
        or application.service_auth_401_redirect is not True
    ):
        raise AppError("The owned Access application has unexpected drift.", code="access_drift")
    policies = api.list_access_policies(
        account_id=manifest.manager.account_id, application_id=application_id
    )
    actual = tuple(
        sorted(
            serialize_policy_contract(
                precedence=item.precedence, decision=item.decision, include=item.include
            )
            for item in policies
        )
    )
    if (
        tuple(sorted(item.id for item in policies)) != tuple(sorted(publication.state.policy_ids))
        or actual != tuple(sorted(build_expected_policy_contracts(publication)))
        or any(item.has_additional_constraints for item in policies)
    ):
        raise AppError("The owned Access policies have unexpected drift.", code="access_drift")


def _delete_access_application(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    publication: ManagedPublication,
) -> None:
    application_id = publication.state.access_application_id
    if application_id is not None:
        api.delete_access_application(
            account_id=manifest.manager.account_id, application_id=application_id, missing_ok=True
        )


def _require_public_audience_reachable(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    spec: PublicationSpec,
) -> None:
    if spec.audience != "public":
        return
    organization = api.get_organization(account_id=manifest.manager.account_id)
    if (
        organization.deny_unmatched_requests
        and manifest.manager.zone_name
        not in organization.deny_unmatched_requests_exempted_zone_names
    ):
        raise AppError(
            "Public publication is blocked by the account require-protection guard.",
            hints=(
                "Disable the guard or explicitly exempt the configured zone before publishing.",
            ),
        )


def _human_policy_include(spec: PublicationSpec) -> JsonArray:
    include: JsonArray = [{"email": {"email": email}} for email in spec.allowed_emails]
    include.extend({"email_domain": {"domain": domain}} for domain in spec.allowed_email_domains)
    if not include:
        raise AppError("Human-access publication requires at least one human allow rule.")
    return include
