"""Mutating and planning CLI command handlers."""

from __future__ import annotations

from cloudflare_publish.cli_output import (
    manifest_summary_to_object,
    organization_to_object,
    publication_spec_to_object,
    publication_to_object,
    service_token_secret_to_object,
    tunnel_to_object,
)
from cloudflare_publish.cli_parser import CliArgs
from cloudflare_publish.cli_runtime import CliRuntime
from cloudflare_publish.cli_shared import (
    api_from_token,
    env_or_none,
    raise_requires_yes,
    require_value,
)
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.guard_flow import (
    guard_blocking_publication_names,
    require_guard_compatible,
    run_guard_enable,
    run_guard_status,
)
from cloudflare_publish.json_types import JsonArray, JsonObject, JsonValue
from cloudflare_publish.models import (
    ManagedPublication,
    PublicationRemoteState,
    PublicationSpec,
    PublishRequest,
    SetupRequest,
)
from cloudflare_publish.publication_contract import (
    build_publication_spec,
    ensure_hostname_within_zone,
)
from cloudflare_publish.publication_remote import (
    authorization_boundary_matches,
    publication_request,
    validate_publication_remote_slot,
)
from cloudflare_publish.publish_flow import run_publish
from cloudflare_publish.remove_flow import run_remove
from cloudflare_publish.render import build_tunnel_configuration
from cloudflare_publish.setup_flow import run_setup
from cloudflare_publish.state import replace_publications, transition_to_object
from cloudflare_publish.teardown_flow import run_teardown
from cloudflare_publish.token_flow import run_token_rotate
from cloudflare_publish.tunnel_flow import run_tunnel_recover
from cloudflare_publish.workflow_support import require_manifest


def run_setup_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Run setup or refresh."""

    if args.takeover and not args.yes:
        raise_requires_yes("setup --takeover")
    manifest = run_setup(
        request=SetupRequest(
            install_deps=args.install_deps,
            takeover=args.takeover,
            refresh_only=args.refresh_only,
            api_token=env_or_none(
                args.api_token,
                "CLOUDFLARE_API_TOKEN",
                home=runtime.paths.home,
            ),
            account_id=env_or_none(
                args.account_id,
                "CLOUDFLARE_ACCOUNT_ID",
                home=runtime.paths.home,
            ),
            zone_id=env_or_none(
                args.zone_id,
                "CLOUDFLARE_ZONE_ID",
                home=runtime.paths.home,
            ),
            zone_name=env_or_none(
                args.zone_name,
                "CLOUDFLARE_ZONE",
                home=runtime.paths.home,
            ),
            tunnel_name=env_or_none(
                args.tunnel_name,
                "CLOUDFLARE_TUNNEL_NAME",
                home=runtime.paths.home,
            ),
        ),
        paths=runtime.paths,
        cloudflared=runtime.cloudflared,
        launchd=runtime.launchd,
        keychain=runtime.keychain,
        http=runtime.http,
        console=console,
    )
    return {"manifest": manifest_summary_to_object(manifest)}


def run_publish_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Plan or apply one publication."""

    request = _publish_request(args)
    if args.publish_command == "plan":
        return _publish_plan(request=request, runtime=runtime, api_token=args.api_token)
    if args.publish_command != "apply":
        raise AppError("Unknown publish subcommand.")
    if not args.yes:
        raise_requires_yes("publish apply")
    publication = run_publish(
        request=request,
        paths=runtime.paths,
        keychain=runtime.keychain,
        http=runtime.http,
        launchd=runtime.launchd,
        console=console,
        api_token=args.api_token,
    )
    payload = publication_to_object(publication)
    result: JsonObject = {"publication": payload}
    handoff = _publication_credential_handoff(publication=publication, runtime=runtime)
    if handoff is not None:
        result["credential_handoff"] = handoff
    return result


def run_tunnel_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Dispatch shared tunnel commands."""

    if args.tunnel_command != "recover":
        raise AppError("Unknown tunnel subcommand.")
    if args.recover_command == "plan":
        return _tunnel_recover_plan(runtime=runtime)
    if args.recover_command != "apply":
        raise AppError("Unknown tunnel recover subcommand.")
    if not args.yes:
        raise_requires_yes("tunnel recover apply")
    tunnel = run_tunnel_recover(
        paths=runtime.paths,
        cloudflared=runtime.cloudflared,
        launchd=runtime.launchd,
        keychain=runtime.keychain,
        http=runtime.http,
        console=console,
        api_token=args.api_token,
    )
    return {"tunnel": tunnel_to_object(tunnel), "disconnected_shared_tunnel_connectors": True}


def run_remove_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Plan or apply one publication removal."""

    publication_name = require_value(args.name, message="rm requires a name.")
    if args.remove_command == "plan":
        return _remove_plan(publication_name=publication_name, runtime=runtime)
    if args.remove_command != "apply":
        raise AppError("Unknown rm subcommand.")
    if not args.yes:
        raise_requires_yes("rm apply")
    publication = run_remove(
        publication_name=publication_name,
        paths=runtime.paths,
        keychain=runtime.keychain,
        http=runtime.http,
        launchd=runtime.launchd,
        console=console,
        api_token=args.api_token,
    )
    return {"removed_publication": publication_to_object(publication)}


def run_token_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Rotate one publication service token."""

    if args.token_command != "rotate":
        raise AppError("Unknown token subcommand.")
    if not args.yes:
        raise_requires_yes("token rotate")
    rotated = run_token_rotate(
        publication_name=require_value(args.name, message="token rotate requires a name."),
        paths=runtime.paths,
        keychain=runtime.keychain,
        http=runtime.http,
        console=console,
        api_token=args.api_token,
        recover=args.recover,
    )
    return {"service_token": service_token_secret_to_object(rotated)}


def run_guard_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Read or update account-level require-protection."""

    if args.guard_command == "status":
        organization = run_guard_status(
            paths=runtime.paths,
            keychain=runtime.keychain,
            http=runtime.http,
            console=console,
            api_token=args.api_token,
        )
        payload = organization_to_object(organization)
        manifest = require_manifest(runtime.paths)
        blocking_publications = guard_blocking_publication_names(
            manifest=manifest,
            organization=organization,
        )
        if not organization.deny_unmatched_requests and blocking_publications:
            payload["guard_blocked_by_publications"] = list(blocking_publications)
        elif not organization.deny_unmatched_requests:
            payload["risk"] = (
                "Hostnames without a matching Access application are not blocked by default."
            )
            recommended_next_commands: list[JsonValue] = [
                "cloudflare-publish guard plan",
                "cloudflare-publish guard apply --yes",
            ]
            payload["recommended_next_commands"] = recommended_next_commands
        return {"organization": payload}
    if args.guard_command == "plan":
        return _guard_plan(args=args, runtime=runtime)
    if args.guard_command == "apply":
        if not args.yes:
            raise_requires_yes("guard apply")
        organization = run_guard_enable(
            paths=runtime.paths,
            keychain=runtime.keychain,
            http=runtime.http,
            console=console,
            api_token=args.api_token,
        )
        return {"organization": organization_to_object(organization)}
    raise AppError("Unknown guard subcommand.")


def run_teardown_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Delete all managed resources and local manager state."""

    if not args.yes:
        raise_requires_yes("teardown")
    manifest = run_teardown(
        paths=runtime.paths,
        launchd=runtime.launchd,
        keychain=runtime.keychain,
        http=runtime.http,
        console=console,
        api_token=args.api_token,
    )
    return {"removed_manager": manifest_summary_to_object(manifest)}


def _publish_plan(
    *,
    request: PublishRequest,
    runtime: CliRuntime,
    api_token: str | None,
) -> JsonObject:
    """Validate and report one publication mutation without mutating state."""

    manifest = require_manifest(runtime.paths)
    spec = build_publication_spec(request)
    ensure_hostname_within_zone(hostname=spec.hostname, zone_name=manifest.manager.zone_name)
    if manifest.pending is not None:
        return {
            "plan": True,
            "action": "publish apply",
            "publication": publication_spec_to_object(spec),
            "pending": transition_to_object(manifest.pending),
            "resume": manifest.pending.kind == "publish"
            and manifest.pending.request == publication_request(spec),
            "recommended_next_command": "cloudflare-publish repair plan",
        }
    api = api_from_token(args_token=api_token, runtime=runtime)
    validate_publication_remote_slot(api=api, manifest=manifest, spec=spec)
    existing = manifest.publications.get(spec.name)
    next_publications = dict(manifest.publications)
    next_publications[spec.name] = _planned_publication(spec, existing)
    next_manifest = replace_publications(manifest, publications=next_publications)
    return {
        "plan": True,
        "action": "publish apply",
        "mode": "update" if existing is not None else "create",
        "publication": publication_spec_to_object(spec),
        "effects": _publish_effects(spec=spec, existing=existing),
        "tunnel_configuration": build_tunnel_configuration(
            next_manifest.publications,
            auth_domain=manifest.manager.auth_domain,
        ),
    }


def _remove_plan(*, publication_name: str, runtime: CliRuntime) -> JsonObject:
    """Report one publication removal without mutating state."""

    manifest = require_manifest(runtime.paths)
    publication = manifest.publications.get(publication_name)
    if publication is None:
        raise AppError(f"Unknown publication {publication_name!r}.")
    effects: JsonArray = [
        "persist the pending withdrawal before changing routing",
        "remove publication ingress from shared tunnel configuration",
        "observe the exact configuration version on every active connector",
        "delete proxied DNS record",
        "delete Access policies and application"
        if publication.state.access_application_id
        else "no Access application or policies",
        (
            "delete service token"
            if publication.state.service_token_id is not None
            else "no service token"
        ),
        "remove publication from local state",
    ]
    return {
        "plan": True,
        "action": "rm apply",
        "publication": publication_to_object(publication),
        "effects": effects,
        "pending": transition_to_object(manifest.pending),
    }


def _guard_plan(*, args: CliArgs, runtime: CliRuntime) -> JsonObject:
    """Report account-level require-protection enablement without mutating state."""

    manifest = require_manifest(runtime.paths)
    api = api_from_token(args_token=args.api_token, runtime=runtime)
    organization = api.get_organization(account_id=manifest.manager.account_id)
    require_guard_compatible(manifest=manifest, organization=organization)
    return {
        "plan": True,
        "action": "guard apply",
        "organization": organization_to_object(organization),
        "would_update": not organization.deny_unmatched_requests,
        "preserved_exempted_zone_names": list(
            organization.deny_unmatched_requests_exempted_zone_names
        ),
    }


def _tunnel_recover_plan(*, runtime: CliRuntime) -> JsonObject:
    """Report shared tunnel recovery blast radius without mutating state."""

    manifest = require_manifest(runtime.paths)
    return {
        "plan": True,
        "action": "tunnel recover apply",
        "tunnel": {
            "id": manifest.manager.tunnel_id,
            "name": manifest.manager.tunnel_name,
            "account_id": manifest.manager.account_id,
        },
        "effects": [
            "fetch current remote tunnel token",
            f"rewrite {runtime.paths.tunnel_token_file}",
            f"reinstall {runtime.paths.canonical_launch_agent_file}",
            "restart the managed connector",
            "delete every active connector on the shared tunnel",
        ],
    }


def _publish_request(args: CliArgs) -> PublishRequest:
    """Build a publication request from parsed args."""

    return PublishRequest(
        name=require_value(args.name, message="publish requires a name."),
        hostname=require_value(args.hostname, message="publish requires --hostname."),
        origin_url=require_value(args.origin_url, message="publish requires --to."),
        audience=require_value(args.audience, message="publish requires --audience."),
        allowed_emails=tuple(args.allowed_emails),
        allowed_email_domains=tuple(args.allowed_email_domains),
        verify_path=args.verify_path,
        expect_status=args.expect_status,
        http_host_header=args.http_host_header,
        origin_server_name=args.origin_server_name,
        no_tls_verify=args.no_tls_verify,
        ssh_host_key=args.ssh_host_key,
    )


def _planned_publication(
    spec: PublicationSpec,
    existing: ManagedPublication | None,
) -> ManagedPublication:
    """Return existing state or a planned placeholder for tunnel config rendering."""

    if existing is not None and authorization_boundary_matches(existing.spec, spec):
        return ManagedPublication(spec=spec, state=existing.state)
    service_token_id = "planned" if spec.audience in {"machine", "mixed"} else None
    access_application_id = None if spec.audience == "public" else "planned"
    return ManagedPublication(
        spec=spec,
        state=PublicationRemoteState(
            dns_record_id="planned",
            access_application_id=access_application_id,
            access_aud=access_application_id,
            policy_ids=() if spec.audience == "public" else ("planned",),
            service_token_id=service_token_id,
            service_token_client_id=None,
            service_token_keychain_account=None,
            updated_at="planned",
        ),
    )


def _publish_effects(
    *,
    spec: PublicationSpec,
    existing: ManagedPublication | None,
) -> JsonArray:
    """Return truthful planned effects, including audience-transition cleanup."""

    target_audience = spec.audience
    effects: JsonArray = ["persist normalized intent and partial resource ownership"]
    has_access = existing is not None and existing.state.access_application_id is not None
    has_token = existing is not None and existing.state.service_token_id is not None
    boundary_change = existing is not None and not authorization_boundary_matches(
        existing.spec,
        spec,
    )
    if boundary_change:
        effects.extend(
            [
                "withdraw the old ingress and observe every active connector",
                "retire the old Access application only after withdrawal is observed",
            ]
        )
    if target_audience == "public":
        if has_access:
            effects.append("the new public origin owns fail-closed request authentication")
        else:
            effects.extend(["ensure no Access application", "ensure no Access policies"])
    else:
        effects.extend(
            [
                "reuse Access application"
                if has_access and not boundary_change
                else "create Access application with a distinct AUD",
                "verify exact Access policies",
            ]
        )
    if target_audience in {"machine", "mixed"}:
        effects.append("sync service token" if has_token else "create service token")
    elif has_token:
        effects.extend(["delete service token", "delete service-token Keychain secret"])
    else:
        effects.append("no service token")
    effects.extend(
        [
            "sync proxied DNS record",
            "apply candidate routing with native per-route Access guard when protected",
            "observe the exact configuration version on every active connector",
            "retire superseded owned resources and commit publication state",
        ]
    )
    return effects


def _publication_credential_handoff(
    *,
    publication: ManagedPublication,
    runtime: CliRuntime,
) -> JsonObject | None:
    """Return explicit service-token handoff data for machine-capable publications."""

    keychain_account = publication.state.service_token_keychain_account
    client_id = publication.state.service_token_client_id
    service_token_id = publication.state.service_token_id
    if keychain_account is None or client_id is None or service_token_id is None:
        return None
    try:
        client_secret = runtime.keychain.load_secret(account=keychain_account)
    except AppError:
        raise AppError(
            "The publication change completed, but its service-token secret is unavailable "
            + "for credential handoff.",
            code="credential_handoff_unavailable",
            data={"publication_applied": True, "publication_name": publication.spec.name},
            hints=(
                f"Run cloudflare-publish token rotate {publication.spec.name} --yes "
                + "to explicitly issue and store a replacement secret.",
            ),
        ) from None
    return {
        "kind": "access_service_token",
        "service_token": {
            "id": service_token_id,
            "name": publication.spec.name,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    }
