"""Read-only and local lifecycle CLI command handlers."""

from __future__ import annotations

import shlex
from urllib.parse import urlsplit

from cloudflare_publish.cli_output import (
    account_to_object,
    check_groups_to_array,
    check_result_to_object,
    manifest_summary_to_object,
    object_array,
    organization_to_object,
    publication_to_object,
    publications_map_to_object,
    ssh_client_to_object,
    tunnel_to_object,
    zone_to_object,
)
from cloudflare_publish.cli_parser import CliArgs
from cloudflare_publish.cli_runtime import CliRuntime
from cloudflare_publish.cli_shared import api_from_token, raise_requires_yes, require_value
from cloudflare_publish.console import Console
from cloudflare_publish.discover_flow import discover_tunnel, render_tunnel_discovery
from cloudflare_publish.doctor_flow import run_doctor
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject, JsonValue
from cloudflare_publish.models import AppPaths, ManagedPublication, PendingTransition
from cloudflare_publish.repair_flow import (
    pending_effect_candidates,
    run_repair_resolve,
    run_repair_retire_token,
)
from cloudflare_publish.service_flow import (
    collect_service_status,
    run_service_logs,
    run_service_restart,
    run_service_start,
    run_service_status,
    run_service_stop,
)
from cloudflare_publish.state import transition_to_object
from cloudflare_publish.verify_flow import collect_verify_checks, render_verify_checks, run_verify
from cloudflare_publish.workflow_support import canonical_public_url, require_manifest


def run_doctor_command(
    *,
    args: CliArgs,
    runtime: CliRuntime,
    console: Console,
    render: bool,
) -> JsonObject:
    """Run non-mutating diagnostics."""

    ready, auth_source, checks = run_doctor(
        paths=runtime.paths,
        cloudflared=runtime.cloudflared,
        launchd=runtime.launchd,
        keychain=runtime.keychain,
        http=runtime.http,
        explicit_token=args.api_token,
    )
    payload: JsonObject = {
        "ready": ready,
        "auth_source": auth_source,
        "checks": [check_result_to_object(result) for result in checks],
    }
    if render:
        console.section("Doctor")
        console.note("Ready: " + ("yes" if ready else "no"))
        console.note(f"Auth source: {auth_source}")
        for result in checks:
            console.show_check(result)
    return payload


def run_discover_command(
    *,
    args: CliArgs,
    runtime: CliRuntime,
    console: Console,
    render: bool,
) -> JsonObject:
    """Run typed Cloudflare discovery commands."""

    api = api_from_token(args_token=args.api_token, runtime=runtime)
    if args.discover_command == "tunnel":
        payload = discover_tunnel(
            api=api,
            account_id=require_value(
                args.account_id, message="discover tunnel requires --account-id."
            ),
            zone_id=require_value(args.zone_id, message="discover tunnel requires --zone-id."),
            tunnel_id=require_value(
                args.tunnel_id, message="discover tunnel requires a tunnel ID."
            ),
        )
        if render:
            render_tunnel_discovery(console, payload)
        return payload
    if args.discover_command == "accounts":
        accounts = api.list_accounts()
        if render:
            console.section("Accounts")
            if not accounts:
                console.note("No accounts are visible to this API token.")
            for account in accounts:
                console.line(f"{account.id}\t{account.name}")
        return {"accounts": object_array(tuple(account_to_object(item) for item in accounts))}
    if args.discover_command == "zones":
        zones = api.list_zones(name=args.zone_name)
        filtered = tuple(zone for zone in zones if zone.account_id == args.account_id)
        if render:
            console.section("Zones")
            if not filtered:
                console.note("No zones matched this account and name filter.")
            for zone in filtered:
                console.line(
                    f"{zone.id}\t{zone.name}\t{zone.status}\t{zone.zone_type}\t{zone.account_id}"
                )
        return {"zones": object_array(tuple(zone_to_object(item) for item in filtered))}
    if args.discover_command == "zone":
        zone_name = require_value(args.zone_name, message="discover zone requires a zone name.")
        matched_zones = [
            zone for zone in api.list_zones(name=zone_name) if zone.account_id == args.account_id
        ]
        if not matched_zones:
            raise AppError(f"Zone {zone_name!r} is not visible in account {args.account_id!r}.")
        if len(matched_zones) > 1:
            raise AppError(f"Zone {zone_name!r} is ambiguous in account {args.account_id!r}.")
        zone = matched_zones[0]
        if render:
            console.section("Zone")
            console.note(f"ID: {zone.id}")
            console.note(f"Name: {zone.name}")
            console.note(f"Account ID: {zone.account_id}")
            console.note(f"Status: {zone.status}")
            console.note(f"Type: {zone.zone_type}")
        return {"zone": zone_to_object(zone)}
    if args.discover_command == "tunnels":
        account_id = require_value(
            args.account_id,
            message="discover tunnels requires --account-id.",
        )
        tunnels = api.list_tunnels(account_id=account_id)
        if render:
            console.section("Tunnels")
            if not tunnels:
                console.note("No tunnels are visible in this account.")
            for tunnel in tunnels:
                deletion = "" if not tunnel.deleted_at else f"\tdeleted_at={tunnel.deleted_at}"
                console.line(
                    f"{tunnel.id}\t{tunnel.name}\t{tunnel.status}\t"
                    + f"remote_config={tunnel.remote_config}\t{tunnel.created_at}"
                    + deletion
                )
        return {"tunnels": object_array(tuple(tunnel_to_object(item) for item in tunnels))}
    if args.discover_command == "organization":
        account_id = require_value(
            args.account_id,
            message="discover organization requires --account-id.",
        )
        organization = api.get_organization(account_id=account_id)
        if render:
            console.section("Organization")
            console.note(f"Auth domain: {organization.auth_domain}")
            console.note(
                "Require Access protection: enabled"
                if organization.deny_unmatched_requests
                else "Require Access protection: disabled"
            )
            if organization.deny_unmatched_requests_exempted_zone_names:
                console.note(
                    "Exempted zones: "
                    + ", ".join(organization.deny_unmatched_requests_exempted_zone_names)
                )
        return {"organization": organization_to_object(organization)}
    raise AppError("Unknown discover subcommand.")


def run_ls_command(*, paths: AppPaths, console: Console, render: bool) -> JsonObject:
    """Render or serialize the local publication list."""

    manifest = require_manifest(paths)
    if render:
        console.section("Publications")
        console.note(f"Account: {manifest.manager.account_name} ({manifest.manager.account_id})")
        console.note(f"Zone: {manifest.manager.zone_name}")
        console.note(f"Tunnel: {manifest.manager.tunnel_name} ({manifest.manager.tunnel_id})")
        console.note(f"Publications: {len(manifest.publications)}")
        if manifest.pending is not None:
            console.note(
                f"Incomplete: {manifest.pending.kind} {manifest.pending.target} "
                + f"({manifest.pending.operation_id}); run cloudflare-publish repair plan."
            )
        if not manifest.publications:
            console.note("No publications are managed yet.")
        for name in sorted(manifest.publications):
            publication = manifest.publications[name]
            summary = (
                f"{publication.spec.name}\t{publication.spec.hostname}\t"
                + f"{publication.spec.audience}\t{publication.spec.origin_url}"
            )
            console.line(summary)
    return {
        "manifest": manifest_summary_to_object(manifest),
        "publications": publications_map_to_object(manifest.publications),
    }


def run_inspect_command(
    *,
    paths: AppPaths,
    publication_name: str,
    console: Console,
    render: bool,
) -> JsonObject:
    """Render or serialize one publication contract without secrets."""

    manifest = require_manifest(paths)
    publication = manifest.publications.get(publication_name)
    if publication is None:
        raise AppError(f"Unknown publication {publication_name!r}.")
    if render:
        _render_inspect(
            console=console,
            manifest_name=manifest.manager.account_name,
            publication=publication,
        )
    return {
        "manifest": manifest_summary_to_object(manifest),
        "publication": publication_to_object(publication),
    }


def run_verify_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Run verification and preserve verify's nonzero readiness exit behavior."""

    if args.json:
        checks = collect_verify_checks(
            paths=runtime.paths,
            cloudflared=runtime.cloudflared,
            launchd=runtime.launchd,
            keychain=runtime.keychain,
            http=runtime.http,
            publication_name=args.name,
            live=args.live,
            api_token=args.api_token,
        )
        failures = sum(1 for result in checks if not result.ok)
        check_objects = object_array(tuple(check_result_to_object(result) for result in checks))
        if failures != 0:
            raise AppError(
                f"Verification failed with {failures} failing checks.",
                code="verify_failed",
                data={
                    "checks": check_objects,
                    "groups": check_groups_to_array(checks),
                    "failures": failures,
                },
            )
        return {
            "checks": check_objects,
            "groups": check_groups_to_array(checks),
            "failures": failures,
        }
    failures = run_verify(
        paths=runtime.paths,
        cloudflared=runtime.cloudflared,
        launchd=runtime.launchd,
        keychain=runtime.keychain,
        http=runtime.http,
        publication_name=args.name,
        live=args.live,
        console=console,
        api_token=args.api_token,
    )
    if failures != 0:
        raise AppError(f"Verification failed with {failures} failing checks.", code="verify_failed")
    return {"failures": 0}


def run_repair_command(
    *,
    args: CliArgs,
    runtime: CliRuntime,
    console: Console,
    render: bool,
) -> JsonObject:
    """Explain pending custody, resolve one exact effect, or plan manager repair."""

    if args.repair_command in {"resolve", "retire-token"}:
        if not args.yes:
            raise_requires_yes(f"repair {args.repair_command}")
        operation_id = require_value(args.operation_id, message="repair requires --operation.")
        if args.repair_command == "resolve":
            manifest = run_repair_resolve(
                paths=runtime.paths,
                keychain=runtime.keychain,
                http=runtime.http,
                operation_id=operation_id,
                resource_id=args.resource_id,
                absent=args.absent,
                api_token=args.api_token,
            )
        else:
            manifest = run_repair_retire_token(
                paths=runtime.paths,
                keychain=runtime.keychain,
                http=runtime.http,
                operation_id=operation_id,
                resource_id=require_value(args.resource_id, message="Missing --resource-id."),
                api_token=args.api_token,
            )
        if render:
            console.note("Resolution recorded. Resume the original operation; it is not complete.")
        result: JsonObject = {"manifest": manifest_summary_to_object(manifest), "resolved": True}
        if manifest.pending is not None:
            result["recommended_next_commands"] = list(_pending_recommendations(manifest.pending))
            candidate = manifest.pending.candidate
            if candidate is not None and candidate.state.service_token_keychain_account is not None:
                try:
                    _ = runtime.keychain.load_secret(
                        account=candidate.state.service_token_keychain_account,
                    )
                    result["credential_ready"] = True
                except AppError:
                    result["credential_ready"] = False
        return result
    if args.repair_command != "plan":
        raise AppError("Unknown repair subcommand.")
    manifest = require_manifest(runtime.paths)
    if manifest.pending is not None:
        pending = manifest.pending
        pending_commands = _pending_recommendations(pending)
        pending_payload: JsonObject = {
            "plan": True,
            "action": "repair plan",
            "ready": False,
            "pending": transition_to_object(pending),
            "recommended_next_commands": list(pending_commands),
        }
        candidates: tuple[JsonObject, ...] = ()
        if pending.effect is not None:
            try:
                api = api_from_token(args_token=args.api_token, runtime=runtime)
                candidates = pending_effect_candidates(manifest=manifest, api=api)
                pending_payload["matching_resources"] = list(candidates)
            except AppError as error:
                pending_payload["observation_error"] = {
                    "code": error.code,
                    "message": error.message,
                }
        if render:
            console.section("Repair Plan")
            console.note(f"Incomplete: {pending.kind} {pending.target}; phase={pending.phase}")
            console.note(f"Operation: {pending.operation_id}")
            if pending.effect is not None:
                console.note(f"Unknown provider result: {pending.effect.kind}")
                for item in candidates:
                    console.line(str(item))
            for command in pending_commands:
                console.note(f"Next: {command}")
        return pending_payload
    checks = collect_verify_checks(
        paths=runtime.paths,
        cloudflared=runtime.cloudflared,
        launchd=runtime.launchd,
        keychain=runtime.keychain,
        http=runtime.http,
        publication_name=None,
        live=False,
        api_token=args.api_token,
    )
    failures = sum(1 for result in checks if not result.ok)
    recommendations: list[JsonValue] = [item for item in _repair_recommendations(failures=failures)]
    payload: JsonObject = {
        "plan": True,
        "action": "repair plan",
        "checks": object_array(tuple(check_result_to_object(result) for result in checks)),
        "groups": check_groups_to_array(checks),
        "failures": failures,
        "recommended_next_commands": recommendations,
    }
    if render:
        console.section("Repair Plan")
        console.note(f"Failing checks: {failures}")
        render_verify_checks(console, checks)
        for command in _repair_recommendations(failures=failures):
            console.note(f"Next: {command}")
    return payload


def _pending_recommendations(pending: PendingTransition) -> tuple[str, ...]:
    """Name the original operation, never a refresh that could resurrect a withdrawal."""

    operation = shlex.quote(pending.operation_id)
    target = shlex.quote(pending.target)
    if pending.effect is not None:
        if pending.effect.kind == "token_retire":
            return (
                f"cloudflare-publish repair retire-token --operation {operation} "
                + f"--resource-id {shlex.quote(pending.effect.resource_id or '<token-id>')} --yes",
            )
        if pending.effect.kind == "token_rotate":
            return (f"cloudflare-publish token rotate {target} --recover --yes",)
        if pending.effect.kind == "service_token" and pending.candidate is not None:
            return (
                f"cloudflare-publish repair resolve --operation {operation} "
                + "--resource-id <matching-id> --yes",
                f"cloudflare-publish repair retire-token --operation {operation} "
                + "--resource-id <matching-id> --yes (if its secret was lost)",
            )
        return (
            f"cloudflare-publish repair resolve --operation {operation} "
            + "--resource-id <matching-id> --yes",
            f"cloudflare-publish repair resolve --operation {operation} --absent --yes "
            + "(only after the complete resource observation proves absence)",
        )
    if pending.kind == "remove":
        return (f"cloudflare-publish rm apply {target} --yes",)
    if pending.kind == "teardown":
        return ("cloudflare-publish teardown --yes",)
    if pending.kind == "setup_refresh":
        return ("cloudflare-publish setup --refresh-only",)
    if pending.kind == "setup":
        return ("cloudflare-publish setup (repeat --takeover --yes only if originally selected)",)
    if pending.kind == "token_rotate":
        return (f"cloudflare-publish token rotate {target} --yes",)
    request = pending.request
    argv = ["cloudflare-publish", "publish", "apply", pending.target]
    for key, flag in (
        ("hostname", "--hostname"),
        ("origin_url", "--to"),
        ("audience", "--audience"),
        ("verify_path", "--verify-path"),
        ("expect_status", "--expect-status"),
        ("http_host_header", "--http-host-header"),
        ("origin_server_name", "--origin-server-name"),
        ("ssh_host_key", "--ssh-host-key"),
    ):
        value = request.get(key)
        if isinstance(value, str):
            argv.extend((flag, value))
    for key, flag in (
        ("allowed_emails", "--allow-email"),
        ("allowed_email_domains", "--allow-domain"),
    ):
        values = request.get(key)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str):
                    argv.extend((flag, value))
    if request.get("no_tls_verify") is True:
        argv.append("--no-tls-verify")
    argv.append("--yes")
    commands = [shlex.join(argv)]
    candidate = pending.candidate
    if candidate is not None and candidate.state.service_token_id is not None:
        commands.insert(
            0,
            "If the candidate secret is unavailable: cloudflare-publish repair retire-token "
            + f"--operation {operation} --resource-id "
            + f"{shlex.quote(candidate.state.service_token_id)} --yes",
        )
    return tuple(commands)


def run_service_command(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Dispatch local connector lifecycle commands."""

    if args.service_command == "status":
        if args.json:
            return collect_service_status(
                paths=runtime.paths,
                cloudflared=runtime.cloudflared,
                launchd=runtime.launchd,
            )
        run_service_status(
            paths=runtime.paths,
            cloudflared=runtime.cloudflared,
            launchd=runtime.launchd,
            console=console,
        )
        return {"status": "rendered"}
    if args.service_command == "start":
        run_service_start(
            paths=runtime.paths,
            cloudflared=runtime.cloudflared,
            launchd=runtime.launchd,
            console=console,
        )
        return {"action": "service start"}
    if args.service_command == "stop":
        run_service_stop(paths=runtime.paths, launchd=runtime.launchd, console=console)
        return {"action": "service stop"}
    if args.service_command == "restart":
        run_service_restart(
            paths=runtime.paths,
            cloudflared=runtime.cloudflared,
            launchd=runtime.launchd,
            console=console,
        )
        return {"action": "service restart"}
    if args.service_command == "logs":
        run_service_logs(paths=runtime.paths, lines=args.log_lines, console=console)
        return {"action": "service logs", "lines": args.log_lines}
    raise AppError("Unknown service subcommand.")


def _render_inspect(
    *,
    console: Console,
    manifest_name: str,
    publication: ManagedPublication,
) -> None:
    """Render the human inspect view."""

    spec = publication.spec
    state = publication.state
    console.section("Inspect")
    console.note(f"Account: {manifest_name}")
    console.note(f"Name: {spec.name}")
    console.note(f"Kind: {spec.kind}")
    console.note(f"Hostname: {spec.hostname}")
    console.note(f"Origin: {spec.origin_url}")
    console.note(f"Audience: {spec.audience}")
    if spec.kind == "ssh_public":
        client = ssh_client_to_object(spec)
        console.note(f"Pinned SSH host key: {spec.ssh_host_key}")
        console.note(f"SSH ProxyCommand: {client['proxy_command']}")
        console.note(f"SSH known_hosts line: {client['known_hosts_line']}")
        console.note("SSH HostKeyAlgorithms: ssh-ed25519")
        console.note("SSH StrictHostKeyChecking: yes")
        console.note(
            "SSH service-token environment: TUNNEL_SERVICE_TOKEN_ID, TUNNEL_SERVICE_TOKEN_SECRET"
        )
        console.note("SSH login user and private key remain operator-managed.")
    else:
        if spec.verify_path is not None:
            console.note(
                "Public verify URL: " + canonical_public_url(spec.hostname, spec.verify_path)
            )
        console.note(f"Verify path: {spec.verify_path}")
        console.note(f"Expect status: {spec.expect_status}")
    if spec.allowed_emails:
        console.note("Allowed emails: " + ", ".join(spec.allowed_emails))
    if spec.allowed_email_domains:
        console.note("Allowed domains: " + ", ".join(spec.allowed_email_domains))
    if spec.kind == "http_public":
        console.note(
            "Origin Host header: " + _display_optional(spec.origin_options.http_host_header)
        )
        console.note(
            "Origin server name: " + _display_optional(spec.origin_options.origin_server_name)
        )
        console.note(
            "Origin TLS verification: "
            + _origin_tls_mode(spec.origin_url, spec.origin_options.no_tls_verify)
        )
    console.note(f"Access app ID: {state.access_application_id}")
    console.note(f"Access AUD: {state.access_aud}")
    console.note(f"DNS record ID: {state.dns_record_id}")
    console.note("Policy IDs: " + ", ".join(state.policy_ids))
    if state.service_token_id is not None:
        console.note(f"Service token ID: {state.service_token_id}")
        if state.service_token_client_id is not None:
            console.note(f"Service token client ID: {state.service_token_client_id}")


def _display_optional(value: str | None) -> str:
    """Render optional inspect fields without hiding unset state."""

    if value is None:
        return "unset"
    return value


def _origin_tls_mode(origin_url: str, no_tls_verify: bool) -> str:
    """Render the effective inspect label for origin TLS verification."""

    scheme = urlsplit(origin_url).scheme
    if scheme == "http":
        return "not applicable"
    if no_tls_verify:
        return "disabled"
    return "enabled"


def _repair_recommendations(*, failures: int) -> list[str]:
    """Return conservative next commands for the read-only repair plan."""

    if failures == 0:
        return ["cloudflare-publish verify --live"]
    return [
        "cloudflare-publish setup --refresh-only",
        "cloudflare-publish verify",
        "cloudflare-publish verify --live",
    ]
