"""Manager bootstrap workflow."""

from __future__ import annotations

import getpass
import sys
from dataclasses import replace

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import AccountRef, TunnelRef, ZoneRef
from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.config_application import require_configuration_applied
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.local_connector_observation import LocalConnectorObserver
from cloudflare_publish.models import (
    API_TOKEN_ACCOUNT,
    DEFAULT_TUNNEL_NAME,
    AppPaths,
    BackupRecord,
    ManagerConfig,
    SetupRequest,
    StateManifest,
)
from cloudflare_publish.ownership import (
    OwnershipInspection,
    cleanup_conflicts,
    create_backup,
    inspect_ownership,
    require_takeover,
)
from cloudflare_publish.render import build_tunnel_configuration
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.state import (
    build_initial_manifest,
    load_manifest,
    replace_manager,
)
from cloudflare_publish.transitions import Mutation, effective_publications, require_no_pending
from cloudflare_publish.tunnel_configuration import (
    compare_tunnel_configuration,
    require_refresh_configuration_owned,
)
from cloudflare_publish.workflow_support import (
    ensure_manager_directories,
    ensure_platform_tools,
    install_connector_service,
    load_api_token,
    write_tunnel_token,
)


def run_setup(
    *,
    request: SetupRequest,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
) -> StateManifest:
    """Bootstrap or refresh the local manager."""

    if paths.host_platform == "linux" and request.install_deps:
        raise AppError(
            "Automatic dependency installation is supported only on macOS through Homebrew.",
            code="unsupported_dependency_install",
            hints=("Install the documented Linux prerequisites before running setup.",),
        )
    if paths.host_platform == "linux" and request.takeover:
        raise AppError(
            "Legacy takeover is supported only on macOS.",
            code="unsupported_takeover",
            hints=(
                "Resolve Linux legacy service/configuration ownership explicitly before setup.",
            ),
        )
    existing = load_manifest(paths.state_file)
    if request.refresh_only and existing is None:
        _raise_refresh_requires_manager()
    if existing is not None and existing.pending is not None:
        if existing.pending.kind not in {"setup", "setup_refresh"}:
            require_no_pending(existing)
        if existing.pending.kind == "setup" and request.refresh_only:
            raise AppError(
                "Initial setup is incomplete; resume setup without --refresh-only.",
                code="transition_pending",
            )
        _validate_refresh_request(request=request, manifest=existing)

    ensure_platform_tools(
        cloudflared=cloudflared,
        launchd=launchd,
        keychain=keychain,
        install_deps=request.install_deps,
    )
    ensure_manager_directories(paths)
    inspection = inspect_ownership(paths, launchd)
    manifest = inspection.manifest
    resuming_setup = (
        manifest is not None and manifest.pending is not None and (manifest.pending.kind == "setup")
    )
    if inspection.requires_takeover and not request.takeover and not resuming_setup:
        require_takeover(inspection)

    console.section("Setup")
    if manifest is not None:
        if resuming_setup:
            _validate_refresh_request(request=request, manifest=manifest)
            mutation = Mutation(
                path=paths.state_file,
                manifest=manifest,
                kind="setup",
                target=manifest.manager.tunnel_name,
                request=_setup_identity(manifest.manager),
            )
            return _complete_initial_setup(
                mutation=mutation,
                request=request,
                paths=paths,
                cloudflared=cloudflared,
                launchd=launchd,
                keychain=keychain,
                http=http,
                console=console,
            )
        return _run_setup_refresh(
            request=request,
            manifest=manifest,
            paths=paths,
            cloudflared=cloudflared,
            launchd=launchd,
            keychain=keychain,
            http=http,
            console=console,
        )

    if request.refresh_only:
        _raise_refresh_requires_manager()

    api_token = _resolve_initial_api_token(request.api_token)
    api = CloudflareApi(http, api_token)
    account = _select_account(api=api, explicit_account_id=request.account_id, console=console)
    zone = _select_zone(
        api=api,
        account_id=account.id,
        explicit_zone_id=request.zone_id,
        explicit_zone_name=request.zone_name,
        console=console,
    )
    _require_zone_belongs_to_account(account=account, zone=zone)
    _require_supported_zone(zone)
    organization = api.get_organization(account_id=account.id)
    tunnel_name = _resolve_tunnel_name(request.tunnel_name)
    _ensure_remote_tunnel_name_is_unused(api=api, account_id=account.id, tunnel_name=tunnel_name)

    manager = ManagerConfig(
        account_id=account.id,
        account_name=account.name,
        zone_id=zone.id,
        zone_name=zone.name,
        auth_domain=organization.auth_domain,
        tunnel_name=tunnel_name,
        tunnel_id="",
        api_token_keychain_account=API_TOKEN_ACCOUNT,
    )
    mutation = Mutation(
        path=paths.state_file,
        manifest=build_initial_manifest(manager=manager),
        kind="setup",
        target=tunnel_name,
        request=_setup_identity(manager),
    )
    return _complete_initial_setup(
        mutation=mutation,
        request=replace(request, api_token=api_token),
        paths=paths,
        cloudflared=cloudflared,
        launchd=launchd,
        keychain=keychain,
        http=http,
        console=console,
    )


def _setup_identity(manager: ManagerConfig) -> JsonObject:
    """Normalize only selected identity; never persist an API credential in intent."""

    return {
        "account_id": manager.account_id,
        "zone_id": manager.zone_id,
        "zone_name": manager.zone_name,
        "tunnel_name": manager.tunnel_name,
    }


def _complete_initial_setup(
    *,
    mutation: Mutation,
    request: SetupRequest,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
) -> StateManifest:
    """Resume bootstrap from durable owned identities, including before tunnel creation."""

    if mutation.pending.effect is not None:
        raise AppError(
            "Tunnel creation has an unknown outcome; the POST must not be repeated.",
            code="outcome_unknown",
            hints=("Run cloudflare-publish --json repair plan to resolve the exact operation.",),
        )
    manifest = mutation.manifest
    token = load_api_token(
        keychain=keychain,
        manifest=manifest,
        home=paths.home,
        explicit_token=request.api_token,
    )
    api = CloudflareApi(http, token)
    if request.api_token is not None:
        # The API credential and selected identity must survive before any remote POST.
        keychain.store_secret(account=manifest.manager.api_token_keychain_account, secret=token)
    inspection = inspect_ownership(paths, launchd)
    if inspection.requires_takeover:
        if not manifest.backups:
            if not request.takeover:
                require_takeover(inspection)
            backup = create_backup(paths, inspection)
            mutation.manifest = replace(mutation.manifest, backups=(backup,))
            mutation.save(pending=replace(mutation.pending, phase="takeover_backed_up"))
            console.note(f"Backed up conflicting local cloudflared state to {backup.directory}")
        # Ownership of the backup is durable before any original is removed.
        _require_backed_up_conflicts(
            paths=paths,
            inspection=inspection,
            backup=mutation.manifest.backups[0],
        )
        cleanup_conflicts(paths, launchd, inspection)
    manager = mutation.manifest.manager
    if not manager.tunnel_id:
        zone = _select_zone(
            api=api,
            account_id=manager.account_id,
            explicit_zone_id=manager.zone_id,
            explicit_zone_name=manager.zone_name,
            console=console,
        )
        _require_supported_zone(zone)
        remote_name = f"{manager.tunnel_name}:{mutation.pending.operation_id}"
        _ensure_remote_tunnel_name_is_unused(
            api=api,
            account_id=manager.account_id,
            tunnel_name=remote_name,
        )
        mutation.before_effect(kind="tunnel", resource_name=remote_name)
        tunnel = api.create_tunnel(account_id=manager.account_id, name=remote_name)
        _require_live_managed_tunnel(tunnel, expected_name=remote_name)
        mutation.manifest = replace_manager(
            mutation.manifest,
            manager=replace(manager, tunnel_id=tunnel.id),
        )
        mutation.observed()
        mutation.save(pending=replace(mutation.pending, phase="tunnel_created"))
    else:
        _require_live_managed_tunnel(
            api.get_tunnel(account_id=manager.account_id, tunnel_id=manager.tunnel_id),
            expected_id=manager.tunnel_id,
        )
    return _complete_setup_configuration(
        mutation=mutation,
        api=api,
        paths=paths,
        cloudflared=cloudflared,
        launchd=launchd,
        http=http,
        console=console,
    )


def _require_backed_up_conflicts(
    *,
    paths: AppPaths,
    inspection: OwnershipInspection,
    backup: BackupRecord,
) -> None:
    """A resumed takeover must not discard edits made after its preserved copy."""

    for original in inspection.conflicting_paths:
        retained = backup.directory / original.relative_to(paths.home)
        if (
            original not in backup.copied_paths
            or not retained.is_file()
            or not original.is_file()
            or original.read_bytes() != retained.read_bytes()
        ):
            raise AppError(
                "Legacy cloudflared state changed after the takeover backup was saved.",
                code="takeover_conflict_changed",
                hints=(
                    "Keep the current originals and inspect the retained backup before resuming.",
                    f"Changed path: {original}",
                ),
            )


def _run_setup_refresh(
    *,
    request: SetupRequest,
    manifest: StateManifest,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
) -> StateManifest:
    """Refresh a manager that is already bootstrapped."""

    _validate_refresh_request(request=request, manifest=manifest)
    if manifest.pending is not None and manifest.pending.kind != "setup_refresh":
        require_no_pending(manifest)
    api_token = (
        request.api_token
        if request.api_token is not None
        else load_api_token(
            keychain=keychain,
            manifest=manifest,
            home=paths.home,
        )
    )
    api = CloudflareApi(http, api_token)
    tunnel = api.get_tunnel(
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
    )
    _require_live_managed_tunnel(tunnel, expected_id=manifest.manager.tunnel_id)
    organization = api.get_organization(account_id=manifest.manager.account_id)
    expected = build_tunnel_configuration(
        effective_publications(manifest),
        auth_domain=organization.auth_domain,
    )
    actual = api.get_tunnel_configuration(
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
    )
    require_refresh_configuration_owned(actual=actual, expected=expected)
    mutation = Mutation(
        path=paths.state_file,
        manifest=manifest,
        kind="setup_refresh",
        target=manifest.manager.tunnel_name,
        request=_setup_identity(manifest.manager),
    )
    if request.api_token is not None:
        keychain.store_secret(
            account=manifest.manager.api_token_keychain_account,
            secret=request.api_token,
        )
    updated_manager = ManagerConfig(
        account_id=manifest.manager.account_id,
        account_name=manifest.manager.account_name,
        zone_id=manifest.manager.zone_id,
        zone_name=manifest.manager.zone_name,
        auth_domain=organization.auth_domain,
        tunnel_name=manifest.manager.tunnel_name,
        tunnel_id=tunnel.id,
        api_token_keychain_account=manifest.manager.api_token_keychain_account,
    )
    mutation.manifest = replace_manager(mutation.manifest, manager=updated_manager)
    mutation.save()
    result = _complete_setup_configuration(
        mutation=mutation,
        api=api,
        paths=paths,
        cloudflared=cloudflared,
        launchd=launchd,
        http=http,
        console=console,
    )
    console.note(f"Refreshed tunnel token for {tunnel.name}.")
    return result


def _require_live_managed_tunnel(
    tunnel: TunnelRef,
    *,
    expected_id: str | None = None,
    expected_name: str | None = None,
) -> None:
    """Do not adopt another identity, a local-config tunnel, or a deletion tombstone."""

    if (
        not tunnel.id
        or (expected_id is not None and tunnel.id != expected_id)
        or (expected_name is not None and tunnel.name != expected_name)
        or not tunnel.remote_config
        or tunnel.deleted_at is not None
    ):
        raise AppError(
            "Cloudflare did not return the expected live remotely managed tunnel.",
            code="tunnel_identity_mismatch",
        )


def _complete_setup_configuration(
    *,
    mutation: Mutation,
    api: CloudflareApi,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    http: CurlHttpClient,
    console: Console,
) -> StateManifest:
    """Apply one owned configuration and retain custody if its application is unobserved."""

    manager = mutation.manifest.manager
    if mutation.pending.phase not in {"configured", "installed"}:
        version = api.update_tunnel_configuration(
            account_id=manager.account_id,
            tunnel_id=manager.tunnel_id,
            configuration=build_tunnel_configuration(
                effective_publications(mutation.manifest),
                auth_domain=manager.auth_domain,
            ),
        )
        mutation.save(
            pending=replace(
                mutation.pending,
                phase="configured",
                configuration_version=version,
            )
        )
    # A retained version describes an earlier PUT, not the current stored body.
    # Reobserve both together on every completion path, including installed resumes.
    snapshot = api.get_tunnel_configuration_snapshot(
        account_id=manager.account_id,
        tunnel_id=manager.tunnel_id,
    )
    comparison = compare_tunnel_configuration(
        actual=snapshot.config,
        expected=build_tunnel_configuration(
            effective_publications(mutation.manifest),
            auth_domain=manager.auth_domain,
        ),
    )
    if not comparison.matches:
        raise AppError(
            "The stored setup configuration differs from the owned desired configuration.",
            code="tunnel_configuration_drift",
            hints=(comparison.detail or "Inspect the exact remote configuration.",),
        )
    if mutation.pending.configuration_version != snapshot.version:
        mutation.save(
            pending=replace(
                mutation.pending,
                configuration_version=snapshot.version,
            )
        )
    if mutation.pending.phase != "installed":
        token = api.get_tunnel_token(account_id=manager.account_id, tunnel_id=manager.tunnel_id)
        write_tunnel_token(paths, token)
        install_connector_service(cloudflared=cloudflared, launchd=launchd)
        mutation.save(pending=replace(mutation.pending, phase="installed"))
    observation = require_configuration_applied(
        api,
        account_id=manager.account_id,
        tunnel_id=manager.tunnel_id,
        expected_version=mutation.pending.configuration_version,
        local_observer=LocalConnectorObserver(launchd, http),
    )
    if observation.no_active_connectors:
        raise AppError(
            "Setup installed the connector, but no active connector application is observable.",
            code="configuration_application_unobserved",
            hints=("Resume the same setup after the connector reports the stored configuration.",),
        )
    console.note(f"Account: {manager.account_name}")
    console.note(f"Zone: {manager.zone_name}")
    console.note(f"Tunnel: {manager.tunnel_name} ({manager.tunnel_id})")
    console.note(f"Access organization: {manager.auth_domain}")
    return mutation.finish()


def _raise_refresh_requires_manager() -> None:
    """Fail refresh-only setup when no local manager is available to repair."""

    raise AppError(
        "Setup refresh requires existing local manager state.",
        hints=("Run initial setup without --refresh-only before using refresh actions.",),
    )


def _resolve_initial_api_token(explicit_token: str | None) -> str:
    """Resolve the initial Cloudflare API token."""

    if explicit_token is not None and explicit_token.strip():
        return explicit_token.strip()
    if sys.stdin.isatty():
        entered = getpass.getpass("Cloudflare API token: ").strip()
        if entered:
            return entered
    raise AppError(
        "Cloudflare API token is required for initial setup.",
        hints=(
            (
                "Use the setup prompt, set CLOUDFLARE_API_TOKEN, or populate "
                "CLOUDFLARE_PUBLISH_DOTENV with an absolute private dotenv path."
            ),
        ),
    )


def _select_account(
    *,
    api: CloudflareApi,
    explicit_account_id: str | None,
    console: Console,
) -> AccountRef:
    """Resolve the managed Cloudflare account."""

    accounts = api.list_accounts()
    if explicit_account_id is not None:
        for account in accounts:
            if account.id == explicit_account_id:
                return account
        raise AppError(f"Account {explicit_account_id!r} is not visible to the API token.")
    if len(accounts) == 1:
        return accounts[0]
    if sys.stdin.isatty():
        console.note("Visible Cloudflare accounts:")
        for account in accounts:
            console.note(f"- {account.name} ({account.id})")
        selected = input("Cloudflare account ID: ").strip()
        for account in accounts:
            if account.id == selected:
                return account
    raise AppError("Cloudflare account is ambiguous. Pass --account-id.")


def _select_zone(
    *,
    api: CloudflareApi,
    account_id: str,
    explicit_zone_id: str | None,
    explicit_zone_name: str | None,
    console: Console,
) -> ZoneRef:
    """Resolve the managed Cloudflare DNS zone."""

    zones = _zones_in_account(api.list_zones(name=explicit_zone_name), account_id=account_id)
    if explicit_zone_id is not None:
        for zone in zones:
            if zone.id == explicit_zone_id:
                return zone
        for zone in api.list_zones():
            if zone.id == explicit_zone_id:
                if zone.account_id != account_id:
                    raise AppError(
                        (
                            f"Zone {zone.id!r} is owned by account {zone.account_id!r}, "
                            f"not {account_id!r}."
                        ),
                        hints=(
                            "Choose a zone in the selected account "
                            + "or pass the matching --account-id.",
                        ),
                    )
                return zone
        raise AppError(f"Zone {explicit_zone_id!r} is not visible to the API token.")
    if explicit_zone_name is not None:
        exact = [zone for zone in zones if zone.name == explicit_zone_name]
        if len(exact) == 1:
            return exact[0]
        if not exact:
            visible_elsewhere = [
                zone
                for zone in api.list_zones(name=explicit_zone_name)
                if zone.name == explicit_zone_name
            ]
            if len(visible_elsewhere) == 1:
                zone = visible_elsewhere[0]
                raise AppError(
                    (
                        f"Zone {zone.name!r} is owned by account {zone.account_id!r}, "
                        f"not {account_id!r}."
                    ),
                    hints=(
                        "Choose a zone in the selected account "
                        + "or pass the matching --account-id.",
                    ),
                )
            raise AppError(
                f"Zone {explicit_zone_name!r} is not visible in account {account_id!r}.",
            )
    if len(zones) == 1:
        return zones[0]
    if sys.stdin.isatty():
        console.note("Visible Cloudflare zones:")
        for zone in zones:
            console.note(f"- {zone.name} ({zone.id})")
        selected = input("Cloudflare zone name or ID: ").strip()
        for zone in zones:
            if zone.id == selected or zone.name == selected:
                return zone
    raise AppError("Cloudflare zone is ambiguous. Pass --zone or --zone-id.")


def _ensure_remote_tunnel_name_is_unused(
    *,
    api: CloudflareApi,
    account_id: str,
    tunnel_name: str,
) -> None:
    """Reject silent adoption of a same-name remote tunnel."""

    for tunnel in api.list_tunnels(account_id=account_id):
        if tunnel.name == tunnel_name:
            raise AppError(
                f"A remote tunnel named {tunnel_name!r} already exists.",
                hints=("Delete it manually or choose a different --tunnel-name.",),
            )


def _zones_in_account(zones: tuple[ZoneRef, ...], *, account_id: str) -> tuple[ZoneRef, ...]:
    """Return only the zones owned by the selected account."""

    return tuple(zone for zone in zones if zone.account_id == account_id)


def _require_zone_belongs_to_account(*, account: AccountRef, zone: ZoneRef) -> None:
    """Fail closed when the chosen zone is not owned by the chosen account."""

    if zone.account_id == account.id:
        return
    raise AppError(
        f"Zone {zone.name!r} is owned by account {zone.account_id!r}, not {account.id!r}.",
        hints=("Choose a zone in the selected account or pass the matching --account-id.",),
    )


def _require_supported_zone(zone: ZoneRef) -> None:
    """Fail closed unless the selected zone is active and fully Cloudflare-managed."""

    if zone.zone_type != "full":
        raise AppError(
            f"Zone {zone.name!r} must be a full Cloudflare-managed zone, not {zone.zone_type!r}.",
            hints=(
                "Partial CNAME zones are unsupported because this product "
                + "manages DNS records directly.",
            ),
        )
    if zone.status != "active":
        raise AppError(
            f"Zone {zone.name!r} must be active before setup, not {zone.status!r}.",
        )


def _resolve_tunnel_name(value: str | None) -> str:
    """Resolve the canonical tunnel name."""

    if value is None or not value.strip():
        return DEFAULT_TUNNEL_NAME
    return value.strip()


def _validate_refresh_request(*, request: SetupRequest, manifest: StateManifest) -> None:
    """Reject attempts to change manager identity through refresh setup."""

    expected = manifest.manager
    if request.account_id is not None and request.account_id != expected.account_id:
        raise AppError("Setup cannot switch to a different account without teardown.")
    if request.zone_id is not None and request.zone_id != expected.zone_id:
        raise AppError("Setup cannot switch to a different zone without teardown.")
    if request.zone_name is not None and request.zone_name != expected.zone_name:
        raise AppError("Setup cannot switch to a different zone without teardown.")
    tunnel_name = _resolve_tunnel_name(request.tunnel_name)
    if request.tunnel_name is not None and tunnel_name != expected.tunnel_name:
        raise AppError("Setup cannot switch to a different tunnel name without teardown.")
