"""Zero Trust account-level default-deny workflow."""

from __future__ import annotations

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import OrganizationRef
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.models import AppPaths, ManagerConfig, StateManifest
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.state import replace_manager, write_manifest
from cloudflare_publish.workflow_support import load_api_token, require_manifest


def run_guard_status(
    *,
    paths: AppPaths,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
    api_token: str | None = None,
) -> OrganizationRef:
    """Report account-level require-protection status."""

    manifest = require_manifest(paths)
    api = CloudflareApi(
        http,
        load_api_token(
            keychain=keychain,
            manifest=manifest,
            home=paths.home,
            explicit_token=api_token,
        ),
    )
    organization = api.get_organization(account_id=manifest.manager.account_id)
    console.section("Guard Status")
    console.note(f"Auth domain: {organization.auth_domain}")
    console.note(
        "Require Access protection: enabled"
        if organization.deny_unmatched_requests
        else "Require Access protection: disabled"
    )
    if not organization.deny_unmatched_requests:
        blocking_publications = guard_blocking_publication_names(
            manifest=manifest,
            organization=organization,
        )
        if blocking_publications:
            console.note(
                "Guard unavailable while public publications remain: "
                + ", ".join(blocking_publications)
            )
        else:
            console.note(
                "Risk: hostnames without a matching Access application are not blocked by default."
            )
            console.note("Next: cloudflare-publish guard plan")
            console.note("Apply: cloudflare-publish guard apply --yes")
    if organization.deny_unmatched_requests_exempted_zone_names:
        console.note(
            "Exempted zones: " + ", ".join(organization.deny_unmatched_requests_exempted_zone_names)
        )
    return organization


def run_guard_enable(
    *,
    paths: AppPaths,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
    api_token: str | None = None,
) -> OrganizationRef:
    """Enable account-level require-protection."""

    manifest = require_manifest(paths)
    api = CloudflareApi(
        http,
        load_api_token(
            keychain=keychain,
            manifest=manifest,
            home=paths.home,
            explicit_token=api_token,
        ),
    )
    organization = api.get_organization(account_id=manifest.manager.account_id)
    _require_publications_guard_compatible(manifest=manifest, organization=organization)
    if organization.deny_unmatched_requests:
        console.section("Guard Enable")
        console.note("Require Access protection is already enabled.")
        return organization
    payload = dict(organization.raw_payload)
    payload["deny_unmatched_requests"] = True
    updated = api.update_organization(
        account_id=manifest.manager.account_id,
        payload=payload,
    )
    refreshed_manifest = replace_manager(
        manifest,
        manager=ManagerConfig(
            account_id=manifest.manager.account_id,
            account_name=manifest.manager.account_name,
            zone_id=manifest.manager.zone_id,
            zone_name=manifest.manager.zone_name,
            auth_domain=updated.auth_domain,
            tunnel_name=manifest.manager.tunnel_name,
            tunnel_id=manifest.manager.tunnel_id,
            api_token_keychain_account=manifest.manager.api_token_keychain_account,
        ),
    )
    write_manifest(paths.state_file, refreshed_manifest)
    console.section("Guard Enable")
    console.note("Require Access protection enabled.")
    return updated


def require_guard_compatible(*, manifest: StateManifest, organization: OrganizationRef) -> None:
    """Deny guard enablement that would make a managed public publication unreachable."""

    _require_publications_guard_compatible(manifest=manifest, organization=organization)


def guard_blocking_publication_names(
    *,
    manifest: StateManifest,
    organization: OrganizationRef,
) -> tuple[str, ...]:
    """Return public publications that account-wide require-protection would block."""

    if manifest.manager.zone_name in organization.deny_unmatched_requests_exempted_zone_names:
        return ()
    return tuple(
        sorted(
            publication.spec.name
            for publication in manifest.publications.values()
            if publication.spec.audience == "public"
        )
    )


def _require_publications_guard_compatible(
    *,
    manifest: StateManifest,
    organization: OrganizationRef,
) -> None:
    public_names = guard_blocking_publication_names(
        manifest=manifest,
        organization=organization,
    )
    if not public_names:
        return
    raise AppError(
        "Require-protection would block managed public publications.",
        hints=(f"Public publications: {', '.join(public_names)}.",),
    )
