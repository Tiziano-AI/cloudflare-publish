"""Service-token rotation workflow."""

from __future__ import annotations

from dataclasses import replace

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import ServiceTokenSecret
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.models import AppPaths, ManagedPublication
from cloudflare_publish.state import now_rfc3339, replace_publications
from cloudflare_publish.transitions import Mutation
from cloudflare_publish.workflow_support import load_api_token, require_manifest


def run_token_rotate(
    *,
    publication_name: str,
    paths: AppPaths,
    keychain: Keychain,
    http: CurlHttpClient,
    console: Console,
    api_token: str | None = None,
    recover: bool = False,
) -> ServiceTokenSecret:
    """Rotate the service-token secret for one publication."""

    manifest = require_manifest(paths)
    publication = manifest.publications.get(publication_name)
    if publication is None:
        raise AppError(f"Unknown publication {publication_name!r}.")
    if publication.state.service_token_id is None:
        raise AppError(f"Publication {publication_name!r} does not have a machine token.")
    if publication.state.service_token_keychain_account is None:
        raise AppError(f"Publication {publication_name!r} is missing its token Keychain account.")
    pending = manifest.pending
    if recover and (
        pending is None
        or pending.kind != "token_rotate"
        or pending.target != publication_name
        or pending.effect is None
        or pending.effect.kind != "token_rotate"
        or pending.effect.resource_id != publication.state.service_token_id
    ):
        raise AppError(
            "Token recovery requires the exact pending rotation with an unknown secret outcome.",
            code="token_recovery_not_pending",
        )
    mutation = Mutation(
        path=paths.state_file,
        manifest=manifest,
        kind="token_rotate",
        target=publication_name,
        request={
            "service_token_id": publication.state.service_token_id,
            "keychain_account": publication.state.service_token_keychain_account,
        },
    )
    if mutation.pending.phase == "rotated":
        client_id = publication.state.service_token_client_id
        if client_id is None:
            raise AppError("The completed token rotation has no owned client ID.")
        rotated = ServiceTokenSecret(
            id=publication.state.service_token_id,
            name=publication_name,
            client_id=client_id,
            client_secret=keychain.load_secret(
                account=publication.state.service_token_keychain_account,
            ),
        )
        _ = mutation.finish()
        _show_rotated_token(console=console, publication_name=publication_name, rotated=rotated)
        return rotated
    if mutation.pending.effect is not None and not recover:
        raise AppError(
            "Service-token rotation has an unknown outcome; it must not be repeated.",
            code="outcome_unknown",
            hints=(
                "Run cloudflare-publish --json repair plan for the exact pending operation.",
                "A lost service-token secret cannot be recovered by reading its remote ID.",
                f"After review, run cloudflare-publish token rotate {publication_name} "
                + "--recover --yes to explicitly issue another secret for the same token.",
            ),
        )
    api = CloudflareApi(
        http,
        load_api_token(
            keychain=keychain,
            manifest=manifest,
            home=paths.home,
            explicit_token=api_token,
        ),
    )
    if recover:
        remote = api.get_service_token(
            account_id=manifest.manager.account_id,
            service_token_id=publication.state.service_token_id,
        )
        if remote.client_id != publication.state.service_token_client_id:
            raise AppError(
                "The pending rotation's owned service-token client ID has drifted.",
                code="token_recovery_identity_mismatch",
            )
        # Explicit reissue keeps the unresolved effect fenced throughout another POST.
        mutation.save(pending=replace(mutation.pending, phase="recovering"))
    else:
        mutation.before_effect(
            kind="token_rotate",
            resource_id=publication.state.service_token_id,
            resource_name=publication_name,
        )
    rotated = api.rotate_service_token(
        account_id=manifest.manager.account_id,
        service_token_id=publication.state.service_token_id,
    )
    if rotated.id != publication.state.service_token_id:
        raise AppError("Cloudflare returned a different token for the rotation request.")
    keychain.store_secret(
        account=publication.state.service_token_keychain_account,
        secret=rotated.client_secret,
    )
    if (
        keychain.load_secret(
            account=publication.state.service_token_keychain_account,
        )
        != rotated.client_secret
    ):
        raise AppError("The rotated service-token secret could not be verified in Keychain.")
    updated_publication = ManagedPublication(
        spec=publication.spec,
        state=replace(
            publication.state,
            service_token_client_id=rotated.client_id,
            updated_at=now_rfc3339(),
        ),
    )
    publications = dict(manifest.publications)
    publications[publication_name] = updated_publication
    mutation.manifest = replace_publications(mutation.manifest, publications=publications)
    mutation.save(pending=replace(mutation.pending, phase="rotated", effect=None))
    _ = mutation.finish()
    _show_rotated_token(console=console, publication_name=publication_name, rotated=rotated)
    return rotated


def _show_rotated_token(
    *,
    console: Console,
    publication_name: str,
    rotated: ServiceTokenSecret,
) -> None:
    """Emit credentials only on this explicit successful handoff path."""

    console.section("Rotate Token")
    console.note(f"Publication: {publication_name}")
    console.note(f"Client ID: {rotated.client_id}")
    console.note(f"Client secret: {rotated.client_secret}")
