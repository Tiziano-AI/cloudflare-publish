"""Full manager retirement workflow."""

from __future__ import annotations

from dataclasses import replace

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.models import AppPaths, StateManifest
from cloudflare_publish.publication_remote import delete_publication_remote
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.transitions import Mutation
from cloudflare_publish.workflow_support import (
    load_api_token,
    remove_local_manager_artifacts,
    require_manifest,
)


def run_teardown(
    *,
    paths: AppPaths,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
    api_token: str | None = None,
) -> StateManifest:
    """Delete all managed remote resources and local manager state."""

    manifest = require_manifest(paths)
    mutation = Mutation(
        path=paths.state_file,
        manifest=manifest,
        kind="teardown",
        target=manifest.manager.tunnel_id,
        request={"tunnel_id": manifest.manager.tunnel_id},
    )
    console.section("Teardown")
    if mutation.pending.phase != "cleanup_complete":
        api = CloudflareApi(
            http,
            load_api_token(
                keychain=keychain,
                manifest=mutation.manifest,
                home=paths.home,
                explicit_token=api_token,
            ),
        )
        if mutation.pending.phase != "tunnel_deleted":
            _delete_serving_tunnel(mutation=mutation, api=api, launchd=launchd)
        for publication_name in sorted(mutation.manifest.publications):
            delete_publication_remote(
                api=api,
                keychain=keychain,
                manifest=mutation.manifest,
                publication=mutation.manifest.publications[publication_name],
            )
            publications = dict(mutation.manifest.publications)
            del publications[publication_name]
            mutation.manifest = replace(mutation.manifest, publications=publications)
            mutation.save()
            console.note(f"Removed publication: {publication_name}")
        mutation.save(pending=replace(mutation.pending, phase="cleanup_complete"))
    # This phase can resume without the API credential: every remote resource is gone.
    keychain.delete_secret(account=mutation.manifest.manager.api_token_keychain_account)
    launchd.remove_definition()
    remove_local_manager_artifacts(paths)
    console.note("Manager state removed.")
    # The result must not advertise an unfinished operation after successful retirement.
    return replace(mutation.manifest, pending=None)


def _delete_serving_tunnel(
    *, mutation: Mutation, api: CloudflareApi, launchd: ConnectorService
) -> None:
    """Keep Access intact until the exact tunnel is positively observed deleted."""

    manager = mutation.manifest.manager
    mutation.save(pending=replace(mutation.pending, phase="deleting"))
    if launchd.is_registered():
        launchd.stop()
    launchd.wait_until_stopped()
    if not api.tunnel_is_deleted(account_id=manager.account_id, tunnel_id=manager.tunnel_id):
        clients = api.list_tunnel_connections(
            account_id=manager.account_id,
            tunnel_id=manager.tunnel_id,
        )
        if any(client.connections is None or client.connections for client in clients):
            raise AppError(
                "The shared tunnel still has active or unobserved connector connections.",
                code="teardown_connections_present",
                hints=(
                    "Stop the relevant replicas before resuming teardown; Access is retained.",
                    "Teardown does not forcibly disconnect connectors owned by another machine.",
                ),
            )
        api.delete_tunnel(
            account_id=manager.account_id,
            tunnel_id=manager.tunnel_id,
            missing_ok=True,
        )
        if not api.tunnel_is_deleted(account_id=manager.account_id, tunnel_id=manager.tunnel_id):
            raise AppError(
                "Cloudflare has not confirmed deletion of the exact managed tunnel.",
                code="tunnel_deletion_unobserved",
                hints=("Resume teardown after deletion is observable; Access is retained.",),
            )
    mutation.save(pending=replace(mutation.pending, phase="tunnel_deleted"))
