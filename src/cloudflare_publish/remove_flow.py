"""Publication retirement workflow."""

from __future__ import annotations

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.launchd import Launchd
from cloudflare_publish.local_connector_observation import LocalConnectorObserver
from cloudflare_publish.models import AppPaths, ManagedPublication
from cloudflare_publish.publication_remote import (
    apply_transition_configuration,
    delete_publication_remote,
    require_known_tunnel_configuration,
)
from cloudflare_publish.state import replace_publications
from cloudflare_publish.transitions import Mutation, require_no_pending
from cloudflare_publish.workflow_support import load_api_token, require_manifest


def run_remove(
    *,
    publication_name: str,
    paths: AppPaths,
    keychain: Keychain,
    http: CurlHttpClient,
    launchd: Launchd,
    console: Console,
    api_token: str | None = None,
) -> ManagedPublication:
    """Remove one managed publication."""

    manifest = require_manifest(paths)
    if manifest.pending is not None and (
        manifest.pending.kind,
        manifest.pending.target,
        manifest.pending.request,
    ) != ("remove", publication_name, {"name": publication_name}):
        require_no_pending(manifest)
    publication = manifest.publications.get(publication_name)
    if publication is None:
        raise AppError(f"Unknown publication {publication_name!r}.")
    api = CloudflareApi(
        http,
        load_api_token(
            keychain=keychain,
            manifest=manifest,
            home=paths.home,
            explicit_token=api_token,
        ),
    )
    require_known_tunnel_configuration(api=api, manifest=manifest)
    mutation = Mutation(
        path=paths.state_file,
        manifest=manifest,
        kind="remove",
        target=publication_name,
        request={"name": publication_name},
        candidate=publication,
    )
    apply_transition_configuration(
        api=api,
        mutation=mutation,
        route="withdrawn",
        phase="cleanup",
        local_observer=LocalConnectorObserver(launchd, http),
    )
    delete_publication_remote(
        api=api,
        keychain=keychain,
        manifest=mutation.manifest,
        publication=publication,
    )
    publications = dict(mutation.manifest.publications)
    _ = publications.pop(publication_name, None)
    mutation.manifest = replace_publications(mutation.manifest, publications=publications)
    _ = mutation.finish()
    console.section("Remove")
    console.note(f"Removed publication: {publication_name}")
    return publication
