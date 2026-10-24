"""Publication create-or-update workflow."""

from __future__ import annotations

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.local_connector_observation import LocalConnectorObserver
from cloudflare_publish.models import AppPaths, ManagedPublication, PublishRequest
from cloudflare_publish.publication_contract import (
    build_publication_spec,
    ensure_hostname_within_zone,
)
from cloudflare_publish.publication_remote import (
    preflight_publication_credentials,
    publication_candidate,
    publication_request,
    require_known_tunnel_configuration,
    sync_publication,
    validate_publication_remote_slot,
)
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.state import replace_publications
from cloudflare_publish.transitions import Mutation, require_no_pending
from cloudflare_publish.workflow_support import load_api_token, require_manifest


def run_publish(
    *,
    request: PublishRequest,
    paths: AppPaths,
    keychain: SecretStore,
    http: CurlHttpClient,
    launchd: ConnectorService,
    console: Console,
    api_token: str | None = None,
) -> ManagedPublication:
    """Create or update one publication."""

    manifest = require_manifest(paths)
    spec = build_publication_spec(request)
    ensure_hostname_within_zone(hostname=spec.hostname, zone_name=manifest.manager.zone_name)
    normalized_request = publication_request(spec)
    if manifest.pending is not None and (
        manifest.pending.kind,
        manifest.pending.target,
        manifest.pending.request,
    ) != ("publish", spec.name, normalized_request):
        require_no_pending(manifest)
    api = CloudflareApi(
        http,
        load_api_token(
            keychain=keychain,
            manifest=manifest,
            home=paths.home,
            explicit_token=api_token,
        ),
    )
    # Precondition reads do not strand a new pending record for a rejected
    # request. Existing custody is never replaced, even if its POST was lost.
    if manifest.pending is not None and manifest.pending.effect is not None:
        raise AppError(
            f"Operation {manifest.pending.operation_id} has an unknown provider result.",
            code="outcome_unknown",
            hints=("Resolve its exact resource with repair resolve before resuming.",),
        )
    require_known_tunnel_configuration(api=api, manifest=manifest)
    validate_publication_remote_slot(api=api, manifest=manifest, spec=spec)
    candidate = publication_candidate(spec, manifest.publications.get(spec.name))
    if manifest.pending is None:
        preflight_publication_credentials(keychain=keychain, manifest=manifest, candidate=candidate)
    mutation = Mutation(
        path=paths.state_file,
        manifest=manifest,
        kind="publish",
        target=spec.name,
        request=normalized_request,
        candidate=candidate,
    )
    managed_publication = sync_publication(
        api=api,
        keychain=keychain,
        mutation=mutation,
        local_observer=LocalConnectorObserver(launchd, http),
    )
    publications = dict(mutation.manifest.publications)
    publications[spec.name] = managed_publication
    mutation.manifest = replace_publications(mutation.manifest, publications=publications)
    _ = mutation.finish()
    console.section("Publish")
    console.note(f"Publication: {spec.name}")
    console.note(f"Hostname: {spec.hostname}")
    console.note(f"Origin: {spec.origin_url}")
    console.note(f"Audience: {spec.audience}")
    if (
        managed_publication.state.service_token_keychain_account is not None
        and managed_publication.state.service_token_client_id is not None
    ):
        console.note(
            f"Service token client ID: {managed_publication.state.service_token_client_id}"
        )
        try:
            client_secret = keychain.load_secret(
                account=managed_publication.state.service_token_keychain_account
            )
        except AppError:
            raise AppError(
                "The publication change completed, but its service-token secret is unavailable "
                + "for credential handoff.",
                code="credential_handoff_unavailable",
                data={"publication_applied": True, "publication_name": spec.name},
                hints=(
                    f"Run cloudflare-publish token rotate {spec.name} --yes "
                    + "to explicitly issue and store a replacement secret.",
                ),
            ) from None
        console.note("Service token client secret: " + client_secret)
    return managed_publication
