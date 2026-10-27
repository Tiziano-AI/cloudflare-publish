"""Local and live verification workflows."""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import SplitResult, urlsplit, urlunsplit

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import AccessPolicyRef, tunnel_cname
from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.config_application import require_configuration_applied
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.guard_flow import guard_blocking_publication_names
from cloudflare_publish.http import CurlHttpClient, HttpConnectToEntry
from cloudflare_publish.local_connector_observation import LocalConnectorObserver
from cloudflare_publish.models import (
    CHECK_GROUPS,
    AppPaths,
    CheckGroup,
    CheckResult,
    ManagedPublication,
    ManagerConfig,
    StateManifest,
)
from cloudflare_publish.publication_contract import status_matches_range
from cloudflare_publish.render import build_tunnel_configuration
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.ssh import SshProbe
from cloudflare_publish.transitions import effective_publications
from cloudflare_publish.tunnel_configuration import compare_tunnel_configuration
from cloudflare_publish.verify_support import (
    build_expected_policy_contracts,
    default_port,
    failed_check,
    is_denied_or_access_redirect,
    live_response_detail,
    netloc,
    serialize_policy_contract,
)
from cloudflare_publish.workflow_support import (
    canonical_public_url,
    load_api_token,
    require_manifest,
    select_publications,
)


def run_verify(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    publication_name: str | None,
    live: bool,
    console: Console,
    api_token: str | None = None,
) -> int:
    """Run local checks and optional live public-endpoint checks."""

    checks = collect_verify_checks(
        paths=paths,
        cloudflared=cloudflared,
        launchd=launchd,
        keychain=keychain,
        http=http,
        publication_name=publication_name,
        live=live,
        api_token=api_token,
    )
    console.section("Verify")
    render_verify_checks(console, checks)
    return sum(1 for result in checks if not result.ok)


def render_verify_checks(console: Console, checks: tuple[CheckResult, ...]) -> None:
    """Group checks by the boundary their evidence can establish."""

    for group in CHECK_GROUPS:
        selected = tuple(result for result in checks if result.group == group)
        if not selected:
            continue
        console.section(group.replace("_", " ").title())
        for result in selected:
            console.show_check(result)


def collect_verify_checks(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    publication_name: str | None,
    live: bool,
    api_token: str | None = None,
) -> tuple[CheckResult, ...]:
    """Collect local and optional live checks without rendering."""

    stored_manifest = require_manifest(paths)
    manifest = replace(stored_manifest, publications=effective_publications(stored_manifest))
    pending = manifest.pending
    checks: list[CheckResult] = []
    if pending is not None:
        checks.append(
            CheckResult(
                "manager mutation complete",
                ok=False,
                detail=(
                    f"operation={pending.operation_id} kind={pending.kind} "
                    f"target={pending.target} phase={pending.phase} route={pending.route}; "
                    "resume the same operation shown by cloudflare-publish repair plan"
                ),
            )
        )
    if (
        pending is not None
        and pending.target == publication_name
        and publication_name not in manifest.publications
    ):
        selected_names = ()
    else:
        selected_names = select_publications(manifest, publication_name=publication_name)
    try:
        api = CloudflareApi(
            http,
            load_api_token(
                keychain=keychain,
                manifest=manifest,
                home=paths.home,
                explicit_token=api_token,
            ),
        )
    except AppError as error:
        if pending is None:
            raise
        checks.append(failed_check("Cloudflare credentials available", error))
        return tuple(checks)
    ssh = SshProbe()
    for result in _local_checks(
        paths=paths,
        cloudflared=cloudflared,
        launchd=launchd,
        api=api,
        manifest=manifest,
        selected_names=selected_names,
        http=http,
        ssh=ssh,
    ):
        checks.append(result)
    if live:
        for name in selected_names:
            access_checks = tuple(
                check
                for check in checks
                if check.group == "access" and check.publication_name == name
            )
            for result in _live_checks(
                publication=manifest.publications[name],
                manager=manifest.manager,
                keychain=keychain,
                http=http,
                ssh=ssh,
                cloudflared=cloudflared,
                access_parity_verified=bool(access_checks)
                and all(check.ok for check in access_checks),
            ):
                checks.append(
                    _publication_check(
                        result, publication=manifest.publications[name], group="public_probe"
                    )
                )
    return tuple(checks)


def _local_checks(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    api: CloudflareApi,
    manifest: StateManifest,
    selected_names: tuple[str, ...],
    http: CurlHttpClient,
    ssh: SshProbe,
) -> tuple[CheckResult, ...]:
    """Collect local doctor checks."""

    checks: list[CheckResult] = [
        _cloudflared_support_check(cloudflared),
        CheckResult("state.json exists", ok=paths.state_file.exists()),
        CheckResult("tunnel token file exists", ok=paths.tunnel_token_file.exists()),
        CheckResult(
            (
                "canonical launch agent file exists"
                if paths.host_platform == "darwin"
                else "canonical user service file exists"
            ),
            ok=paths.service_file.exists(),
        ),
        CheckResult(
            (
                "launch agent loaded"
                if paths.host_platform == "darwin"
                else "user service enabled or active"
            ),
            ok=launchd.is_loaded(),
        ),
        _remote_tunnel_check(api=api, manager=manifest.manager),
        _organization_check(api=api, manager=manifest.manager),
        *_tunnel_configuration_checks(
            api=api, manifest=manifest, local_observer=LocalConnectorObserver(launchd, http)
        ),
    ]
    for name in selected_names:
        checks.extend(
            _local_publication_checks(
                api=api,
                manifest=manifest,
                publication=manifest.publications[name],
                http=http,
                ssh=ssh,
            )
        )
    return tuple(checks)


def _cloudflared_support_check(cloudflared: Cloudflared) -> CheckResult:
    """Return the selected executable's connector security-minimum check."""

    try:
        info = cloudflared.require_security_minimum()
    except AppError as error:
        return failed_check("cloudflared meets security minimum", error)
    return CheckResult(
        "cloudflared meets security minimum",
        ok=True,
        detail=info.raw,
    )


def _remote_tunnel_check(*, api: CloudflareApi, manager: ManagerConfig) -> CheckResult:
    """Verify the shared remote tunnel is still reachable."""

    if not manager.tunnel_id:
        return CheckResult(
            "remote tunnel reachable",
            ok=False,
            detail="setup has not observed a tunnel identity; resume its pending operation",
        )
    try:
        tunnel = api.get_tunnel(account_id=manager.account_id, tunnel_id=manager.tunnel_id)
    except AppError as error:
        return failed_check("remote tunnel reachable", error)
    return CheckResult(
        "remote tunnel reachable",
        ok=(
            tunnel.id == manager.tunnel_id
            and tunnel.status in {"healthy", "degraded"}
            and not tunnel.deleted_at
        ),
        detail=f"status={tunnel.status}",
    )


def _organization_check(*, api: CloudflareApi, manager: ManagerConfig) -> CheckResult:
    """Verify the configured Zero Trust organization is still reachable."""

    try:
        organization = api.get_organization(account_id=manager.account_id)
    except AppError as error:
        return failed_check("Zero Trust organization reachable", error)
    return CheckResult(
        "Zero Trust organization reachable",
        ok=organization.auth_domain == manager.auth_domain,
        detail=organization.auth_domain,
    )


def _tunnel_configuration_checks(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    local_observer: LocalConnectorObserver | None = None,
) -> tuple[CheckResult, ...]:
    """Check effective routing and observed application of that exact stored version."""

    config_label = "remote tunnel config matches local state"
    application_label = "active connectors applied stored tunnel configuration"
    if not manifest.manager.tunnel_id:
        detail = "setup has not observed a tunnel identity; no tunnel configuration was queried"
        return (
            CheckResult(config_label, ok=False, detail=detail, group="routing"),
            CheckResult(application_label, ok=False, detail=detail, group="routing"),
        )
    try:
        expected = build_tunnel_configuration(
            effective_publications(manifest), auth_domain=manifest.manager.auth_domain
        )
        snapshot = api.get_tunnel_configuration_snapshot(
            account_id=manifest.manager.account_id,
            tunnel_id=manifest.manager.tunnel_id,
        )
    except AppError as error:
        return (
            replace(failed_check(config_label, error), group="routing"),
            CheckResult(
                application_label,
                ok=False,
                detail="managed tunnel configuration could not be observed",
                group="routing",
            ),
        )
    comparison = compare_tunnel_configuration(actual=snapshot.config, expected=expected)
    configuration_check = CheckResult(
        config_label, ok=comparison.matches, detail=comparison.detail, group="routing"
    )
    if not comparison.matches:
        return (
            configuration_check,
            CheckResult(
                application_label,
                ok=False,
                detail="not checked: stored routing does not match the effective managed routes",
                group="routing",
            ),
        )
    try:
        application = require_configuration_applied(
            api,
            account_id=manifest.manager.account_id,
            tunnel_id=manifest.manager.tunnel_id,
            expected_version=snapshot.version,
            local_observer=local_observer,
        )
    except AppError as error:
        return (
            configuration_check,
            replace(failed_check(application_label, error), group="routing"),
        )
    return (
        configuration_check,
        CheckResult(
            application_label,
            ok=not application.no_active_connectors,
            detail=(
                f"version={application.expected_version} "
                f"active_connectors={len(application.active_connector_ids)}; "
                "native_local_acknowledgments="
                f"{len(application.locally_acknowledged_connector_ids)}; "
                "a connector snapshot does not establish token revocation or session drainage"
            ),
            group="routing",
        ),
    )


def _local_publication_checks(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    publication: ManagedPublication,
    http: CurlHttpClient,
    ssh: SshProbe,
) -> tuple[CheckResult, ...]:
    """Collect local checks for one publication."""

    checks = [
        _publication_check(
            _origin_check(publication=publication, http=http, ssh=ssh),
            publication=publication,
            group="origin",
        ),
        _publication_check(
            _dns_check(api=api, manager=manifest.manager, publication=publication),
            publication=publication,
            group="routing",
        ),
    ]
    if publication.spec.audience == "public":
        checks.append(
            _public_access_absence_check(
                api=api,
                manager=manifest.manager,
                publication=publication,
            )
        )
        checks.append(
            _public_guard_compatibility_check(
                api=api,
                manifest=manifest,
                publication=publication,
            )
        )
    else:
        checks.extend(
            (
                _access_application_check(
                    api=api,
                    manager=manifest.manager,
                    publication=publication,
                ),
                _access_policy_check(
                    api=api,
                    manager=manifest.manager,
                    publication=publication,
                ),
            )
        )
    return tuple(
        result
        if result.publication_name is not None
        else _publication_check(result, publication=publication, group="access")
        for result in checks
    )


def _publication_check(
    result: CheckResult, *, publication: ManagedPublication, group: CheckGroup
) -> CheckResult:
    """Attach stable publication identity without parsing human check labels."""

    return replace(
        result,
        group=group,
        publication_name=publication.spec.name,
        hostname=publication.spec.hostname,
    )


def _origin_check(
    *, publication: ManagedPublication, http: CurlHttpClient, ssh: SshProbe
) -> CheckResult:
    """Verify the origin probe matches the publication verification contract."""

    if publication.spec.kind == "ssh_public":
        return _ssh_origin_check(publication=publication, ssh=ssh)
    try:
        _, expect_status = _http_probe_contract(publication)
        origin_url, headers, connect_to = _origin_probe_request(publication)
        response = http.get(
            origin_url,
            headers=headers,
            follow_redirects=False,
            insecure=publication.spec.origin_options.no_tls_verify,
            connect_to=connect_to,
        )
    except AppError as error:
        return failed_check(f"{publication.spec.name}: origin reachable", error)
    return CheckResult(
        f"{publication.spec.name}: origin reachable",
        ok=status_matches_range(expect_status, response.status_code),
        detail=f"HTTP {response.status_code}",
    )


def _dns_check(
    *,
    api: CloudflareApi,
    manager: ManagerConfig,
    publication: ManagedPublication,
) -> CheckResult:
    """Verify the managed DNS record still targets the shared tunnel canonically."""

    try:
        records = api.list_dns_records(zone_id=manager.zone_id, name=publication.spec.hostname)
    except AppError as error:
        return failed_check(f"{publication.spec.name}: DNS record matches state", error)
    expected_target = tunnel_cname(manager.tunnel_id)
    for record in records:
        if record.id != publication.state.dns_record_id:
            continue
        return CheckResult(
            f"{publication.spec.name}: DNS record matches state",
            ok=record.content == expected_target and record.proxied,
            detail=f"{record.content} proxied={record.proxied}",
        )
    return CheckResult(
        f"{publication.spec.name}: DNS record matches state",
        ok=False,
        detail="managed DNS record ID is missing",
    )


def _access_application_check(
    *,
    api: CloudflareApi,
    manager: ManagerConfig,
    publication: ManagedPublication,
) -> CheckResult:
    """Verify the managed Access application still matches the publication hostname."""

    application_id = publication.state.access_application_id
    access_aud = publication.state.access_aud
    if application_id is None or access_aud is None:
        return CheckResult(
            f"{publication.spec.name}: Access app matches state",
            ok=False,
            detail="protected publication state is missing Access application metadata",
        )
    try:
        app = api.get_access_application(
            account_id=manager.account_id,
            application_id=application_id,
        )
    except AppError as error:
        return failed_check(f"{publication.spec.name}: Access app matches state", error)
    return CheckResult(
        f"{publication.spec.name}: Access app matches state",
        ok=(
            app.id == application_id
            and app.aud == access_aud
            and app.domain == publication.spec.hostname
            and (publication.spec.kind != "ssh_public" or app.service_auth_401_redirect is True)
        ),
        detail=(
            f"domain={app.domain} aud={app.aud}"
            + (
                f" service_auth_401_redirect={app.service_auth_401_redirect}"
                if publication.spec.kind == "ssh_public"
                else ""
            )
        ),
    )


def _access_policy_check(
    *,
    api: CloudflareApi,
    manager: ManagerConfig,
    publication: ManagedPublication,
) -> CheckResult:
    """Verify the managed Access policies still match state and publication semantics."""

    application_id = publication.state.access_application_id
    if application_id is None:
        return CheckResult(
            f"{publication.spec.name}: Access policies match state",
            ok=False,
            detail="protected publication state is missing an Access application ID",
        )
    try:
        policies = api.list_access_policies(
            account_id=manager.account_id,
            application_id=application_id,
        )
    except AppError as error:
        return failed_check(f"{publication.spec.name}: Access policies match state", error)
    actual_ids = tuple(sorted(policy.id for policy in policies))
    actual_contract = tuple(sorted(_policy_contract_signature(policy) for policy in policies))
    additional_constraints = any(policy.has_additional_constraints for policy in policies)
    expected_ids = tuple(sorted(publication.state.policy_ids))
    try:
        expected_contract = tuple(sorted(build_expected_policy_contracts(publication)))
    except AppError as error:
        return failed_check(f"{publication.spec.name}: Access policies match state", error)
    return CheckResult(
        f"{publication.spec.name}: Access policies match state",
        ok=(
            actual_ids == expected_ids
            and actual_contract == expected_contract
            and not additional_constraints
        ),
        detail=(
            f"ids={actual_ids} contracts={actual_contract} "
            f"additional_constraints={additional_constraints}"
        ),
    )


def _public_access_absence_check(
    *,
    api: CloudflareApi,
    manager: ManagerConfig,
    publication: ManagedPublication,
) -> CheckResult:
    """Verify a public publication has no Access application or auth metadata."""

    if (
        publication.state.access_application_id is not None
        or publication.state.access_aud is not None
        or publication.state.policy_ids
        or publication.state.service_token_id is not None
        or publication.state.service_token_client_id is not None
        or publication.state.service_token_keychain_account is not None
    ):
        return CheckResult(
            f"{publication.spec.name}: public Access boundary is absent",
            ok=False,
            detail="public publication state retains Access metadata",
        )
    try:
        matching = tuple(
            application
            for application in api.list_access_applications(account_id=manager.account_id)
            if application.domain == publication.spec.hostname
        )
    except AppError as error:
        return failed_check(f"{publication.spec.name}: public Access boundary is absent", error)
    return CheckResult(
        f"{publication.spec.name}: public Access boundary is absent",
        ok=not matching,
        detail="no matching Access application" if not matching else "matching Access app exists",
    )


def _public_guard_compatibility_check(
    *,
    api: CloudflareApi,
    manifest: StateManifest,
    publication: ManagedPublication,
) -> CheckResult:
    """Verify account require-protection does not block one managed public hostname."""

    try:
        organization = api.get_organization(account_id=manifest.manager.account_id)
    except AppError as error:
        return failed_check(f"{publication.spec.name}: public guard is compatible", error)
    blocking = (
        guard_blocking_publication_names(manifest=manifest, organization=organization)
        if organization.deny_unmatched_requests
        else ()
    )
    return CheckResult(
        f"{publication.spec.name}: public guard is compatible",
        ok=publication.spec.name not in blocking,
        detail=(
            "configured zone is reachable without Access"
            if publication.spec.name not in blocking
            else "account require-protection blocks this public publication"
        ),
    )


def _live_checks(
    *,
    publication: ManagedPublication,
    manager: ManagerConfig,
    keychain: SecretStore,
    http: CurlHttpClient,
    ssh: SshProbe,
    cloudflared: Cloudflared,
    access_parity_verified: bool,
) -> tuple[CheckResult, ...]:
    """Collect live public-endpoint checks for one publication."""

    if publication.spec.audience == "public":
        return (_public_live_check(publication=publication, http=http),)
    anonymous = _anonymous_live_check(publication=publication, manager=manager, http=http)
    checks: list[CheckResult] = [anonymous]
    if publication.spec.kind == "ssh_public":
        checks.append(
            _ssh_live_check(
                publication=publication,
                keychain=keychain,
                cloudflared=cloudflared,
                ssh=ssh,
                access_verified=access_parity_verified and anonymous.ok,
            )
        )
        return tuple(checks)
    if publication.spec.audience in {"machine", "mixed"}:
        verify_path, _ = _http_probe_contract(publication)
        checks.append(
            _authenticated_live_check(
                publication=publication,
                keychain=keychain,
                http=http,
                target_url=canonical_public_url(
                    publication.spec.hostname,
                    verify_path,
                ),
            )
        )
    return tuple(checks)


def _public_live_check(
    *,
    publication: ManagedPublication,
    http: CurlHttpClient,
) -> CheckResult:
    """Verify anonymous traffic reaches the public origin contract."""

    try:
        verify_path, expect_status = _http_probe_contract(publication)
        target_url = canonical_public_url(publication.spec.hostname, verify_path)
        response = http.get(target_url, follow_redirects=False)
    except AppError as error:
        return failed_check(f"{publication.spec.name}: public request reaches origin", error)
    return CheckResult(
        f"{publication.spec.name}: public request reaches origin",
        ok=status_matches_range(expect_status, response.status_code),
        detail=live_response_detail(response),
    )


def _anonymous_live_check(
    *,
    publication: ManagedPublication,
    manager: ManagerConfig,
    http: CurlHttpClient,
) -> CheckResult:
    """Verify anonymous traffic is denied or redirected to the Access auth domain."""

    verify_path = (
        "/" if publication.spec.kind == "ssh_public" else _http_probe_contract(publication)[0]
    )
    target_url = canonical_public_url(publication.spec.hostname, verify_path)
    try:
        response = http.get(target_url, follow_redirects=False)
    except AppError as error:
        return failed_check(f"{publication.spec.name}: anonymous request denied", error)
    return CheckResult(
        f"{publication.spec.name}: anonymous request denied",
        ok=(
            response.status_code in {401, 403}
            if publication.spec.kind == "ssh_public"
            else is_denied_or_access_redirect(response=response, auth_domain=manager.auth_domain)
        ),
        detail=live_response_detail(response),
    )


def _authenticated_live_check(
    *,
    publication: ManagedPublication,
    keychain: SecretStore,
    http: CurlHttpClient,
    target_url: str,
) -> CheckResult:
    """Verify a machine-authenticated request still reaches the origin."""

    secret_account = publication.state.service_token_keychain_account
    client_id = publication.state.service_token_client_id
    if secret_account is None or client_id is None:
        return CheckResult(
            f"{publication.spec.name}: authenticated request succeeds",
            ok=False,
            detail="state is missing service-token metadata",
        )
    try:
        client_secret = keychain.load_secret(account=secret_account)
    except AppError as error:
        return CheckResult(
            f"{publication.spec.name}: authenticated request succeeds",
            ok=False,
            detail=(
                f"{error.message} Run `cloudflare-publish token rotate "
                f"{publication.spec.name} --yes` "
                "to issue a new client secret."
            ),
        )
    try:
        _, expect_status = _http_probe_contract(publication)
        response = http.get(
            target_url,
            headers={
                "CF-Access-Client-Id": client_id,
                "CF-Access-Client-Secret": client_secret,
            },
            follow_redirects=False,
        )
    except AppError as error:
        return failed_check(f"{publication.spec.name}: authenticated request succeeds", error)
    return CheckResult(
        f"{publication.spec.name}: authenticated request succeeds",
        ok=status_matches_range(expect_status, response.status_code),
        detail=_authenticated_live_detail(
            publication=publication,
            status_code=response.status_code,
        ),
    )


def _origin_probe_request(
    publication: ManagedPublication,
) -> tuple[str, dict[str, str], tuple[HttpConnectToEntry, ...]]:
    """Build the origin probe request URL, headers, and connect-to mapping."""

    origin = urlsplit(publication.spec.origin_url)
    verify_path, _ = _http_probe_contract(publication)
    origin_host = origin.hostname
    if origin_host is None:
        raise AppError("Origin URL is missing a hostname.")
    port = origin.port if origin.port is not None else default_port(origin.scheme)
    request_host = publication.spec.origin_options.origin_server_name or origin_host
    include_port = origin.port is not None or request_host != origin_host
    request_url = urlunsplit(
        SplitResult(
            scheme=origin.scheme,
            netloc=netloc(request_host, port if include_port else None),
            path=verify_path,
            query="",
            fragment="",
        )
    )
    headers: dict[str, str] = {}
    if publication.spec.origin_options.http_host_header is not None:
        headers["Host"] = publication.spec.origin_options.http_host_header
    if request_host == origin_host:
        return request_url, headers, ()
    return (
        request_url,
        headers,
        (
            HttpConnectToEntry(
                request_host=request_host,
                request_port=port,
                connect_host=origin_host,
                connect_port=port,
            ),
        ),
    )


def _policy_contract_signature(policy: AccessPolicyRef) -> str:
    """Serialize one remote Access policy into the canonical comparison signature."""

    return serialize_policy_contract(
        precedence=policy.precedence,
        decision=policy.decision,
        include=policy.include,
    )


def _authenticated_live_detail(*, publication: ManagedPublication, status_code: int) -> str:
    """Render machine-authenticated live proof with Host-header guidance on origin denial."""

    detail = f"HTTP {status_code}"
    _, expect_status = _http_probe_contract(publication)
    if status_matches_range(expect_status, status_code):
        return detail
    if publication.spec.origin_options.http_host_header is not None:
        return detail
    return (
        detail
        + "; the tunnel forwards the public Host header by default. "
        + "Set --http-host-header when the origin rejects the public hostname."
    )


def _http_probe_contract(publication: ManagedPublication) -> tuple[str, str]:
    """Require HTTP-specific verification fields before constructing an HTTP probe."""

    path = publication.spec.verify_path
    status = publication.spec.expect_status
    if publication.spec.kind != "http_public" or path is None or status is None:
        raise AppError("HTTP verification requires an HTTP publication verification profile.")
    return path, status


def _ssh_origin_check(*, publication: ManagedPublication, ssh: SshProbe) -> CheckResult:
    """Verify signed SSH key exchange directly against the trusted origin host key."""

    label = f"{publication.spec.name}: SSH origin host key verified"
    origin = urlsplit(publication.spec.origin_url)
    if origin.hostname is None or publication.spec.ssh_host_key is None:
        return CheckResult(label, ok=False, detail="SSH origin or pinned host key is missing")
    try:
        result = ssh.probe(
            origin.hostname,
            origin.port or 22,
            publication.spec.ssh_host_key,
            publication.spec.hostname,
        )
    except AppError as error:
        return failed_check(label, error)
    return CheckResult(label, ok=result.ok, detail=result.detail)


def _ssh_live_check(
    *,
    publication: ManagedPublication,
    keychain: SecretStore,
    cloudflared: Cloudflared,
    ssh: SshProbe,
    access_verified: bool,
) -> CheckResult:
    """Verify SSH identity through Access without user login, prompts, or forwarding."""

    label = f"{publication.spec.name}: public SSH host key verified"
    if not access_verified:
        return CheckResult(
            label,
            ok=False,
            detail=(
                "SSH probe not started: Access app, service policy, and 401/403 denial must match"
            ),
        )
    secret_account = publication.state.service_token_keychain_account
    client_id = publication.state.service_token_client_id
    host_key = publication.spec.ssh_host_key
    if secret_account is None or client_id is None or host_key is None:
        return CheckResult(label, ok=False, detail="SSH pin or service-token metadata is missing")
    binary = cloudflared.binary()
    if binary is None:
        return CheckResult(label, ok=False, detail="cloudflared is not installed")
    try:
        secret = keychain.load_secret(account=secret_account)
        result = ssh.probe(
            publication.spec.hostname,
            22,
            host_key,
            publication.spec.hostname,
            cloudflared_binary=str(binary),
            service_token_client_id=client_id,
            service_token_client_secret=secret,
        )
    except AppError as error:
        return failed_check(label, error)
    return CheckResult(label, ok=result.ok, detail=result.detail)
