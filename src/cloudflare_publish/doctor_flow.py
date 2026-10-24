"""Non-mutating CLI diagnostics."""

from __future__ import annotations

import shutil

from cloudflare_publish.cli_auth import resolve_api_token
from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.models import AppPaths, CheckResult
from cloudflare_publish.secret_store import SecretStore


def run_doctor(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    explicit_token: str | None,
) -> tuple[bool, str, tuple[CheckResult, ...]]:
    """Collect non-mutating install, auth, local-state, and reachability diagnostics."""

    checks: list[CheckResult] = [
        CheckResult("platform is supported", ok=True, detail=paths.host_platform),
        _native_service_preflight(launchd),
        _which_check("uv"),
        _which_check("cloudflare-publish"),
        _repo_wrapper_check(paths),
        _cloudflared_check(cloudflared),
        CheckResult(
            "state.json exists",
            ok=paths.state_file.exists(),
            detail=str(paths.state_file),
        ),
        CheckResult(
            "tunnel token file exists",
            ok=paths.tunnel_token_file.exists(),
            detail=str(paths.tunnel_token_file),
        ),
        CheckResult(
            "launch agent file exists"
            if paths.host_platform == "darwin"
            else "user unit file exists",
            ok=paths.service_file.exists(),
            detail=str(paths.service_file),
        ),
        _native_service_loaded(launchd),
    ]
    token_resolution = resolve_api_token(
        explicit_token=explicit_token,
        keychain=keychain,
        paths=paths,
    )
    checks.append(
        CheckResult(
            "api token available",
            ok=token_resolution.available,
            detail=token_resolution.source,
        )
    )
    if token_resolution.token is not None:
        checks.append(_cloudflare_reachability_check(http=http, api_token=token_resolution.token))
    ready = all(result.ok for result in checks)
    return ready, token_resolution.source, tuple(checks)


def _native_service_preflight(service: ConnectorService) -> CheckResult:
    """Diagnose native prerequisites without performing service effects."""

    try:
        service.preflight()
    except AppError as error:
        return CheckResult("native user service prerequisites", ok=False, detail=error.message)
    return CheckResult("native user service prerequisites", ok=True)


def _native_service_loaded(service: ConnectorService) -> CheckResult:
    """Keep an unavailable or foreign native service an explicit failed check."""

    label = "launch agent loaded" if service.platform == "darwin" else "user unit enabled or active"
    try:
        return CheckResult(label, ok=service.is_loaded())
    except AppError as error:
        return CheckResult(label, ok=False, detail=error.message)


def _which_check(command: str) -> CheckResult:
    """Return whether one command is available on PATH."""

    path = shutil.which(command)
    return CheckResult(f"{command} on PATH", ok=path is not None, detail=path)


def _repo_wrapper_check(paths: AppPaths) -> CheckResult:
    """Return repo wrapper state when the invocation appears to run from the checkout."""

    wrapper = paths.repo_root / "bin" / "cloudflare-publish"
    package_root = paths.repo_root / "src" / "cloudflare_publish"
    if package_root.exists():
        return CheckResult(
            "repo development wrapper exists",
            ok=wrapper.exists(),
            detail=str(wrapper),
        )
    return CheckResult(
        "repo development wrapper optional",
        ok=True,
        detail="not running from source checkout",
    )


def _cloudflared_check(cloudflared: Cloudflared) -> CheckResult:
    """Return whether cloudflared supports the product token-file contract."""

    try:
        version = cloudflared.require_token_file_support()
    except AppError as error:
        return CheckResult("cloudflared supports --token-file", ok=False, detail=error.message)
    return CheckResult("cloudflared supports --token-file", ok=True, detail=version.raw)


def _cloudflare_reachability_check(*, http: CurlHttpClient, api_token: str) -> CheckResult:
    """Return whether the API token can reach account discovery."""

    try:
        accounts = CloudflareApi(http, api_token).list_accounts()
    except AppError as error:
        return CheckResult("Cloudflare account API reachable", ok=False, detail=error.message)
    return CheckResult(
        "Cloudflare account API reachable",
        ok=True,
        detail=f"{len(accounts)} visible account(s)",
    )
