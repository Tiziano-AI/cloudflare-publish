"""Shared tunnel recovery workflow."""

from __future__ import annotations

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import TunnelRef
from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.console import Console
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.models import AppPaths
from cloudflare_publish.secret_store import SecretStore
from cloudflare_publish.workflow_support import (
    ensure_platform_tools,
    install_connector_service,
    load_api_token,
    require_manifest,
    write_tunnel_token,
)


def run_tunnel_recover(
    *,
    paths: AppPaths,
    cloudflared: Cloudflared,
    launchd: ConnectorService,
    keychain: SecretStore,
    http: CurlHttpClient,
    console: Console,
    api_token: str | None = None,
) -> TunnelRef:
    """Recover the local connector after dashboard token rotation or tunnel incidents."""

    manifest = require_manifest(paths)
    ensure_platform_tools(
        cloudflared=cloudflared,
        launchd=launchd,
        keychain=keychain,
        install_deps=False,
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
    tunnel = api.get_tunnel(
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
    )
    tunnel_token = api.get_tunnel_token(
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
    )
    write_tunnel_token(paths, tunnel_token)
    install_connector_service(cloudflared=cloudflared, launchd=launchd)
    api.cleanup_tunnel_connections(
        account_id=manifest.manager.account_id,
        tunnel_id=manifest.manager.tunnel_id,
    )
    console.section("Tunnel Recover")
    console.note(f"Tunnel: {tunnel.name} ({tunnel.id})")
    if tunnel.status is not None:
        console.note(f"Prior status: {tunnel.status}")
    console.note("Rewrote the local tunnel token and restarted the managed connector.")
    console.note("Disconnected every connector on the shared tunnel.")
    return tunnel
