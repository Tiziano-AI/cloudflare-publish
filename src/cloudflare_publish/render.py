"""Rendering helpers for launchd and remotely managed tunnel config."""

from __future__ import annotations

import re
from xml.sax.saxutils import escape

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonArray, JsonObject
from cloudflare_publish.models import CANONICAL_LABEL, AppPaths, ManagedPublication
from cloudflare_publish.tunnel_configuration import (
    compare_tunnel_configuration as compare_tunnel_configuration,
)
from cloudflare_publish.tunnel_configuration import (
    normalize_tunnel_configuration as normalize_tunnel_configuration,
)
from cloudflare_publish.tunnel_configuration import (
    parse_tunnel_configuration,
)
from cloudflare_publish.tunnel_configuration import (
    tunnel_configuration_matches as tunnel_configuration_matches,
)


def render_launch_agent_plist(paths: AppPaths, cloudflared_binary: str) -> str:
    """Render the canonical launchd plist."""

    binary = escape(cloudflared_binary)
    tunnel_token = escape(str(paths.tunnel_token_file))
    stdout_log = escape(str(paths.stdout_log_file))
    stderr_log = escape(str(paths.stderr_log_file))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        "<dict>\n"
        "  <key>Label</key>\n"
        f"  <string>{CANONICAL_LABEL}</string>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array>\n"
        f"    <string>{binary}</string>\n"
        "    <string>tunnel</string>\n"
        "    <string>run</string>\n"
        "    <string>--token-file</string>\n"
        f"    <string>{tunnel_token}</string>\n"
        "  </array>\n"
        "  <key>RunAtLoad</key>\n"
        "  <true/>\n"
        "  <key>KeepAlive</key>\n"
        "  <dict>\n"
        "    <key>SuccessfulExit</key>\n"
        "    <false/>\n"
        "  </dict>\n"
        "  <key>ThrottleInterval</key>\n"
        "  <integer>5</integer>\n"
        "  <key>StandardOutPath</key>\n"
        f"  <string>{stdout_log}</string>\n"
        "  <key>StandardErrorPath</key>\n"
        f"  <string>{stderr_log}</string>\n"
        "</dict>\n"
        "</plist>\n"
    )


def build_tunnel_configuration(
    publications: dict[str, ManagedPublication], *, auth_domain: str | None = None
) -> JsonObject:
    """Build the canonical remote tunnel configuration body."""

    ordered = sorted(publications.values(), key=lambda item: item.spec.hostname)
    ingress: JsonArray = []
    for publication in ordered:
        origin_request: JsonObject = {}
        if publication.spec.kind == "http_public":
            options = publication.spec.origin_options
            if options.http_host_header is not None:
                origin_request["httpHostHeader"] = options.http_host_header
            if options.origin_server_name is not None:
                origin_request["originServerName"] = options.origin_server_name
            if options.no_tls_verify:
                origin_request["noTLSVerify"] = True
        if publication.spec.audience != "public":
            if not publication.state.access_application_id or not publication.state.access_aud:
                raise AppError(
                    "A protected tunnel route requires its owned Access application and audience.",
                    code="access_guard_missing",
                )
            team = _access_team(auth_domain)
            origin_request["access"] = {
                "required": True,
                "teamName": team,
                "audTag": [publication.state.access_aud],
            }
        rule: JsonObject = {
            "hostname": publication.spec.hostname,
            "service": publication.spec.origin_url,
        }
        if origin_request:
            rule["originRequest"] = origin_request
        ingress.append(rule)
    ingress.append({"service": "http_status:404"})
    configuration: JsonObject = {"ingress": ingress}
    _ = parse_tunnel_configuration(configuration)
    return {"config": configuration}


def _access_team(auth_domain: str | None) -> str:
    """Derive the native connector team slug from the owned Access organization."""

    if auth_domain is None:
        raise AppError(
            "Protected tunnel routes require the manager's Access authentication domain.",
            code="access_guard_missing",
        )
    match = re.fullmatch(
        r"([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.cloudflareaccess\.com", auth_domain
    )
    if match is None:
        raise AppError(
            "The Access authentication domain must be TEAM.cloudflareaccess.com.",
            code="access_guard_invalid",
        )
    return match.group(1)
