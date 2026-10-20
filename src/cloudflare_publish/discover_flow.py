"""Bounded, allowlisted remote hostname topology discovery; never adoption."""

from __future__ import annotations

import fnmatch
import json
import re
from urllib.parse import urlsplit, urlunsplit

from cloudflare_publish.cli_output import redact_text, tunnel_to_object, zone_to_object
from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import AccessDiscoveryRef, tunnel_cname
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonArray, JsonObject, JsonValue

_HOST = re.compile(r"[A-Za-z0-9*_.-]+\Z")
_ORIGIN_OPTIONS = {"httpHostHeader", "originServerName", "noTLSVerify"}
_POLICY_RULE_KINDS = {
    "email",
    "email_domain",
    "service_token",
    "everyone",
    "group",
    "ip",
    "geo",
    "certificate",
    "login_method",
    "device_posture",
    "auth_method",
    "common_name",
    "any_valid_service_token",
    "external_evaluation",
    "github-organization",
    "gsuite",
    "okta",
    "saml",
    "azureAD",
    "auth_context",
    "rule_group",
}


def discover_tunnel(
    *, api: CloudflareApi, account_id: str, zone_id: str, tunnel_id: str
) -> JsonObject:
    """Read one explicit tunnel and related resources in one selected zone."""

    zones = tuple(zone for zone in api.list_zones() if zone.id == zone_id)
    if len(zones) != 1 or zones[0].account_id != account_id:
        raise AppError(
            "The selected zone is not visible in the selected account.",
            code="discovery_scope_mismatch",
        )
    zone = zones[0]
    tunnel = api.get_tunnel(account_id=account_id, tunnel_id=tunnel_id)
    unsupported: JsonArray = []
    if tunnel.deleted_at:
        _issue(unsupported, "deleted_tunnel", "tunnel")
        ingress: JsonArray = []
    else:
        if not tunnel.remote_config:
            _issue(unsupported, "locally_managed_tunnel", "tunnel")
            configuration: JsonObject = {}
        else:
            configuration = api.get_tunnel_configuration(account_id=account_id, tunnel_id=tunnel_id)
        ingress = _ingress_summary(configuration, unsupported)
    if zone.zone_type != "full" or zone.status != "active":
        _issue(unsupported, "zone_not_active_full", "zone")
    hostnames: set[str] = set()
    for rule in ingress:
        if isinstance(rule, dict):
            hostname = rule.get("hostname")
            if isinstance(hostname, str):
                hostnames.add(hostname)
                if hostname != zone.name and not hostname.endswith(f".{zone.name}"):
                    _issue(
                        unsupported,
                        "hostname_outside_selected_zone",
                        f"ingress:{rule.get('index')}",
                    )
    dns: JsonArray = []
    for record in api.list_dns_records(zone_id=zone_id):
        if record.content.rstrip(".") != tunnel_cname(tunnel_id) and record.name not in hostnames:
            continue
        dns.append(
            {
                "id": record.id,
                "name": record.name,
                "type": record.record_type,
                "target": record.content if record.record_type == "CNAME" else None,
                "proxied": record.proxied,
            }
        )
        if record.record_type != "CNAME":
            _issue(unsupported, "non_cname_dns", f"dns:{record.id}")
        hostnames.add(record.name)
        if "*" in record.name:
            _issue(unsupported, "wildcard_dns", f"dns:{record.id}")
    access = _access_summary(api, account_id, hostnames, unsupported)
    return {
        "account_id": account_id,
        "zone": zone_to_object(zone),
        "tunnel": tunnel_to_object(tunnel),
        "ingress": ingress,
        "dns": dns,
        "access": access,
        "unsupported_topology": unsupported,
        "coverage": (
            (
                "Deleted-tunnel tombstone; obsolete ingress configuration was not queried. "
                if tunnel.deleted_at
                else ""
            )
            + "Selected-zone HTTP(S)/SSH hostname metadata only; no private-network route "
            + "enumeration, connector inventory, Access override or require/exclude semantics, "
            + "authentication execution, or application-workflow proof."
        ),
    }


def render_tunnel_discovery(console: Console, payload: JsonObject) -> None:
    """Expose the same bounded metadata in the human renderer."""

    console.section("Tunnel Discovery")
    for field in (
        "account_id",
        "zone",
        "tunnel",
        "ingress",
        "dns",
        "access",
        "unsupported_topology",
        "coverage",
    ):
        console.note(f"{field}: {json.dumps(payload[field], sort_keys=True)}")


def _ingress_summary(configuration: JsonObject, unsupported: JsonArray) -> JsonArray:
    """Allowlist routing structure and redact embedded origin credentials."""

    if set(configuration) - {"ingress", "warp-routing", "originRequest"}:
        _issue(unsupported, "unreported_configuration_fields", "configuration")
    warp = configuration.get("warp-routing")
    if isinstance(warp, dict) and warp.get("enabled") is True:
        _issue(unsupported, "private_network_enabled", "configuration")
    if configuration.get("originRequest"):
        _issue(unsupported, "global_origin_options", "configuration")
    rules = configuration.get("ingress")
    if not isinstance(rules, list):
        _issue(unsupported, "missing_ingress", "configuration")
        return []
    summaries: JsonArray = []
    for index, rule in enumerate(rules):
        scope = f"ingress:{index}"
        if not isinstance(rule, dict):
            _issue(unsupported, "invalid_ingress", scope)
            continue
        hostname_value = rule.get("hostname")
        hostname = (
            hostname_value
            if isinstance(hostname_value, str) and _HOST.fullmatch(hostname_value)
            else None
        )
        if hostname_value is not None and hostname is None:
            _issue(unsupported, "invalid_hostname", scope)
        if hostname is not None and "*" in hostname:
            _issue(unsupported, "wildcard_hostname", scope)
        has_path = bool(rule.get("path"))
        if has_path:
            _issue(unsupported, "path_routing", scope)
        service = _service_summary(rule.get("service"), scope, unsupported)
        if hostname is not None and service is not None and service.startswith("http_status:"):
            _issue(unsupported, "non_http_publication_service", scope)
        options = rule.get("originRequest")
        option_summary: JsonObject = {}
        if isinstance(options, dict):
            for name in _ORIGIN_OPTIONS:
                value = options.get(name)
                if isinstance(value, str | bool):
                    if service is not None and service.startswith("ssh://"):
                        _issue(unsupported, "http_origin_options_on_ssh", scope)
                        break
                    option_summary[name] = redact_text(value) if isinstance(value, str) else value
            if set(options) - _ORIGIN_OPTIONS:
                _issue(unsupported, "unreported_origin_options", scope)
        if set(rule) - {"hostname", "service", "path", "originRequest"}:
            _issue(unsupported, "unreported_ingress_fields", scope)
        if hostname is None and (index != len(rules) - 1 or service != "http_status:404"):
            _issue(unsupported, "noncanonical_catch_all", scope)
        summaries.append(
            {
                "index": index,
                "hostname": hostname,
                "has_path": has_path,
                "service": service,
                "origin_options": option_summary,
            }
        )
    return summaries


def _service_summary(value: JsonValue | None, scope: str, unsupported: JsonArray) -> str | None:
    """Never copy userinfo, query strings, fragments or unsupported service strings."""

    if not isinstance(value, str):
        _issue(unsupported, "invalid_service", scope)
        return None
    if re.fullmatch(r"http_status:[1-5][0-9][0-9]", value):
        return value
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "ssh"} or parsed.hostname is None:
            _issue(unsupported, "unsupported_service", scope)
            return None
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        netloc = host if parsed.port is None else f"{host}:{parsed.port}"
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            _issue(unsupported, "noncanonical_origin_url", scope)
        return urlunsplit((parsed.scheme, netloc, "", "", ""))
    except ValueError:
        _issue(unsupported, "invalid_service", scope)
        return None


def _access_summary(
    api: CloudflareApi, account_id: str, hostnames: set[str], unsupported: JsonArray
) -> JsonArray:
    """Report matching app identity and rule kinds, not policy values or secrets."""

    summaries: JsonArray = []
    for app in api.list_access_discovery(account_id=account_id):
        domains = _matching_domains(app, hostnames)
        if not domains:
            continue
        scope = f"access:{app.id}"
        if len(app.domains) > 1 or app.has_private_destinations:
            _issue(unsupported, "multi_destination_access", scope)
        if app.has_destination_overrides:
            _issue(unsupported, "access_destination_overrides", scope)
        if any("*" in domain or "/" in domain for domain in domains):
            _issue(unsupported, "wildcard_or_path_access", scope)
        policies: JsonArray = []
        for policy in api.list_access_policies(account_id=account_id, application_id=app.id):
            if policy.has_additional_constraints:
                _issue(unsupported, "unreported_policy_constraints", f"policy:{policy.id}")
            kinds: set[str] = set()
            for encoded in policy.include:
                decoded: object = json.loads(encoded)
                if isinstance(decoded, dict):
                    kinds.update(key for key in decoded if key in _POLICY_RULE_KINDS)
                    if set(decoded) - _POLICY_RULE_KINDS:
                        _issue(unsupported, "unreported_policy_rule_kinds", f"policy:{policy.id}")
            policy_summary: JsonObject = {
                "id": policy.id,
                "name": redact_text(policy.name),
                "decision": policy.decision,
                "precedence": policy.precedence,
                "include_rule_kinds": [kind for kind in sorted(kinds)],
                "has_additional_constraints": policy.has_additional_constraints,
            }
            policies.append(policy_summary)
        app_summary: JsonObject = {
            "id": app.id,
            "name": redact_text(app.name),
            "type": app.application_type,
            "domains": [domain for domain in domains],
            "has_destination_overrides": app.has_destination_overrides,
            "policies": policies,
        }
        summaries.append(app_summary)
    return summaries


def _matching_domains(app: AccessDiscoveryRef, hostnames: set[str]) -> list[str]:
    """Match public Access selectors without returning arbitrary destination URI data."""

    matches: list[str] = []
    for domain in app.domains:
        selector = domain.split("/", 1)[0]
        if not _HOST.fullmatch(selector):
            continue
        if any(fnmatch.fnmatchcase(hostname, selector) for hostname in hostnames):
            matches.append(selector + ("/[path]" if "/" in domain else ""))
    return matches


def _issue(unsupported: JsonArray, code: str, scope: str) -> None:
    """Emit one fixed unsupported-topology code without raw omitted values."""

    unsupported.append({"code": code, "scope": scope})
