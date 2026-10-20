"""Machine-readable CLI rendering and model serialization helpers."""

from __future__ import annotations

import json
import re
import sys
from typing import override

from cloudflare_publish.cloudflare_contract import (
    AccountRef,
    OrganizationRef,
    ServiceTokenSecret,
    TunnelRef,
    ZoneRef,
)
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError, AppErrorJsonValue
from cloudflare_publish.json_types import JsonArray, JsonObject, JsonValue
from cloudflare_publish.models import (
    CHECK_GROUPS,
    CheckResult,
    ManagedPublication,
    ManagerConfig,
    PublicationRemoteState,
    PublicationSpec,
    StateManifest,
)
from cloudflare_publish.state import transition_to_object
from cloudflare_publish.workflow_support import canonical_public_url

_SECRET_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"CLOUDFLARE_API_TOKEN\s*=\s*[^\"'\s,}]+"),
    re.compile(r"CF-Access-Client-Secret:\s*[^,\s]+", re.IGNORECASE),
    re.compile(r"client_secret[\"']?\s*[:=]\s*[\"']?[^\"'\s,}]+", re.IGNORECASE),
    re.compile(r"secret-[A-Za-z0-9._~+/=-]+"),
)


class QuietConsole(Console):
    """Discard human workflow output while JSON mode owns stdout."""

    @override
    def line(self, text: str = "") -> None:
        """Discard one human line."""

        del text

    @override
    def error(self, text: str) -> None:
        """Discard human errors because JSON mode renders a structured error."""

        del text


def write_json_success(*, command: str, data: JsonObject, warnings: tuple[str, ...] = ()) -> None:
    """Write one stable success envelope to stdout."""

    envelope: JsonObject = {
        "ok": True,
        "command": command,
        "output_class": _success_output_class(command=command, data=data),
        "data": data,
        "warnings": list(warnings),
    }
    _ = sys.stdout.write(json.dumps(envelope, indent=2, sort_keys=True) + "\n")


def write_json_error(*, command: str, error: AppError) -> None:
    """Write one stable redacted error envelope to stdout."""

    envelope: JsonObject = {
        "ok": False,
        "command": command,
        "output_class": "evidence_error" if error.data is not None else "public_diagnostic",
        "error": {
            "code": error.code,
            "message": redact_text(error.message),
            "hints": [redact_text(hint) for hint in error.hints],
        },
        "warnings": [],
    }
    if error.data is not None:
        envelope["data"] = object_to_redacted_json_value(error.data)
    _ = sys.stdout.write(json.dumps(envelope, indent=2, sort_keys=True) + "\n")


def redact_text(text: str) -> str:
    """Redact credential-shaped substrings from machine-readable errors."""

    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[redacted]", redacted)
    return redacted


def check_result_to_object(result: CheckResult) -> JsonObject:
    """Serialize one diagnostic or verification check."""

    payload: JsonObject = {
        "label": result.label,
        "ok": result.ok,
        "group": result.group,
        "publication_name": result.publication_name,
        "hostname": result.hostname,
    }
    if result.detail is not None:
        payload["detail"] = result.detail
    return payload


def check_groups_to_array(checks: tuple[CheckResult, ...]) -> JsonArray:
    """Serialize populated verification groups with their failing-check count."""

    return [
        {
            "group": group,
            "checks": [check_result_to_object(check) for check in checks if check.group == group],
            "failures": sum(1 for check in checks if check.group == group and not check.ok),
        }
        for group in CHECK_GROUPS
        if any(check.group == group for check in checks)
    ]


def account_to_object(account: AccountRef) -> JsonObject:
    """Serialize a Cloudflare account reference."""

    return {"id": account.id, "name": account.name}


def zone_to_object(zone: ZoneRef) -> JsonObject:
    """Serialize a Cloudflare zone reference."""

    return {
        "id": zone.id,
        "name": zone.name,
        "account_id": zone.account_id,
        "type": zone.zone_type,
        "status": zone.status,
    }


def tunnel_to_object(tunnel: TunnelRef) -> JsonObject:
    """Serialize a Cloudflare tunnel reference."""

    return {
        "id": tunnel.id,
        "name": tunnel.name,
        "created_at": tunnel.created_at,
        "remote_config": tunnel.remote_config,
        "status": tunnel.status,
        "deleted_at": tunnel.deleted_at,
    }


def organization_to_object(organization: OrganizationRef) -> JsonObject:
    """Serialize the Zero Trust organization fields owned by this product."""

    exempted_zones: JsonArray = [
        name for name in organization.deny_unmatched_requests_exempted_zone_names
    ]
    return {
        "auth_domain": organization.auth_domain,
        "deny_unmatched_requests": organization.deny_unmatched_requests,
        "deny_unmatched_requests_exempted_zone_names": exempted_zones,
    }


def service_token_secret_to_object(secret: ServiceTokenSecret) -> JsonObject:
    """Serialize an explicit service-token handoff result."""

    return {
        "id": secret.id,
        "name": secret.name,
        "client_id": secret.client_id,
        "client_secret": secret.client_secret,
    }


def manager_to_object(manager: ManagerConfig) -> JsonObject:
    """Serialize manager identity without secrets."""

    return {
        "account_id": manager.account_id,
        "account_name": manager.account_name,
        "zone_id": manager.zone_id,
        "zone_name": manager.zone_name,
        "auth_domain": manager.auth_domain,
        "tunnel_name": manager.tunnel_name,
        "tunnel_id": manager.tunnel_id,
        "api_token_keychain_account": manager.api_token_keychain_account,
    }


def publication_to_object(publication: ManagedPublication) -> JsonObject:
    """Serialize one managed publication without service-token secret material."""

    return {
        "spec": publication_spec_to_object(publication.spec),
        "state": publication_state_to_object(publication.state),
    }


def publication_spec_to_object(spec: PublicationSpec) -> JsonObject:
    """Serialize one publication spec."""

    is_http = spec.kind == "http_public"
    payload: JsonObject = {
        "kind": spec.kind,
        "name": spec.name,
        "hostname": spec.hostname,
        "public_verify_url": (
            canonical_public_url(spec.hostname, spec.verify_path)
            if is_http and spec.verify_path is not None
            else None
        ),
        "origin_url": spec.origin_url,
        "audience": spec.audience,
        "allowed_emails": list(spec.allowed_emails),
        "allowed_email_domains": list(spec.allowed_email_domains),
        "verify_path": spec.verify_path,
        "expect_status": spec.expect_status,
        "origin_options": (
            {
                "http_host_header": spec.origin_options.http_host_header,
                "origin_server_name": spec.origin_options.origin_server_name,
                "no_tls_verify": spec.origin_options.no_tls_verify,
            }
            if is_http
            else None
        ),
    }
    if spec.kind == "ssh_public":
        payload["ssh_host_key"] = spec.ssh_host_key
        payload["ssh_client"] = ssh_client_to_object(spec)
    return payload


def ssh_client_to_object(spec: PublicationSpec) -> JsonObject:
    """Describe native SSH transport and trust without choosing a login identity."""

    return {
        "proxy_command": "cloudflared access ssh --hostname %h --loglevel error",
        "known_hosts_line": f"{spec.hostname} {spec.ssh_host_key}",
        "host_key_algorithms": "ssh-ed25519",
        "strict_host_key_checking": "yes",
        "service_token_environment": ["TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET"],
    }


def publication_state_to_object(state: PublicationRemoteState) -> JsonObject:
    """Serialize publication remote ownership state."""

    return {
        "dns_record_id": state.dns_record_id,
        "access_application_id": state.access_application_id,
        "access_aud": state.access_aud,
        "policy_ids": list(state.policy_ids),
        "service_token_id": state.service_token_id,
        "service_token_client_id": state.service_token_client_id,
        "service_token_keychain_account": state.service_token_keychain_account,
        "updated_at": state.updated_at,
    }


def manifest_summary_to_object(manifest: StateManifest) -> JsonObject:
    """Serialize the non-secret manager summary."""

    return {
        "schema_version": manifest.schema_version,
        "manager": manager_to_object(manifest.manager),
        "publication_count": len(manifest.publications),
        "updated_at": manifest.updated_at,
        "pending": transition_to_object(manifest.pending),
    }


def publications_map_to_object(publications: dict[str, ManagedPublication]) -> JsonObject:
    """Serialize a publication map with stable sorted keys."""

    payload: JsonObject = {}
    for name in sorted(publications):
        payload[name] = publication_to_object(publications[name])
    return payload


def json_value_or_empty_object(value: JsonValue) -> JsonObject:
    """Return JSON object payloads as-is and wrap other values under `value`."""

    if isinstance(value, dict):
        return value
    return {"value": value}


def object_array(items: tuple[JsonObject, ...]) -> JsonArray:
    """Return a JSON array from object items."""

    return [item for item in items]


def object_to_redacted_json_value(value: AppErrorJsonValue) -> JsonValue:
    """Convert error diagnostic payloads into JSON while redacting credential-shaped strings."""

    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, list):
        return [object_to_redacted_json_value(item) for item in value]
    payload: JsonObject = {}
    for key, item in value.items():
        payload[key] = object_to_redacted_json_value(item)
    return payload


def _success_output_class(*, command: str, data: JsonObject) -> str:
    """Return the stable output class for one successful JSON envelope."""

    if "credential_handoff" in data or command == "token rotate":
        return "credential_handoff"
    return "public_diagnostic"
