"""Typed Cloudflare API entities and decode helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject, JsonValue, require_object


@dataclass(frozen=True)
class AccountRef:
    """Cloudflare account identity."""

    id: str
    name: str


@dataclass(frozen=True)
class ZoneRef:
    """Cloudflare DNS zone identity."""

    id: str
    name: str
    account_id: str
    zone_type: str | None
    status: str | None


@dataclass(frozen=True)
class TunnelRef:
    """Shared Cloudflare Tunnel identity."""

    id: str
    name: str
    created_at: str
    remote_config: bool
    status: str | None
    deleted_at: str | None


@dataclass(frozen=True)
class TunnelConfigurationRef:
    """One remotely stored configuration and its observed vendor version."""

    config: JsonObject
    version: int | None


@dataclass(frozen=True)
class TunnelConnectionRef:
    """One connection reported for a connector, including reconnecting connections."""

    id: str
    is_pending_reconnect: bool | None


@dataclass(frozen=True)
class TunnelClientRef:
    """Connector identity and the configuration version it reports applying."""

    id: str
    config_version: int | None
    connections: tuple[TunnelConnectionRef, ...] | None


@dataclass(frozen=True)
class DnsRecordRef:
    """Managed DNS record identity."""

    id: str
    name: str
    content: str
    proxied: bool
    record_type: str | None


@dataclass(frozen=True)
class AccessApplicationRef:
    """Managed Access application identity."""

    id: str
    name: str
    aud: str
    domain: str
    service_auth_401_redirect: bool | None = None


@dataclass(frozen=True)
class AccessDiscoveryRef:
    """Allowlisted application targeting metadata, including multi-destination apps."""

    id: str
    name: str
    domains: tuple[str, ...]
    application_type: str | None
    has_private_destinations: bool
    has_destination_overrides: bool


@dataclass(frozen=True)
class AccessPolicyRef:
    """Managed Access policy identity."""

    id: str
    name: str
    decision: str
    include: tuple[str, ...]
    precedence: int | None
    has_additional_constraints: bool


@dataclass(frozen=True)
class ServiceTokenSecret:
    """A service token plus the only-returned client secret."""

    id: str
    name: str
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class ServiceTokenRef:
    """Recoverable service-token metadata, deliberately excluding its secret."""

    id: str
    name: str
    client_id: str


@dataclass(frozen=True)
class OrganizationRef:
    """Zero Trust organization settings relevant to this repo."""

    auth_domain: str
    deny_unmatched_requests: bool
    deny_unmatched_requests_exempted_zone_names: tuple[str, ...]
    raw_payload: JsonObject


def account_from_value(payload: JsonValue) -> AccountRef:
    """Decode one account object."""

    return _account_from_object(require_object(payload, message="account entries must be objects."))


def zone_from_value(payload: JsonValue) -> ZoneRef:
    """Decode one zone object."""

    return _zone_from_object(require_object(payload, message="zone entries must be objects."))


def tunnel_from_value(payload: JsonValue) -> TunnelRef:
    """Decode one tunnel object."""

    return _tunnel_from_object(require_object(payload, message="tunnel entries must be objects."))


def tunnel_from_object(payload: JsonObject) -> TunnelRef:
    """Decode one tunnel object."""

    return _tunnel_from_object(payload)


def tunnel_configuration_from_object(payload: JsonObject) -> TunnelConfigurationRef:
    """Preserve a configuration version without inventing one when omitted."""

    config = payload.get("config")
    return TunnelConfigurationRef(
        config=(
            {}
            if config is None
            else require_object(config, message="Tunnel configuration `config` must be an object.")
        ),
        version=_optional_nonnegative_int(payload, "version"),
    )


def tunnel_client_from_value(payload: JsonValue) -> TunnelClientRef:
    """Decode one connector while retaining absent connection observability."""

    item = require_object(payload, message="Tunnel connector entries must be objects.")
    connections_value = item.get("conns")
    connections: tuple[TunnelConnectionRef, ...] | None = None
    if connections_value is not None:
        if not isinstance(connections_value, list):
            raise AppError("Cloudflare API field 'conns' must be an array or null.")
        connections = tuple(_tunnel_connection_from_value(value) for value in connections_value)
    return TunnelClientRef(
        id=_require_nonempty_str(item, "id"),
        config_version=_optional_nonnegative_int(item, "config_version"),
        connections=connections,
    )


def dns_record_from_value(payload: JsonValue) -> DnsRecordRef:
    """Decode one DNS record object."""

    return _dns_record_from_object(
        require_object(payload, message="DNS record entries must be objects.")
    )


def dns_record_from_object(payload: JsonObject) -> DnsRecordRef:
    """Decode one DNS record object."""

    return _dns_record_from_object(payload)


def access_application_from_value(payload: JsonValue) -> AccessApplicationRef:
    """Decode one Access application object."""

    return _access_application_from_object(
        require_object(payload, message="Access application entries must be objects.")
    )


def access_application_from_object(payload: JsonObject) -> AccessApplicationRef:
    """Decode one Access application object."""

    return _access_application_from_object(payload)


def access_discovery_from_value(payload: JsonValue) -> AccessDiscoveryRef:
    """Decode only public destination selectors, never application credentials."""

    item = require_object(payload, message="Access application entries must be objects.")
    domains: list[str] = []
    domain = item.get("domain")
    if isinstance(domain, str) and domain:
        domains.append(domain)
    has_private = False
    has_overrides = False
    destinations = item.get("destinations")
    if isinstance(destinations, list):
        for destination in destinations:
            if not isinstance(destination, dict):
                continue
            uri = destination.get("uri")
            if isinstance(uri, str) and uri:
                domains.append(uri)
            if destination.get("type") == "private":
                has_private = True
            if destination.get("overrides"):
                has_overrides = True
    return AccessDiscoveryRef(
        id=_require_str(item, "id"),
        name=_require_str(item, "name"),
        domains=tuple(dict.fromkeys(domains)),
        application_type=_optional_str(item, "type"),
        has_private_destinations=has_private,
        has_destination_overrides=has_overrides,
    )


def access_policy_from_value(payload: JsonValue) -> AccessPolicyRef:
    """Decode one Access policy object."""

    return _access_policy_from_object(
        require_object(payload, message="Access policy entries must be objects.")
    )


def access_policy_from_object(payload: JsonObject) -> AccessPolicyRef:
    """Decode one Access policy object."""

    return _access_policy_from_object(payload)


def policy_include_signature(payload: JsonValue | None) -> tuple[str, ...]:
    """Return a stable Access-policy include signature tuple."""

    if payload is None:
        return ()
    if not isinstance(payload, list):
        raise AppError("Cloudflare API field 'include' must be an array.")
    encoded: list[str] = []
    for item in payload:
        rule = require_object(item, message="Access policy include entries must be objects.")
        encoded.append(json.dumps(rule, sort_keys=True, separators=(",", ":")))
    encoded.sort()
    return tuple(encoded)


def service_token_from_object(payload: JsonObject) -> ServiceTokenSecret:
    """Decode a service token response object."""

    return ServiceTokenSecret(
        id=_require_str(payload, "id"),
        name=_require_str(payload, "name"),
        client_id=_require_str(payload, "client_id"),
        client_secret=_require_str(payload, "client_secret"),
    )


def service_token_ref_from_value(payload: JsonValue) -> ServiceTokenRef:
    """Decode metadata from a list response without preserving any secret fields."""

    return service_token_ref_from_object(
        require_object(payload, message="Service token entries must be objects.")
    )


def service_token_ref_from_object(payload: JsonObject) -> ServiceTokenRef:
    """Decode the exact identity of a previously created service token."""

    return ServiceTokenRef(
        id=_require_nonempty_str(payload, "id"),
        name=_require_str(payload, "name"),
        client_id=_require_nonempty_str(payload, "client_id"),
    )


def organization_from_object(payload: JsonObject) -> OrganizationRef:
    """Decode organization settings."""

    return OrganizationRef(
        auth_domain=_require_str(payload, "auth_domain"),
        deny_unmatched_requests=_require_bool(payload, "deny_unmatched_requests"),
        deny_unmatched_requests_exempted_zone_names=_optional_string_tuple(
            payload,
            "deny_unmatched_requests_exempted_zone_names",
        ),
        raw_payload=dict(payload),
    )


def cloudflare_error_hints(payload: JsonObject) -> tuple[str, ...]:
    """Return bounded vendor error codes, never echoed messages or request values."""

    codes: list[str] = []
    errors_value = payload.get("errors")
    if isinstance(errors_value, list):
        for item in errors_value:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            if type(code) is int and 0 <= code <= 9_999_999 and str(code) not in codes:
                codes.append(str(code))
            if len(codes) == 8:
                break
    return ("Cloudflare error codes: " + ", ".join(codes) + ".",) if codes else ()


def tunnel_cname(tunnel_id: str) -> str:
    """Return the canonical tunnel CNAME target."""

    return f"{tunnel_id}.cfargotunnel.com"


def _account_from_object(payload: JsonObject) -> AccountRef:
    """Decode one account object."""

    return AccountRef(id=_require_str(payload, "id"), name=_require_str(payload, "name"))


def _zone_from_object(payload: JsonObject) -> ZoneRef:
    """Decode one zone object."""

    account = require_object(
        payload.get("account"),
        message="zone entries must include an account object.",
    )
    return ZoneRef(
        id=_require_str(payload, "id"),
        name=_require_str(payload, "name"),
        account_id=_require_str(account, "id"),
        zone_type=_optional_str(payload, "type"),
        status=_optional_str(payload, "status"),
    )


def _tunnel_from_object(payload: JsonObject) -> TunnelRef:
    """Decode one tunnel object."""

    return TunnelRef(
        id=_require_str(payload, "id"),
        name=_require_str(payload, "name"),
        created_at=_require_str(payload, "created_at"),
        remote_config=_require_bool(payload, "remote_config"),
        status=_optional_str(payload, "status"),
        deleted_at=_optional_str(payload, "deleted_at"),
    )


def _tunnel_connection_from_value(payload: JsonValue) -> TunnelConnectionRef:
    """Decode an individual transport connection without interpreting it as drained."""

    item = require_object(payload, message="Tunnel connection entries must be objects.")
    return TunnelConnectionRef(
        id=_require_nonempty_str(item, "id"),
        is_pending_reconnect=_optional_bool(item, "is_pending_reconnect"),
    )


def _dns_record_from_object(payload: JsonObject) -> DnsRecordRef:
    """Decode one DNS record object."""

    return DnsRecordRef(
        id=_require_str(payload, "id"),
        name=_require_str(payload, "name"),
        content=_require_str(payload, "content"),
        proxied=_require_bool(payload, "proxied"),
        record_type=_optional_str(payload, "type"),
    )


def _access_application_from_object(payload: JsonObject) -> AccessApplicationRef:
    """Decode one Access application object."""

    return AccessApplicationRef(
        id=_require_str(payload, "id"),
        name=_require_str(payload, "name"),
        aud=_require_str(payload, "aud"),
        domain=_require_access_domain(payload),
        service_auth_401_redirect=_optional_bool(payload, "service_auth_401_redirect"),
    )


def _require_access_domain(payload: JsonObject) -> str:
    """Decode the canonical public domain for one Access application."""

    domain_value = payload.get("domain")
    if isinstance(domain_value, str) and domain_value:
        return domain_value
    destinations = payload.get("destinations")
    if isinstance(destinations, list):
        for item in destinations:
            if not isinstance(item, dict):
                continue
            uri = item.get("uri")
            if isinstance(uri, str) and uri:
                return uri
    raise AppError("Access application response did not include a domain or destination URI.")


def _access_policy_from_object(payload: JsonObject) -> AccessPolicyRef:
    """Decode one Access policy object."""

    return AccessPolicyRef(
        id=_require_str(payload, "id"),
        name=_require_str(payload, "name"),
        decision=_require_str(payload, "decision"),
        include=policy_include_signature(payload.get("include")),
        precedence=_optional_int(payload, "precedence"),
        has_additional_constraints=bool(payload.get("require") or payload.get("exclude")),
    )


def _require_str(payload: JsonObject, key: str) -> str:
    """Require a string field from a JSON object."""

    value = payload.get(key)
    if not isinstance(value, str):
        raise AppError(f"Cloudflare API field {key!r} must be a string.")
    return value


def _require_nonempty_str(payload: JsonObject, key: str) -> str:
    """Require an observable resource identity rather than an empty placeholder."""

    value = _require_str(payload, key)
    if not value:
        raise AppError(f"Cloudflare API field {key!r} must not be empty.")
    return value


def _optional_str(payload: JsonObject, key: str) -> str | None:
    """Return an optional string field."""

    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise AppError(f"Cloudflare API field {key!r} must be a string or null.")
    return value


def _require_bool(payload: JsonObject, key: str) -> bool:
    """Require a boolean field from a JSON object."""

    value = payload.get(key)
    if not isinstance(value, bool):
        raise AppError(f"Cloudflare API field {key!r} must be a boolean.")
    return value


def _optional_bool(payload: JsonObject, key: str) -> bool | None:
    """Decode a nullable Boolean without treating strings or integers as flags."""

    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise AppError(f"Cloudflare API field {key!r} must be a boolean or null.")
    return value


def _optional_string_tuple(payload: JsonObject, key: str) -> tuple[str, ...]:
    """Return an optional array of strings."""

    value = payload.get(key)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise AppError(f"Cloudflare API field {key!r} must be an array of strings.")
    strings: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise AppError(f"Cloudflare API field {key!r} must be an array of strings.")
        strings.append(item)
    return tuple(strings)


def _optional_int(payload: JsonObject, key: str) -> int | None:
    """Return an optional integer field."""

    value = payload.get(key)
    if value is None:
        return None
    if type(value) is not int:
        raise AppError(f"Cloudflare API field {key!r} must be an integer or null.")
    return value


def _optional_nonnegative_int(payload: JsonObject, key: str) -> int | None:
    """Decode version counters without accepting booleans, strings or negatives."""

    value = _optional_int(payload, key)
    if value is not None and value < 0:
        raise AppError(f"Cloudflare API field {key!r} must be nonnegative.")
    return value
