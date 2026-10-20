"""Typed, closed tunnel configuration contract and field-specific comparison."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import urlsplit

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonArray, JsonObject, JsonValue


@dataclass(frozen=True)
class AccessValidation:
    """A route-local required JWT validator, never a global inherited guard."""

    team_name: str
    audiences: tuple[str, ...]


@dataclass(frozen=True)
class OriginRequest:
    """The supported connector origin options, with explicit benign defaults."""

    http_host_header: str | None = None
    origin_server_name: str | None = None
    no_tls_verify: bool = False
    access: AccessValidation | None = None


@dataclass(frozen=True)
class IngressRule:
    """One ordered exact-hostname rule, or the terminal 404."""

    hostname: str | None
    service: str
    origin_request: OriginRequest


@dataclass(frozen=True)
class TunnelConfiguration:
    """The complete managed topology; unrepresented vendor fields are rejected."""

    ingress: tuple[IngressRule, ...]


@dataclass(frozen=True)
class TunnelConfigurationComparison:
    """A non-throwing parity result safe for read-only diagnostics."""

    matches: bool
    detail: str | None = None


def parse_tunnel_configuration(payload: JsonValue) -> TunnelConfiguration:
    """Parse only the supported subset, retaining routing order and rejecting drift."""

    config = _object(payload, "config")
    _fields(config, {"ingress", "originRequest", "warp-routing"}, "config")
    if "originRequest" in config:
        global_origin = _object(config["originRequest"], "config.originRequest")
        _fields(global_origin, set(), "config.originRequest")
    if "warp-routing" in config:
        warp = _object(config["warp-routing"], "config.warp-routing")
        _fields(warp, {"enabled"}, "config.warp-routing")
        if "enabled" in warp and warp["enabled"] is not False:
            _invalid("config.warp-routing.enabled", "must be false; private routing is not managed")
    ingress = config.get("ingress")
    if not isinstance(ingress, list) or not ingress:
        _invalid("config.ingress", "must be a nonempty array ending with one catch-all 404")
    rules: list[IngressRule] = []
    hostnames: set[str] = set()
    for index, value in enumerate(ingress):
        path = f"config.ingress[{index}]"
        rule = _parse_rule(value, path)
        if rule.hostname is None:
            if index != len(ingress) - 1:
                _invalid(path, "the only catch-all must be the final rule")
        elif rule.hostname.casefold() in hostnames:
            _invalid(f"{path}.hostname", "duplicates an earlier hostname")
        else:
            hostnames.add(rule.hostname.casefold())
        rules.append(rule)
    if rules[-1].hostname is not None:
        _invalid("config.ingress", "must end with exactly one hostless catch-all 404")
    return TunnelConfiguration(tuple(rules))


def normalize_tunnel_configuration(config: JsonValue) -> JsonObject:
    """Return the typed managed contract with defaults normalized, never reordered."""

    return _configuration_json(parse_tunnel_configuration(config))


def compare_tunnel_configuration(
    *, actual: JsonValue, expected: JsonValue
) -> TunnelConfigurationComparison:
    """Compare GET config to a PUT body; malformed input is negative evidence, not a crash."""

    try:
        actual_config = normalize_tunnel_configuration(actual)
        expected_body = _object(expected, "expected")
        _fields(expected_body, {"config"}, "expected")
        expected_config = normalize_tunnel_configuration(expected_body.get("config"))
    except AppError as error:
        return TunnelConfigurationComparison(False, error.message)
    difference = _difference(actual_config, expected_config, "config")
    return TunnelConfigurationComparison(difference is None, difference)


def tunnel_configuration_matches(*, actual: JsonValue, expected: JsonValue) -> bool:
    """Return parity without allowing malformed provider data to abort diagnostics."""

    return compare_tunnel_configuration(actual=actual, expected=expected).matches


def require_refresh_configuration_owned(*, actual: JsonValue, expected: JsonValue) -> None:
    """Permit explicit native-guard upgrade, never overwrite foreign configuration drift."""

    comparison = compare_tunnel_configuration(actual=actual, expected=expected)
    if comparison.matches:
        return
    body = _object(expected, "expected")
    _fields(body, {"config"}, "expected")
    configuration = parse_tunnel_configuration(body.get("config"))
    legacy = TunnelConfiguration(
        tuple(
            IngressRule(
                rule.hostname,
                rule.service,
                OriginRequest(
                    http_host_header=rule.origin_request.http_host_header,
                    origin_server_name=rule.origin_request.origin_server_name,
                    no_tls_verify=rule.origin_request.no_tls_verify,
                ),
            )
            for rule in configuration.ingress
        )
    )
    legacy_comparison = compare_tunnel_configuration(
        actual=actual, expected={"config": _configuration_json(legacy)}
    )
    if legacy_comparison.matches:
        return
    raise AppError(
        "Remote tunnel configuration is not owned or exactly pre-guard. "
        + (comparison.detail or "Configuration parity is unobserved."),
        code="tunnel_configuration_drift",
        hints=("Inspect foreign configuration before manager refresh; it was not overwritten.",),
    )


def _parse_rule(value: JsonValue, path: str) -> IngressRule:
    rule = _object(value, path)
    _fields(rule, {"hostname", "service", "originRequest"}, path)
    service = _string(rule.get("service"), f"{path}.service")
    origin = _parse_origin(rule.get("originRequest", {}), f"{path}.originRequest")
    if "hostname" not in rule:
        if service != "http_status:404" or origin != OriginRequest():
            _invalid(path, "the hostless catch-all must use only http_status:404")
        return IngressRule(None, service, origin)
    hostname = _string(rule["hostname"], f"{path}.hostname")
    if len(hostname) > 253 or any(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None
        for label in hostname.split(".")
    ):
        _invalid(f"{path}.hostname", "must be an exact DNS hostname")
    try:
        parsed = urlsplit(service)
        valid_service = (
            parsed.scheme in {"http", "https", "ssh"}
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and (parsed.port is None or parsed.port > 0)
        )
    except ValueError:
        valid_service = False
    if not valid_service:
        _invalid(f"{path}.service", "must be a managed HTTP(S) or SSH origin URL")
    if service.startswith("ssh://") and (
        origin.http_host_header is not None
        or origin.origin_server_name is not None
        or origin.no_tls_verify
    ):
        _invalid(f"{path}.originRequest", "HTTP origin options are not supported on SSH")
    return IngressRule(hostname, service, origin)


def _parse_origin(value: JsonValue, path: str) -> OriginRequest:
    origin = _object(value, path)
    _fields(origin, {"httpHostHeader", "originServerName", "noTLSVerify", "access"}, path)
    no_tls_verify = origin.get("noTLSVerify", False)
    if not isinstance(no_tls_verify, bool):
        _invalid(f"{path}.noTLSVerify", "must be a boolean")
    return OriginRequest(
        http_host_header=_optional_string(origin, "httpHostHeader", path),
        origin_server_name=_optional_string(origin, "originServerName", path),
        no_tls_verify=no_tls_verify,
        access=_parse_access(origin["access"], f"{path}.access") if "access" in origin else None,
    )


def _parse_access(value: JsonValue, path: str) -> AccessValidation:
    access = _object(value, path)
    _fields(access, {"required", "teamName", "audTag"}, path)
    if access.get("required") is not True:
        _invalid(f"{path}.required", "must be true for a managed Access validator")
    team = _string(access.get("teamName"), f"{path}.teamName")
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", team) is None:
        _invalid(f"{path}.teamName", "must be an Access team slug, not a URL or domain")
    audience_values = access.get("audTag")
    if not isinstance(audience_values, list) or not audience_values:
        _invalid(f"{path}.audTag", "must be a nonempty array of application audiences")
    audiences = tuple(
        _string(audience, f"{path}.audTag[{index}]")
        for index, audience in enumerate(audience_values)
    )
    if len(audiences) != len(set(audiences)):
        _invalid(f"{path}.audTag", "must not repeat an application audience")
    return AccessValidation(team, audiences)


def _configuration_json(config: TunnelConfiguration) -> JsonObject:
    ingress: JsonArray = []
    for rule in config.ingress:
        item: JsonObject = {"service": rule.service}
        if rule.hostname is not None:
            item["hostname"] = rule.hostname
        origin: JsonObject = {}
        if rule.origin_request.http_host_header is not None:
            origin["httpHostHeader"] = rule.origin_request.http_host_header
        if rule.origin_request.origin_server_name is not None:
            origin["originServerName"] = rule.origin_request.origin_server_name
        if rule.origin_request.no_tls_verify:
            origin["noTLSVerify"] = True
        if rule.origin_request.access is not None:
            origin["access"] = {
                "required": True,
                "teamName": rule.origin_request.access.team_name,
                "audTag": list(rule.origin_request.access.audiences),
            }
        if origin:
            item["originRequest"] = origin
        ingress.append(item)
    return {"ingress": ingress}


def _object(value: JsonValue, path: str) -> JsonObject:
    if not isinstance(value, dict):
        _invalid(path, "must be an object")
    return value


def _fields(value: JsonObject, allowed: set[str], path: str) -> None:
    for field in sorted(set(value) - allowed):
        _invalid(_field_path(path, field), "is not supported by the managed configuration contract")


def _field_path(path: str, field: str) -> str:
    # Never repeat arbitrary provider-controlled keys or values in public diagnostics.
    suffix = field if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", field) else "[unexpected field]"
    return f"{path}.{suffix}"


def _optional_string(value: JsonObject, field: str, path: str) -> str | None:
    return _string(value[field], f"{path}.{field}") if field in value else None


def _string(value: JsonValue, path: str) -> str:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        _invalid(path, "must be a nonempty string without whitespace")
    return value


def _invalid(path: str, message: str) -> NoReturn:
    raise AppError(f"{path}: {message}.", code="tunnel_configuration_invalid")


def _difference(actual: JsonValue, expected: JsonValue, path: str) -> str | None:
    if isinstance(actual, dict) and isinstance(expected, dict):
        for field in sorted(set(actual) | set(expected)):
            field_path = _field_path(path, field)
            if field not in actual:
                return f"{field_path}: missing managed field."
            if field not in expected:
                return f"{field_path}: unexpected managed field."
            if (difference := _difference(actual[field], expected[field], field_path)) is not None:
                return difference
        return None
    if isinstance(actual, list) and isinstance(expected, list):
        if len(actual) != len(expected):
            return f"{path}: rule or value count differs from local state."
        for index, (actual_value, expected_value) in enumerate(zip(actual, expected, strict=True)):
            if (
                difference := _difference(actual_value, expected_value, f"{path}[{index}]")
            ) is not None:
                return difference
        return None
    if type(actual) is not type(expected) or actual != expected:
        return f"{path}: differs from local state."
    return None
