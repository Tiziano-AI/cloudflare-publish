"""Closed tunnel topology, native Access validation and safe drift diagnostics."""

from __future__ import annotations

from copy import deepcopy

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject, JsonValue
from cloudflare_publish.tunnel_configuration import (
    compare_tunnel_configuration,
    normalize_tunnel_configuration,
    require_refresh_configuration_owned,
    tunnel_configuration_matches,
)


def _configuration() -> JsonObject:
    return {
        "ingress": [
            {
                "hostname": "app.example.com",
                "service": "https://127.0.0.1:8443",
                "originRequest": {
                    "httpHostHeader": "app.internal",
                    "originServerName": "origin.internal",
                    "access": {"required": True, "teamName": "team", "audTag": ["aud-app"]},
                },
            },
            {
                "hostname": "mac.example.com",
                "service": "ssh://127.0.0.1:22",
                "originRequest": {
                    "access": {"required": True, "teamName": "team", "audTag": ["aud-mac"]}
                },
            },
            {"service": "http_status:404"},
        ]
    }


def test_complete_http_ssh_configuration_matches_without_reordering() -> None:
    actual = _configuration()
    assert tunnel_configuration_matches(actual=actual, expected={"config": deepcopy(actual)})
    assert normalize_tunnel_configuration(actual) == actual


def test_only_explicit_benign_defaults_are_normalized() -> None:
    actual = _configuration()
    actual["originRequest"] = {}
    actual["warp-routing"] = {"enabled": False}
    actual["ingress"][0]["originRequest"]["noTLSVerify"] = False
    actual["ingress"][-1]["originRequest"] = {}
    assert tunnel_configuration_matches(actual=actual, expected={"config": _configuration()})


def test_origin_service_without_explicit_port_remains_supported() -> None:
    actual = {
        "ingress": [
            {"hostname": "app.example.com", "service": "http://localhost"},
            {"service": "http_status:404"},
        ]
    }
    assert tunnel_configuration_matches(actual=actual, expected={"config": actual})


@pytest.mark.parametrize(
    ("replacement", "path"),
    (
        (None, "config"),
        ([], "config"),
        ({}, "config.ingress"),
        ({"ingress": None}, "config.ingress"),
        ({"ingress": []}, "config.ingress"),
        ({"ingress": [None]}, "config.ingress[0]"),
        ({"ingress": [{"service": "http_status:403"}]}, "config.ingress[0]"),
        (
            {"ingress": [{"service": "http_status:404"}, {"service": "http_status:404"}]},
            "config.ingress[0]",
        ),
        (
            {"ingress": [{"hostname": "app.example.com", "service": "http://localhost"}]},
            "config.ingress",
        ),
    ),
)
def test_malformed_remote_configuration_is_a_negative_check(
    replacement: JsonValue, path: str
) -> None:
    comparison = compare_tunnel_configuration(
        actual=replacement, expected={"config": _configuration()}
    )
    assert comparison.matches is False
    assert comparison.detail is not None and path in comparison.detail


@pytest.mark.parametrize(
    ("field", "value", "path"),
    (
        ("originRequest", {"noTLSVerify": True}, "config.originRequest.noTLSVerify"),
        ("originRequest", {"access": {"required": True}}, "config.originRequest.access"),
        ("originRequest", None, "config.originRequest"),
        ("warp-routing", {"enabled": True}, "config.warp-routing.enabled"),
        ("warp-routing", {"enabled": 0}, "config.warp-routing.enabled"),
        ("warp-routing", {"enabled": False, "routes": []}, "config.warp-routing.routes"),
        ("warp-routing", [], "config.warp-routing"),
        ("private_network", {}, "config.private_network"),
    ),
)
def test_global_and_private_configuration_drift_is_not_discarded(
    field: str, value: JsonValue, path: str
) -> None:
    actual = _configuration()
    actual[field] = value
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert result.detail is not None and path in result.detail


@pytest.mark.parametrize(
    ("field", "value", "path"),
    (
        ("hostname", "*.example.com", "hostname"),
        ("hostname", None, "hostname"),
        ("service", "tcp://127.0.0.1:22", "service"),
        ("service", "https://user:hidden-secret@127.0.0.1:8443", "service"),
        ("service", "https://127.0.0.1:8443/path", "service"),
        ("service", "https://127.0.0.1:65536", "service"),
        ("service", "https://127.0.0.1:0", "service"),
        ("path", "/api", "path"),
        ("originRequest", None, "originRequest"),
        ("originRequest", {"disableChunkedEncoding": True}, "originRequest.disableChunkedEncoding"),
        ("originRequest", {"noTLSVerify": 1}, "originRequest.noTLSVerify"),
        ("originRequest", {"httpHostHeader": None}, "originRequest.httpHostHeader"),
    ),
)
def test_rule_validation_rejects_unsupported_or_malformed_fields(
    field: str, value: JsonValue, path: str
) -> None:
    actual = _configuration()
    actual["ingress"][0][field] = value
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert result.detail is not None and f"config.ingress[0].{path}" in result.detail
    assert "hidden-secret" not in result.detail


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("required", False),
        ("required", 1),
        ("teamName", "other"),
        ("teamName", "team.example.com"),
        ("audTag", ["new-aud"]),
        ("audTag", ["aud-app", "foreign-aud"]),
        ("audTag", ["aud-app", "aud-app"]),
        ("audTag", []),
        ("audTag", "aud-app"),
        ("audTag", [123]),
        ("unexpected", True),
    ),
)
def test_native_access_boundary_drift_identifies_guard_field(field: str, value: JsonValue) -> None:
    actual = _configuration()
    actual["ingress"][0]["originRequest"]["access"][field] = value
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert (
        result.detail is not None
        and f"config.ingress[0].originRequest.access.{field}" in result.detail
    )


def test_missing_route_guard_is_not_equivalent_to_the_protected_route() -> None:
    actual = _configuration()
    del actual["ingress"][1]["originRequest"]
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert result.detail == "config.ingress[1].originRequest: missing managed field."


def test_same_host_rules_are_not_sorted_or_coalesced() -> None:
    actual = _configuration()
    actual["ingress"][1]["hostname"] = "app.example.com"
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert result.detail is not None and "config.ingress[1].hostname" in result.detail
    assert "duplicates" in result.detail


def test_ordered_rules_are_not_sorted_into_false_parity() -> None:
    actual = _configuration()
    actual["ingress"][0], actual["ingress"][1] = actual["ingress"][1], actual["ingress"][0]
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert result.detail is not None and "config.ingress[0].hostname" in result.detail


@pytest.mark.parametrize("field", ("httpHostHeader", "originServerName", "noTLSVerify"))
def test_supported_http_options_remain_behavior_bearing(field: str) -> None:
    actual = _configuration()
    actual["ingress"][0]["originRequest"][field] = (
        True if field == "noTLSVerify" else "changed.internal"
    )
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert result.detail is not None and f"config.ingress[0].originRequest.{field}" in result.detail


def test_ssh_rejects_http_origin_options_but_accepts_its_native_guard() -> None:
    actual = _configuration()
    actual["ingress"][1]["originRequest"]["httpHostHeader"] = "ssh.internal"
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert not result.matches
    assert (
        result.detail is not None
        and "HTTP origin options are not supported on SSH" in result.detail
    )


def test_malformed_expected_configuration_is_also_nonthrowing() -> None:
    result = compare_tunnel_configuration(actual=_configuration(), expected=None)
    assert not result.matches
    assert result.detail == "expected: must be an object."


def test_provider_values_are_never_printed_in_difference_diagnostics() -> None:
    actual = _configuration()
    actual["ingress"][0]["service"] = "https://private-host.internal:8443"
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert result.detail == "config.ingress[0].service: differs from local state."
    actual["sensitive\nprovider-key"] = "hidden-value"
    result = compare_tunnel_configuration(actual=actual, expected={"config": _configuration()})
    assert result.detail == (
        "config.[unexpected field]: is not supported by the managed configuration contract."
    )


def test_refresh_accepts_only_exact_current_or_guard_stripped_legacy() -> None:
    current = _configuration()
    require_refresh_configuration_owned(actual=current, expected={"config": current})
    legacy = deepcopy(current)
    for rule in legacy["ingress"]:
        if "originRequest" in rule:
            del rule["originRequest"]["access"]
            if not rule["originRequest"]:
                del rule["originRequest"]
    require_refresh_configuration_owned(actual=legacy, expected={"config": current})


@pytest.mark.parametrize("drift", ("global", "tls", "private", "partial_guard", "wrong_aud"))
def test_refresh_does_not_use_legacy_upgrade_to_discard_foreign_drift(drift: str) -> None:
    actual = _configuration()
    if drift == "global":
        actual["originRequest"] = {"noTLSVerify": True}
    elif drift == "tls":
        actual["ingress"][0]["originRequest"]["noTLSVerify"] = True
    elif drift == "private":
        actual["warp-routing"] = {"enabled": True}
    elif drift == "partial_guard":
        del actual["ingress"][0]["originRequest"]["access"]
    else:
        actual["ingress"][0]["originRequest"]["access"]["audTag"] = ["foreign-aud"]
    with pytest.raises(AppError) as raised:
        require_refresh_configuration_owned(actual=actual, expected={"config": _configuration()})
    assert raised.value.code == "tunnel_configuration_drift"
