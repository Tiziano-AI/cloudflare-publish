"""Render and publication-contract tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import (
    ManagedPublication,
    OriginOptions,
    PublicationRemoteState,
    PublicationSpec,
    PublishRequest,
)
from cloudflare_publish.paths import build_paths
from cloudflare_publish.publication_contract import build_publication_spec, status_matches_range
from cloudflare_publish.render import build_tunnel_configuration, normalize_tunnel_configuration


def test_build_tunnel_configuration_orders_hostnames(tmp_path: Path) -> None:
    """Tunnel config is ordered by hostname and ends with the catch-all rule."""

    publication_b = _managed_publication(name="b", hostname="b.example.com")
    publication_a = _managed_publication(name="a", hostname="a.example.com")
    rendered = build_tunnel_configuration(
        {"b": publication_b, "a": publication_a}, auth_domain="example.cloudflareaccess.com"
    )
    normalized = normalize_tunnel_configuration(rendered["config"])
    assert normalized["ingress"][-1] == {"service": "http_status:404"}
    assert [item["hostname"] for item in normalized["ingress"][:-1]] == [
        "a.example.com",
        "b.example.com",
    ]


def test_normalize_tunnel_configuration_rejects_unmanaged_origin_request_options() -> None:
    """Tunnel parity rejects foreign behavior rather than silently dropping its fields."""

    with pytest.raises(AppError) as raised:
        _ = normalize_tunnel_configuration(
            {
                "ingress": [
                    {
                        "hostname": "app.example.com",
                        "service": "https://127.0.0.1:8443",
                        "originRequest": {
                            "httpHostHeader": "app.internal",
                            "disableChunkedEncoding": True,
                        },
                    },
                    {"service": "http_status:404"},
                ]
            }
        )
    assert "config.ingress[0].originRequest.disableChunkedEncoding" in raised.value.message


@pytest.mark.parametrize("audience", ("human", "machine", "mixed"))
def test_protected_http_route_binds_its_own_access_audience(audience: str) -> None:
    """Every protected route carries a native validator derived from its owned app."""

    publication = _managed_publication(name="app", hostname="app.example.com")
    publication = replace(publication, spec=replace(publication.spec, audience=audience))
    rendered = build_tunnel_configuration(
        {"app": publication}, auth_domain="my-team.cloudflareaccess.com"
    )
    assert rendered["config"]["ingress"][0]["originRequest"]["access"] == {
        "required": True,
        "teamName": "my-team",
        "audTag": ["aud-app"],
    }


def test_public_route_has_no_access_validator_or_organization_dependency() -> None:
    """Deliberately public origins retain their own authentication boundary."""

    publication = _managed_publication(name="app", hostname="app.example.com")
    publication = replace(publication, spec=replace(publication.spec, audience="public"))
    rendered = build_tunnel_configuration({"app": publication})
    assert rendered == {
        "config": {
            "ingress": [
                {"hostname": "app.example.com", "service": "http://127.0.0.1:3000"},
                {"service": "http_status:404"},
            ]
        }
    }


@pytest.mark.parametrize(
    "auth_domain", (None, "", "https://example.cloudflareaccess.com", "example.com")
)
def test_protected_render_refuses_missing_or_invalid_team_domain(auth_domain: str | None) -> None:
    """Incomplete state cannot silently produce an unguarded protected ingress rule."""

    publication = _managed_publication(name="app", hostname="app.example.com")
    with pytest.raises(AppError):
        _ = build_tunnel_configuration({"app": publication}, auth_domain=auth_domain)


@pytest.mark.parametrize("field", ("access_aud", "access_application_id"))
def test_protected_render_refuses_missing_application_identity(field: str) -> None:
    """A team domain alone is insufficient to bind a route to an owned application."""

    publication = _managed_publication(name="app", hostname="app.example.com")
    publication = replace(publication, state=replace(publication.state, **{field: None}))
    with pytest.raises(AppError) as raised:
        _ = build_tunnel_configuration(
            {"app": publication}, auth_domain="example.cloudflareaccess.com"
        )
    assert raised.value.code == "access_guard_missing"


def test_publication_contract_requires_human_rules() -> None:
    """Human access requires at least one explicit allow rule."""

    with pytest.raises(AppError):
        _ = build_publication_spec(
            request=PublishRequest(
                name="app",
                hostname="app.example.com",
                origin_url="http://127.0.0.1:3000",
                audience="human",
                allowed_emails=(),
                allowed_email_domains=(),
                verify_path=None,
                expect_status=None,
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            )
        )


@pytest.mark.parametrize("hostname", ("foo-.example.com", "example.-com"))
def test_publication_contract_rejects_invalid_dns_labels(hostname: str) -> None:
    """Hostnames fail closed when any DNS label starts or ends with a hyphen."""

    with pytest.raises(AppError):
        _ = build_publication_spec(
            request=PublishRequest(
                name="app",
                hostname=hostname,
                origin_url="http://127.0.0.1:3000",
                audience="machine",
                allowed_emails=(),
                allowed_email_domains=(),
                verify_path=None,
                expect_status=None,
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            )
        )


def test_publication_contract_rejects_invalid_email_domain_labels() -> None:
    """Allowed email domains use the same DNS-label validation as public hostnames."""

    with pytest.raises(AppError):
        _ = build_publication_spec(
            request=PublishRequest(
                name="app",
                hostname="app.example.com",
                origin_url="http://127.0.0.1:3000",
                audience="human",
                allowed_emails=(),
                allowed_email_domains=("example.-com",),
                verify_path=None,
                expect_status=None,
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            )
        )


def test_publication_contract_rejects_origin_urls_with_paths() -> None:
    """Origin URLs stay path-free so verification and routing share one canonical base URL."""

    with pytest.raises(AppError):
        _ = build_publication_spec(
            request=PublishRequest(
                name="app",
                hostname="app.example.com",
                origin_url="http://127.0.0.1:3000/base",
                audience="machine",
                allowed_emails=(),
                allowed_email_domains=(),
                verify_path="/health",
                expect_status=None,
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            )
        )


@pytest.mark.parametrize("verify_path", ("/health?token=secret", "/health#fragment", "/bad path"))
def test_publication_contract_rejects_non_path_verify_values(verify_path: str) -> None:
    """Verification paths stay path-only so inspect cannot surface query-shaped secrets."""

    with pytest.raises(AppError):
        _ = build_publication_spec(
            request=PublishRequest(
                name="app",
                hostname="app.example.com",
                origin_url="http://127.0.0.1:3000",
                audience="machine",
                allowed_emails=(),
                allowed_email_domains=(),
                verify_path=verify_path,
                expect_status=None,
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            )
        )


def test_status_matches_range() -> None:
    """Status range parsing stays inclusive."""

    assert status_matches_range("200-399", 200) is True
    assert status_matches_range("200-399", 399) is True
    assert status_matches_range("200-399", 404) is False


def test_build_paths_uses_manager_locations(tmp_path: Path) -> None:
    """Canonical manager and conflict paths point at the expected locations."""

    paths = build_paths(repo_root=tmp_path / "repo", home=tmp_path / "home")
    assert (
        paths.state_dir
        == tmp_path / "home" / "Library" / "Application Support" / "cloudflare-publish"
    )
    assert paths.logs_dir == tmp_path / "home" / "Library" / "Logs" / "cloudflare-publish"
    assert (
        paths.legacy_launch_agent_file
        == tmp_path / "home" / "Library" / "LaunchAgents" / "com.cloudflare.cloudflared.plist"
    )
    assert paths.legacy_cloudflared_config_file == tmp_path / "home" / ".cloudflared" / "config.yml"
    assert paths.legacy_cloudflared_cert_file == tmp_path / "home" / ".cloudflared" / "cert.pem"


def _managed_publication(*, name: str, hostname: str) -> ManagedPublication:
    """Build a minimal managed publication fixture."""

    return ManagedPublication(
        spec=PublicationSpec(
            kind="http_public",
            name=name,
            hostname=hostname,
            origin_url="http://127.0.0.1:3000",
            audience="machine",
            allowed_emails=(),
            allowed_email_domains=(),
            verify_path="/",
            expect_status="200-399",
            origin_options=OriginOptions(
                http_host_header=None,
                origin_server_name=None,
                no_tls_verify=False,
            ),
        ),
        state=PublicationRemoteState(
            dns_record_id=f"dns-{name}",
            access_application_id=f"app-{name}",
            access_aud=f"aud-{name}",
            policy_ids=(f"policy-{name}",),
            service_token_id=f"token-{name}",
            service_token_client_id=f"client-{name}",
            service_token_keychain_account=f"service-token:{name}",
            updated_at="2026-04-02T00:00:00Z",
        ),
    )
