"""Focused verify-flow regression tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cloudflare_publish import verify_flow
from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.cloudflare_contract import (
    TunnelClientRef,
    TunnelConfigurationRef,
    TunnelConnectionRef,
)
from cloudflare_publish.cloudflared import Cloudflared
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient, HttpResponse
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.keychain import Keychain
from cloudflare_publish.launchd import Launchd
from cloudflare_publish.models import (
    CheckResult,
    ManagedPublication,
    ManagerConfig,
    OriginOptions,
    PendingTransition,
    PublicationRemoteState,
    PublicationSpec,
    StateManifest,
)
from cloudflare_publish.paths import build_paths
from cloudflare_publish.process import CommandRunner
from cloudflare_publish.render import build_tunnel_configuration
from cloudflare_publish.verify_flow import (
    _anonymous_live_check,
    _origin_probe_request,
    _public_live_check,
    _remote_tunnel_check,
    _tunnel_configuration_checks,
    collect_verify_checks,
)


def test_anonymous_live_check_rejects_non_access_redirects() -> None:
    """Live verification does not treat arbitrary public redirects as Access protection."""

    publication = _publication(audience="human")
    manager = _manager()
    http = _StaticHttp(status_code=302, location="https://public.example.com/login")

    result = _anonymous_live_check(publication=publication, manager=manager, http=http)

    assert result.ok is False
    assert result.detail == "HTTP 302 -> https://public.example.com/login"


def test_anonymous_live_check_accepts_access_auth_domain_redirects() -> None:
    """Anonymous live verification accepts redirects to the configured Access auth domain."""

    publication = _publication(audience="human")
    manager = _manager()
    http = _StaticHttp(
        status_code=302,
        location="https://example.cloudflareaccess.com/cdn-cgi/access/login/app.example.com",
    )

    result = _anonymous_live_check(publication=publication, manager=manager, http=http)

    assert result.ok is True


def test_ssh_anonymous_probe_rejects_even_access_login_redirects() -> None:
    """Headless SSH requires a denial response, not a potential browser-login path."""

    original = _publication(audience="machine")
    publication = replace(
        original,
        spec=replace(original.spec, kind="ssh_public", verify_path=None, expect_status=None),
    )
    http = _StaticHttp(
        status_code=302,
        location="https://example.cloudflareaccess.com/cdn-cgi/access/login/app.example.com",
    )
    result = _anonymous_live_check(publication=publication, manager=_manager(), http=http)
    assert result.ok is False


def test_public_live_check_requires_the_declared_origin_status() -> None:
    """Public verification observes the origin contract rather than Access denial."""

    publication = _publication(audience="public")
    http = _StaticHttp(status_code=204)

    result = _public_live_check(publication=publication, http=http)

    assert result.ok is True
    assert result.detail == "HTTP 204"


def test_origin_probe_request_preserves_host_and_sni_overrides() -> None:
    """Local verification requests the override host while connecting to the configured origin."""

    publication = _publication(
        audience="mixed",
        origin_url="https://127.0.0.1:8443",
        http_host_header="grafana.internal",
        origin_server_name="tls.internal",
    )

    request_url, headers, connect_to = _origin_probe_request(publication)

    assert request_url == "https://tls.internal:8443/"
    assert headers == {"Host": "grafana.internal"}
    assert len(connect_to) == 1
    assert connect_to[0].request_host == "tls.internal"
    assert connect_to[0].request_port == 8443
    assert connect_to[0].connect_host == "127.0.0.1"
    assert connect_to[0].connect_port == 8443


def test_configuration_check_uses_effective_withdrawn_routes() -> None:
    manifest = _manifest(pending=PendingTransition("op-1", "remove", "app", {}, route="withdrawn"))
    api = _ConfigurationApi(build_tunnel_configuration({})["config"])

    checks = _tunnel_configuration_checks(api=api, manifest=manifest)

    assert all(check.ok for check in checks)
    assert checks[1].detail is not None and "session drainage" in checks[1].detail


def test_configuration_check_uses_effective_candidate_and_its_new_audience() -> None:
    candidate = _publication(audience="machine", origin_url="http://127.0.0.1:4000")
    candidate = replace(candidate, state=replace(candidate.state, access_aud="candidate-aud"))
    manifest = _manifest(
        pending=PendingTransition(
            "op-1", "publish", "app", {}, route="candidate", candidate=candidate
        )
    )
    config = build_tunnel_configuration(
        {"app": candidate}, auth_domain=manifest.manager.auth_domain
    )["config"]
    checks = _tunnel_configuration_checks(api=_ConfigurationApi(config), manifest=manifest)
    assert all(check.ok for check in checks)


@pytest.mark.parametrize("version", (None, 7, 9))
def test_configuration_application_is_negative_when_active_version_is_unobservable_or_wrong(
    version: int | None,
) -> None:
    manifest = _manifest()
    config = build_tunnel_configuration(
        manifest.publications, auth_domain=manifest.manager.auth_domain
    )["config"]
    api = _ConfigurationApi(config)
    api.clients = (_client(version),)

    parity, application = _tunnel_configuration_checks(api=api, manifest=manifest)

    assert parity.ok
    assert not application.ok
    assert application.group == "routing"


def test_configuration_application_needs_reported_stored_version_and_active_connector() -> None:
    manifest = _manifest()
    config = build_tunnel_configuration(
        manifest.publications, auth_domain=manifest.manager.auth_domain
    )["config"]
    api = _ConfigurationApi(config)
    api.version = None
    parity, application = _tunnel_configuration_checks(api=api, manifest=manifest)
    assert parity.ok and not application.ok
    assert api.connection_reads == 0
    api.version = 8
    api.clients = ()
    parity, application = _tunnel_configuration_checks(api=api, manifest=manifest)
    assert parity.ok and not application.ok
    assert application.detail is not None and "active_connectors=0" in application.detail


def test_malformed_remote_configuration_reports_field_and_does_not_claim_application() -> None:
    api = _ConfigurationApi({"ingress": None})
    parity, application = _tunnel_configuration_checks(api=api, manifest=_manifest())
    assert not parity.ok and not application.ok
    assert parity.detail is not None and "config.ingress" in parity.detail
    assert api.connection_reads == 0


def test_initial_pending_setup_never_queries_an_empty_tunnel_identity() -> None:
    manifest = replace(
        _manifest(pending=PendingTransition("op-setup", "setup", "cloudflare-publish", {})),
        manager=replace(_manager(), tunnel_id=""),
        publications={},
    )
    api = _ConfigurationApi({})
    checks = _tunnel_configuration_checks(api=api, manifest=manifest)
    tunnel_check = _remote_tunnel_check(api=api, manager=manifest.manager)
    assert not tunnel_check.ok
    assert all(not check.ok for check in checks)
    assert api.config_reads == api.connection_reads == 0


@pytest.mark.parametrize("withdrawn", (False, True))
def test_verify_projects_pending_routes_into_selection_local_and_live_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, withdrawn: bool
) -> None:
    candidate = _publication(audience="machine", origin_url="http://127.0.0.1:4000")
    pending = PendingTransition(
        "op-1",
        "remove" if withdrawn else "publish",
        "app",
        {},
        route="withdrawn" if withdrawn else "candidate",
        candidate=None if withdrawn else candidate,
    )
    manifest = _manifest(pending=pending)
    monkeypatch.setattr(verify_flow, "require_manifest", lambda paths: manifest)
    monkeypatch.setattr(verify_flow, "load_api_token", lambda **kwargs: "test-token")
    observed: dict[str, object] = {}

    def local(**kwargs):
        observed["local_publications"] = kwargs["manifest"].publications
        observed["selection"] = kwargs["selected_names"]
        return (CheckResult("Access", True, group="access", publication_name="app"),)

    def live(**kwargs):
        observed["live_publication"] = kwargs["publication"]
        return ()

    monkeypatch.setattr(verify_flow, "_local_checks", local)
    monkeypatch.setattr(verify_flow, "_live_checks", live)
    checks = _collect(tmp_path, publication_name="app")
    assert checks[0].label == "manager mutation complete"
    assert checks[0].ok is False and "operation=op-1" in checks[0].detail
    if withdrawn:
        assert observed["local_publications"] == {}
        assert observed["selection"] == ()
        assert "live_publication" not in observed
    else:
        assert observed["local_publications"] == {"app": candidate}
        assert observed["selection"] == ("app",)
        assert observed["live_publication"] == candidate


def test_pending_setup_remains_visible_even_before_keychain_credentials_exist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(pending=PendingTransition("op-setup", "setup", "cloudflare-publish", {}))
    monkeypatch.setattr(verify_flow, "require_manifest", lambda paths: manifest)

    def missing_token(**kwargs):
        raise AppError("The API token has not been stored.")

    monkeypatch.setattr(verify_flow, "load_api_token", missing_token)
    checks = _collect(tmp_path)
    assert [check.label for check in checks] == [
        "manager mutation complete",
        "Cloudflare credentials available",
    ]
    assert all(not check.ok for check in checks)
    assert "op-setup" in checks[0].detail


def _collect(tmp_path: Path, publication_name: str | None = None) -> tuple[CheckResult, ...]:
    paths = build_paths(repo_root=tmp_path / "repo", home=tmp_path / "home")
    runner = CommandRunner()
    return collect_verify_checks(
        paths=paths,
        cloudflared=Cloudflared(runner),
        launchd=Launchd(runner, paths),
        keychain=Keychain(runner),
        http=CurlHttpClient(runner),
        publication_name=publication_name,
        live=True,
    )


def _manifest(pending: PendingTransition | None = None) -> StateManifest:
    return StateManifest(
        schema_version=1,
        manager=_manager(),
        publications={"app": _publication(audience="machine")},
        backups=(),
        updated_at="2026-04-16T00:00:00Z",
        pending=pending,
    )


def _client(version: int | None = 8) -> TunnelClientRef:
    return TunnelClientRef("local", version, (TunnelConnectionRef("connection", False),))


class _ConfigurationApi(CloudflareApi):
    """Keep config observations independent from expected-version and route projections."""

    def __init__(self, config: JsonObject) -> None:
        self.config = config
        self.version: int | None = 8
        self.clients: tuple[TunnelClientRef, ...] = (_client(),)
        self.config_reads = 0
        self.connection_reads = 0

    def get_tunnel_configuration_snapshot(self, *, account_id: str, tunnel_id: str):
        assert account_id and tunnel_id
        self.config_reads += 1
        return TunnelConfigurationRef(self.config, self.version)

    def list_tunnel_connections(self, *, account_id: str, tunnel_id: str):
        assert account_id and tunnel_id
        self.connection_reads += 1
        return self.clients


class _StaticHttp(CurlHttpClient):
    """Minimal HTTP stub for verify-flow helper tests."""

    def __init__(self, *, status_code: int, location: str | None = None) -> None:
        """Store the fixed response payload."""

        self._status_code = status_code
        self._location = location

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_time: int = 15,
        follow_redirects: bool = False,
        insecure: bool = False,
    ) -> HttpResponse:
        """Return the fixed response for one live verification request."""

        del url, headers, max_time, follow_redirects, insecure
        response_headers = {} if self._location is None else {"location": self._location}
        return HttpResponse(status_code=self._status_code, body="", headers=response_headers)


def _publication(
    *,
    audience: str,
    origin_url: str = "http://127.0.0.1:3000",
    http_host_header: str | None = None,
    origin_server_name: str | None = None,
) -> ManagedPublication:
    """Build a minimal managed publication fixture."""

    return ManagedPublication(
        spec=PublicationSpec(
            kind="http_public",
            name="app",
            hostname="app.example.com",
            origin_url=origin_url,
            audience=audience,
            allowed_emails=("ops@example.com",),
            allowed_email_domains=(),
            verify_path="/",
            expect_status="200-399",
            origin_options=OriginOptions(
                http_host_header=http_host_header,
                origin_server_name=origin_server_name,
                no_tls_verify=False,
            ),
        ),
        state=PublicationRemoteState(
            dns_record_id="dns-1",
            access_application_id="app-1",
            access_aud="aud-1",
            policy_ids=("policy-1",),
            service_token_id="token-1",
            service_token_client_id="client-1",
            service_token_keychain_account="service-token:app",
            updated_at="2026-04-16T00:00:00Z",
        ),
    )


def _manager() -> ManagerConfig:
    """Build a minimal manager fixture."""

    return ManagerConfig(
        account_id="acc-1",
        account_name="Example Account",
        zone_id="zone-1",
        zone_name="example.com",
        auth_domain="example.cloudflareaccess.com",
        tunnel_name="cloudflare-publish",
        tunnel_id="tunnel-1",
        api_token_keychain_account="api-token",
    )
