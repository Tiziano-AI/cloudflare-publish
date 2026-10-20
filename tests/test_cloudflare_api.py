"""Focused Cloudflare API adapter regression tests."""

from __future__ import annotations

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.http import CurlHttpClient, HttpConnectToEntry, HttpResponse


class _RecordingHttpClient(CurlHttpClient):
    """Record one GET request and return a fixed response payload."""

    def __init__(self) -> None:
        """Initialize the recorded request slots."""

        self.recorded_url: str | None = None
        self.recorded_headers: dict[str, str] | None = None
        self.recorded_method: str | None = None
        self._responses: dict[str, HttpResponse] = {}

    def queue_response(self, *, url: str, response: HttpResponse) -> None:
        """Register one URL-specific GET response."""

        self._responses[url] = response

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_time: int = 15,
        follow_redirects: bool = False,
        insecure: bool = False,
        connect_to: tuple[HttpConnectToEntry, ...] = (),
    ) -> HttpResponse:
        """Record the authenticated GET request for tunnel token retrieval."""

        del max_time, follow_redirects, insecure, connect_to
        self.recorded_method = "GET"
        self.recorded_url = url
        self.recorded_headers = headers
        if url in self._responses:
            return self._responses[url]
        return HttpResponse(status_code=200, body='{"success":true,"result":"token-value"}')

    def delete(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_time: int = 30,
        insecure: bool = False,
        connect_to: tuple[HttpConnectToEntry, ...] = (),
    ) -> HttpResponse:
        """Record the authenticated DELETE request for tunnel connection cleanup."""

        del max_time, insecure, connect_to
        self.recorded_method = "DELETE"
        self.recorded_url = url
        self.recorded_headers = headers
        return HttpResponse(status_code=200, body='{"success":true,"result":{}}')


def test_get_tunnel_token_sends_authorization_header() -> None:
    """Tunnel token retrieval must authenticate with the canonical bearer header."""

    http = _RecordingHttpClient()
    api = CloudflareApi(http, "test-token")

    token = api.get_tunnel_token(account_id="account-123", tunnel_id="tunnel-123")

    assert token == "token-value"
    assert (
        http.recorded_url
        == "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123/token"
    )
    assert http.recorded_headers == {"Authorization": "Bearer test-token"}


def test_cleanup_tunnel_connections_sends_authorization_header() -> None:
    """Tunnel-connection cleanup must authenticate with the canonical bearer header."""

    http = _RecordingHttpClient()
    api = CloudflareApi(http, "test-token")

    api.cleanup_tunnel_connections(account_id="account-123", tunnel_id="tunnel-123")

    assert http.recorded_method == "DELETE"
    assert (
        http.recorded_url
        == "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123/connections"
    )
    assert http.recorded_headers == {"Authorization": "Bearer test-token"}


def test_list_accounts_follows_cloudflare_pagination() -> None:
    """Account discovery walks every reported Cloudflare result page."""

    http = _RecordingHttpClient()
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/accounts?page=1&per_page=50",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"acc-1","name":"First"}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/accounts?page=2&per_page=50",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"acc-2","name":"Second"}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    accounts = api.list_accounts()

    assert tuple(account.id for account in accounts) == ("acc-1", "acc-2")


def test_list_zones_decodes_zone_account_id() -> None:
    """Zone discovery keeps the Cloudflare zone owner account attached."""

    http = _RecordingHttpClient()
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/zones?page=1&per_page=50&name=example.com",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"zone-1","name":"example.com",'
                '"account":{"id":"acc-1"},"status":"active","type":"full"}],'
                '"result_info":{"total_pages":1}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    zones = api.list_zones(name="example.com")

    assert len(zones) == 1
    assert zones[0].account_id == "acc-1"
    assert zones[0].status == "active"
    assert zones[0].zone_type == "full"


def test_list_zones_follows_cloudflare_pagination() -> None:
    """Zone discovery walks every reported Cloudflare result page."""

    http = _RecordingHttpClient()
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/zones?page=1&per_page=50",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"zone-1","name":"first.example.com",'
                '"account":{"id":"acc-1"},"status":"active","type":"full"}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/zones?page=2&per_page=50",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"zone-2","name":"second.example.com",'
                '"account":{"id":"acc-1"},"status":"active","type":"full"}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    zones = api.list_zones()

    assert tuple(zone.id for zone in zones) == ("zone-1", "zone-2")


def test_list_tunnels_follows_cloudflare_pagination() -> None:
    """Tunnel discovery walks every reported Cloudflare result page."""

    http = _RecordingHttpClient()
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel?page=1&per_page=1000",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"tunnel-1","name":"first",'
                '"created_at":"2026-04-16T00:00:00Z","remote_config":true,"status":"inactive"}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel?page=2&per_page=1000",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"tunnel-2","name":"second",'
                '"created_at":"2026-04-16T00:00:00Z","remote_config":true,"status":"healthy"}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    tunnels = api.list_tunnels(account_id="account-123")

    assert tuple(tunnel.id for tunnel in tunnels) == ("tunnel-1", "tunnel-2")


def test_list_dns_records_follows_cloudflare_pagination() -> None:
    """DNS discovery walks every reported Cloudflare result page."""

    http = _RecordingHttpClient()
    http.queue_response(
        url=(
            "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records"
            "?page=1&per_page=1000&name=app.example.com"
        ),
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"dns-1","name":"app.example.com",'
                '"content":"tunnel-1.cfargotunnel.com","proxied":true}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    http.queue_response(
        url=(
            "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records"
            "?page=2&per_page=1000&name=app.example.com"
        ),
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"dns-2","name":"app.example.com",'
                '"content":"tunnel-2.cfargotunnel.com","proxied":true}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    records = api.list_dns_records(zone_id="zone-123", name="app.example.com")

    assert tuple(record.id for record in records) == ("dns-1", "dns-2")


def test_list_access_applications_follows_cloudflare_pagination() -> None:
    """Access app discovery walks every reported Cloudflare result page."""

    http = _RecordingHttpClient()
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/accounts/account-123/access/apps?page=1&per_page=1000",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"app-1","name":"first","aud":"aud-1",'
                '"domain":"first.example.com"}],"result_info":{"total_pages":2}}'
            ),
        ),
    )
    http.queue_response(
        url="https://api.cloudflare.com/client/v4/accounts/account-123/access/apps?page=2&per_page=1000",
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"app-2","name":"second","aud":"aud-2",'
                '"domain":"second.example.com"}],"result_info":{"total_pages":2}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    apps = api.list_access_applications(account_id="account-123")

    assert tuple(app.id for app in apps) == ("app-1", "app-2")


def test_list_access_policies_missing_ok_returns_empty_tuple() -> None:
    """Listing policies for a missing app is idempotent when the caller opts in."""

    http = _RecordingHttpClient()
    http.queue_response(
        url=(
            "https://api.cloudflare.com/client/v4/accounts/account-123/access/apps/"
            "app-123/policies?page=1&per_page=200"
        ),
        response=HttpResponse(
            status_code=404,
            body='{"success":false,"errors":[{"message":"missing app"}],"result":null}',
        ),
    )
    api = CloudflareApi(http, "test-token")

    policies = api.list_access_policies(
        account_id="account-123",
        application_id="app-123",
        missing_ok=True,
    )

    assert policies == ()


def test_list_access_policies_decodes_precedence() -> None:
    """Policy discovery keeps precedence as part of the managed contract."""

    http = _RecordingHttpClient()
    http.queue_response(
        url=(
            "https://api.cloudflare.com/client/v4/accounts/account-123/access/apps/"
            "app-123/policies?page=1&per_page=200"
        ),
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"policy-1","name":"human",'
                '"decision":"allow","include":[],"precedence":1}],'
                '"result_info":{"total_pages":1}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    policies = api.list_access_policies(account_id="account-123", application_id="app-123")

    assert len(policies) == 1
    assert policies[0].precedence == 1


def test_list_access_policies_follows_cloudflare_pagination() -> None:
    """Access policy discovery walks every reported Cloudflare result page."""

    http = _RecordingHttpClient()
    http.queue_response(
        url=(
            "https://api.cloudflare.com/client/v4/accounts/account-123/access/apps/"
            "app-123/policies?page=1&per_page=200"
        ),
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"policy-1","name":"human",'
                '"decision":"allow","include":[],"precedence":1}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    http.queue_response(
        url=(
            "https://api.cloudflare.com/client/v4/accounts/account-123/access/apps/"
            "app-123/policies?page=2&per_page=200"
        ),
        response=HttpResponse(
            status_code=200,
            body=(
                '{"success":true,"result":[{"id":"policy-2","name":"machine",'
                '"decision":"non_identity","include":[],"precedence":2}],'
                '"result_info":{"total_pages":2}}'
            ),
        ),
    )
    api = CloudflareApi(http, "test-token")

    policies = api.list_access_policies(account_id="account-123", application_id="app-123")

    assert tuple(policy.id for policy in policies) == ("policy-1", "policy-2")
