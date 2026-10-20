"""Vendor-shape and fail-closed configuration observation regressions."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.config_application import require_configuration_applied
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient, HttpConnectToEntry, HttpResponse
from cloudflare_publish.json_types import JsonArray, JsonObject
from cloudflare_publish.local_connector_observation import (
    LocalConnectorAcknowledgment,
    LocalConnectorObserver,
)

_API = "https://api.cloudflare.com/client/v4"
_TUNNEL = "/accounts/account-id/cfd_tunnel/tunnel-id"


class _HttpResponses(CurlHttpClient):
    """Return explicit REST responses at the actual adapter boundary."""

    def __init__(self) -> None:
        self.responses: dict[tuple[str, str], HttpResponse] = {}
        self.requests: list[tuple[str, str]] = []

    def queue(self, method: str, path: str, result: JsonObject | JsonArray) -> None:
        """Store one successful response, with no generated version or connector state."""

        self.responses[(method, _API + path)] = HttpResponse(
            status_code=200,
            body=json.dumps({"success": True, "result": result}),
        )

    def request(
        self,
        *,
        url: str,
        method: str,
        headers: dict[str, str],
        json_body: str | None,
        max_time: int,
        follow_redirects: bool,
        insecure: bool,
        connect_to: tuple[HttpConnectToEntry, ...],
    ) -> HttpResponse:
        """Consume the requested response without replacing decoding or application logic."""

        del json_body, max_time, follow_redirects, insecure, connect_to
        assert headers == {"Authorization": "Bearer test-token"}
        self.requests.append((method, url))
        return self.responses[(method, url)]


def _with_clients(clients: JsonArray) -> CloudflareApi:
    http = _HttpResponses()
    http.queue("GET", _TUNNEL + "/connections?page=1&per_page=1000", clients)
    return CloudflareApi(http, "test-token")


def _require(api: CloudflareApi, version: int | None = 8):
    return require_configuration_applied(
        api, account_id="account-id", tunnel_id="tunnel-id", expected_version=version
    )


def test_configuration_snapshot_preserves_actual_version_and_legacy_config_getter() -> None:
    http = _HttpResponses()
    http.queue(
        "GET",
        _TUNNEL + "/configurations",
        {"version": 8, "config": {"ingress": [{"service": "http_status:404"}]}},
    )
    api = CloudflareApi(http, "test-token")

    snapshot = api.get_tunnel_configuration_snapshot(account_id="account-id", tunnel_id="tunnel-id")

    assert snapshot.version == 8
    assert snapshot.config == {"ingress": [{"service": "http_status:404"}]}
    assert (
        api.get_tunnel_configuration(account_id="account-id", tunnel_id="tunnel-id")
        == snapshot.config
    )


@pytest.mark.parametrize("version", [0, 8, None])
def test_configuration_put_does_not_invent_a_missing_version(version: int | None) -> None:
    http = _HttpResponses()
    result: JsonObject = {"config": {}}
    if version is not None:
        result["version"] = version
    http.queue("PUT", _TUNNEL + "/configurations", result)
    api = CloudflareApi(http, "test-token")

    assert (
        api.update_tunnel_configuration(
            account_id="account-id", tunnel_id="tunnel-id", configuration={"config": {}}
        )
        == version
    )


@pytest.mark.parametrize("version", [True, "8", 8.5, -1])
def test_configuration_put_rejects_malformed_version(version: object) -> None:
    http = _HttpResponses()
    http.responses[("PUT", _API + _TUNNEL + "/configurations")] = HttpResponse(
        status_code=200, body=json.dumps({"success": True, "result": {"version": version}})
    )

    with pytest.raises(AppError, match="version"):
        CloudflareApi(http, "test-token").update_tunnel_configuration(
            account_id="account-id", tunnel_id="tunnel-id", configuration={"config": {}}
        )


def test_all_connected_replicas_must_report_exact_target_version() -> None:
    api = _with_clients(
        [
            {"id": "local", "config_version": 8, "conns": [{"id": "local-connection"}]},
            {"id": "foreign", "config_version": 8, "conns": [{"id": "foreign-connection"}]},
            {"id": "offline", "config_version": 2, "conns": []},
        ]
    )

    observation = _require(api)

    assert observation.active_connector_ids == ("local", "foreign")
    assert observation.inactive_connector_ids == ("offline",)
    assert not observation.no_active_connectors


@pytest.mark.parametrize("version", [7, 9, None])
def test_stale_newer_and_unobservable_active_versions_block_completion(version: int | None) -> None:
    api = _with_clients(
        [
            {"id": "local", "config_version": 8, "conns": [{"id": "c1"}]},
            {"id": "foreign", "config_version": version, "conns": [{"id": "c2"}]},
        ]
    )

    with pytest.raises(AppError) as caught:
        _require(api)

    assert caught.value.code == "configuration_application_unobserved"
    assert caught.value.data == {
        "connector_id": "foreign",
        "expected_version": 8,
        "observed_version": version,
    }


def test_missing_expected_version_blocks_before_connector_request() -> None:
    http = _HttpResponses()

    with pytest.raises(AppError) as caught:
        _require(CloudflareApi(http, "test-token"), None)

    assert caught.value.code == "configuration_application_unobserved"
    assert http.requests == []


@pytest.mark.parametrize("clients", [[], [{"id": "offline", "conns": []}]])
def test_no_active_connectors_is_explicitly_not_a_running_connector_application_proof(
    clients: JsonArray,
) -> None:
    observation = _require(_with_clients(clients))

    assert observation.no_active_connectors
    assert observation.active_connector_ids == ()


@pytest.mark.parametrize("conns", [None, "invalid", [{}]])
def test_unknown_or_malformed_connections_never_become_offline(conns: object) -> None:
    http = _HttpResponses()
    http.responses[("GET", _API + _TUNNEL + "/connections?page=1&per_page=1000")] = HttpResponse(
        status_code=200,
        body=json.dumps(
            {"success": True, "result": [{"id": "local", "config_version": 8, "conns": conns}]}
        ),
    )

    with pytest.raises(AppError):
        _require(CloudflareApi(http, "test-token"))


def test_reconnecting_connection_does_not_prove_old_configuration_is_gone() -> None:
    api = _with_clients(
        [
            {
                "id": "local",
                "config_version": 7,
                "conns": [{"id": "c1", "is_pending_reconnect": True}],
            }
        ]
    )

    with pytest.raises(AppError) as caught:
        _require(api)

    assert caught.value.code == "configuration_application_unobserved"


def test_duplicate_connector_identity_blocks_ambiguous_observation() -> None:
    api = _with_clients([{"id": "local", "conns": []}, {"id": "local", "conns": []}])

    with pytest.raises(AppError, match="duplicate"):
        _require(api)


def test_connector_pagination_includes_a_stale_replica_on_the_last_page() -> None:
    http = _HttpResponses()
    for page, client_id, version in [(1, "local", 8), (2, "foreign", 7)]:
        http.responses[("GET", _API + _TUNNEL + f"/connections?page={page}&per_page=1000")] = (
            HttpResponse(
                status_code=200,
                body=json.dumps(
                    {
                        "success": True,
                        "result": [
                            {"id": client_id, "config_version": version, "conns": [{"id": "c1"}]}
                        ],
                        "result_info": {"total_pages": 2},
                    }
                ),
            )
        )

    with pytest.raises(AppError) as caught:
        _require(CloudflareApi(http, "test-token"))

    assert caught.value.data is not None
    assert caught.value.data["connector_id"] == "foreign"
    assert len(http.requests) == 2


def _tunnel_payload(*, deleted_at: str | None, identity: str = "tunnel-id") -> JsonObject:
    return {
        "id": identity,
        "name": "managed-tunnel",
        "created_at": "2026-04-16T00:00:00Z",
        "remote_config": True,
        "status": "inactive",
        "deleted_at": deleted_at,
    }


@pytest.mark.parametrize(
    "deleted_at,expected", [(None, False), ("", False), ("2026-10-20T00:00:00Z", True)]
)
def test_deletion_confirmation_requires_a_tombstone_not_inactive_status(
    deleted_at: str | None, expected: bool
) -> None:
    http = _HttpResponses()
    http.queue("GET", _TUNNEL, _tunnel_payload(deleted_at=deleted_at))

    assert (
        CloudflareApi(http, "test-token").tunnel_is_deleted(
            account_id="account-id", tunnel_id="tunnel-id"
        )
        is expected
    )


@pytest.mark.parametrize("status", [404, 403, 500])
def test_generic_errors_do_not_confirm_deletion(status: int) -> None:
    http = _HttpResponses()
    http.responses[("GET", _API + _TUNNEL)] = HttpResponse(status_code=status, body="unavailable")
    api = CloudflareApi(http, "test-token")

    with pytest.raises(AppError):
        api.tunnel_is_deleted(account_id="account-id", tunnel_id="tunnel-id")


def test_cloudflare_json_not_found_still_cannot_confirm_deletion() -> None:
    http = _HttpResponses()
    http.responses[("GET", _API + _TUNNEL)] = HttpResponse(
        status_code=404,
        body='{"success":false,"result":null,"errors":[{"code":1003,"message":"not found"}]}',
    )

    with pytest.raises(AppError):
        CloudflareApi(http, "test-token").tunnel_is_deleted(
            account_id="account-id", tunnel_id="tunnel-id"
        )


def test_wrong_tunnel_identity_cannot_confirm_deletion() -> None:
    http = _HttpResponses()
    http.queue("GET", _TUNNEL, _tunnel_payload(deleted_at="deleted", identity="other-tunnel"))

    with pytest.raises(AppError, match="different tunnel"):
        CloudflareApi(http, "test-token").tunnel_is_deleted(
            account_id="account-id", tunnel_id="tunnel-id"
        )


def test_delete_tunnel_accepts_missing_only_when_explicitly_requested() -> None:
    http = _HttpResponses()
    http.responses[("DELETE", _API + _TUNNEL)] = HttpResponse(status_code=404, body="not found")
    api = CloudflareApi(http, "test-token")

    with pytest.raises(AppError):
        api.delete_tunnel(account_id="account-id", tunnel_id="tunnel-id")
    api.delete_tunnel(account_id="account-id", tunnel_id="tunnel-id", missing_ok=True)


def test_service_token_metadata_has_no_secret_even_if_vendor_returns_one() -> None:
    http = _HttpResponses()
    http.queue(
        "GET",
        "/accounts/account-id/access/service_tokens?page=1&per_page=1000",
        [
            {
                "id": "token-id",
                "name": "managed-token",
                "client_id": "client-id",
                "client_secret": "do-not-retain",
            }
        ],
    )

    (token,) = CloudflareApi(http, "test-token").list_service_tokens(account_id="account-id")

    assert (token.id, token.name, token.client_id) == ("token-id", "managed-token", "client-id")
    assert not hasattr(token, "client_secret")
    assert "do-not-retain" not in repr(token)


def test_exact_service_token_get_recovers_metadata_not_secret() -> None:
    http = _HttpResponses()
    http.queue(
        "GET",
        "/accounts/account-id/access/service_tokens/token-id",
        {"id": "token-id", "name": "managed-token", "client_id": "client-id"},
    )

    token = CloudflareApi(http, "test-token").get_service_token(
        account_id="account-id", service_token_id="token-id"
    )

    assert (token.id, token.name, token.client_id) == ("token-id", "managed-token", "client-id")
    assert not hasattr(token, "client_secret")


def test_exact_service_token_get_rejects_another_identity() -> None:
    http = _HttpResponses()
    http.queue(
        "GET",
        "/accounts/account-id/access/service_tokens/token-id",
        {"id": "other-token", "name": "managed-token", "client_id": "client-id"},
    )

    with pytest.raises(AppError, match="different service token"):
        CloudflareApi(http, "test-token").get_service_token(
            account_id="account-id", service_token_id="token-id"
        )


def test_token_metadata_pagination_covers_all_results() -> None:
    http = _HttpResponses()
    for page in (1, 2):
        path = f"/accounts/account-id/access/service_tokens?page={page}&per_page=1000"
        http.responses[("GET", _API + path)] = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "success": True,
                    "result": [{"id": f"token-{page}", "name": "managed", "client_id": "client"}],
                    "result_info": {"total_pages": 2},
                }
            ),
        )

    tokens = CloudflareApi(http, "test-token").list_service_tokens(account_id="account-id")

    assert tuple(token.id for token in tokens) == ("token-1", "token-2")


@pytest.mark.parametrize("timestamp", ["not-a-date", "2026-10-20", "2026-10-20T10:00:00"])
def test_invalid_tombstone_timestamp_does_not_confirm_deletion(timestamp: str) -> None:
    http = _HttpResponses()
    http.queue("GET", _TUNNEL, _tunnel_payload(deleted_at=timestamp))

    with pytest.raises(AppError, match="timestamp"):
        CloudflareApi(http, "test-token").tunnel_is_deleted(
            account_id="account-id", tunnel_id="tunnel-id"
        )


@pytest.mark.parametrize("status", [200, 400])
def test_api_errors_never_echo_raw_body_or_vendor_message(status: int) -> None:
    http = _HttpResponses()
    http.responses[("GET", _API + _TUNNEL)] = HttpResponse(
        status_code=status,
        body=json.dumps(
            {
                "success": False,
                "errors": [{"code": 10000, "message": "echoed-secret-value"}],
                "request": {"client_secret": "request-secret-value"},
            }
        ),
    )

    with pytest.raises(AppError) as caught:
        CloudflareApi(http, "test-token").get_tunnel(account_id="account-id", tunnel_id="tunnel-id")

    assert caught.value.hints == ("Cloudflare error codes: 10000.",)
    assert "secret-value" not in repr(caught.value)


def test_non_json_api_error_body_is_not_echoed() -> None:
    http = _HttpResponses()
    http.responses[("GET", _API + _TUNNEL)] = HttpResponse(
        status_code=502, body="<html>request-secret-value</html>"
    )

    with pytest.raises(AppError) as caught:
        CloudflareApi(http, "test-token").get_tunnel(account_id="account-id", tunnel_id="tunnel-id")

    assert caught.value.hints == ()
    assert "HTTP 502" in caught.value.message
    assert "request-secret-value" not in repr(caught.value)


class _LocalAcknowledgment(LocalConnectorObserver):
    """Control native evidence while exercising the real replica correlation rule."""

    def __init__(self, *, connector_id: str = "local", version: int = 8) -> None:
        self.connector_id: str = connector_id
        self.version: int = version
        self.tunnel_ids: list[str] = []
        self.unavailable: bool = False

    def observe(self, *, tunnel_id: str) -> LocalConnectorAcknowledgment:
        self.tunnel_ids.append(tunnel_id)
        if self.unavailable:
            raise AppError("Unavailable", code="configuration_application_unobserved")
        return LocalConnectorAcknowledgment(
            connector_id=self.connector_id, configuration_version=self.version, pid=1234
        )


def _require_with_local(api: CloudflareApi, local: _LocalAcknowledgment):
    return require_configuration_applied(
        api,
        account_id="account-id",
        tunnel_id="tunnel-id",
        expected_version=8,
        local_observer=local,
    )


def test_exact_local_acknowledgment_fills_only_that_clients_missing_api_version() -> None:
    local = _LocalAcknowledgment()
    api = _with_clients(
        [
            {"id": "local", "config_version": None, "conns": [{"id": "c1"}]},
            {"id": "foreign", "config_version": 8, "conns": [{"id": "c2"}]},
        ]
    )

    result = _require_with_local(api, local)

    assert result.active_connector_ids == ("local", "foreign")
    assert result.locally_acknowledged_connector_ids == ("local",)
    assert local.tunnel_ids == ["tunnel-id"]


@pytest.mark.parametrize("version", [7, 9])
def test_native_evidence_never_overrides_a_conflicting_remote_version(version: int) -> None:
    local = _LocalAcknowledgment()
    api = _with_clients([{"id": "local", "config_version": version, "conns": [{"id": "c1"}]}])

    with pytest.raises(AppError) as caught:
        _require_with_local(api, local)

    assert caught.value.code == "configuration_application_unobserved"
    assert local.tunnel_ids == []


@pytest.mark.parametrize("version", [7, 9])
def test_native_version_mismatch_stays_unconfirmed(version: int) -> None:
    local = _LocalAcknowledgment(version=version)
    api = _with_clients([{"id": "local", "conns": [{"id": "c1"}]}])

    with pytest.raises(AppError) as caught:
        _require_with_local(api, local)

    assert caught.value.code == "configuration_application_unobserved"


def test_missing_foreign_version_is_not_filled_by_a_local_acknowledgment() -> None:
    local = _LocalAcknowledgment()
    api = _with_clients(
        [
            {"id": "local", "conns": [{"id": "c1"}]},
            {"id": "foreign", "conns": [{"id": "c2"}]},
        ]
    )

    with pytest.raises(AppError) as caught:
        _require_with_local(api, local)

    assert caught.value.data is not None
    assert caught.value.data["connector_id"] == "foreign"
    assert caught.value.data["observed_version"] is None
    assert local.tunnel_ids == ["tunnel-id"]


def test_a_different_ready_native_connector_cannot_stand_in_for_the_api_client() -> None:
    local = _LocalAcknowledgment(connector_id="another-client")
    api = _with_clients([{"id": "local", "conns": [{"id": "c1"}]}])

    with pytest.raises(AppError):
        _require_with_local(api, local)


def test_unavailable_native_evidence_retains_the_unconfirmed_result() -> None:
    local = _LocalAcknowledgment()
    local.unavailable = True
    api = _with_clients([{"id": "local", "conns": [{"id": "c1"}]}])

    with pytest.raises(AppError) as caught:
        _require_with_local(api, local)

    assert caught.value.code == "configuration_application_unobserved"


@pytest.mark.parametrize("clients", [[], [{"id": "local", "conns": []}]])
def test_inactive_clients_do_not_trigger_native_fallback(clients: JsonArray) -> None:
    local = _LocalAcknowledgment()

    result = _require_with_local(_with_clients(clients), local)

    assert result.no_active_connectors
    assert result.locally_acknowledged_connector_ids == ()
    assert local.tunnel_ids == []


def test_missing_connection_observation_cannot_be_replaced_by_native_version() -> None:
    local = _LocalAcknowledgment()

    with pytest.raises(AppError):
        _require_with_local(_with_clients([{"id": "local"}]), local)

    assert local.tunnel_ids == []
