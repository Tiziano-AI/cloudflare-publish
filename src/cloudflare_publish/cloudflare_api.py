"""Cloudflare REST adapter built on top of the shared curl transport."""

from __future__ import annotations

import json
from datetime import datetime

from cloudflare_publish.cloudflare_contract import (
    AccessApplicationRef,
    AccessDiscoveryRef,
    AccessPolicyRef,
    AccountRef,
    DnsRecordRef,
    OrganizationRef,
    ServiceTokenRef,
    ServiceTokenSecret,
    TunnelClientRef,
    TunnelConfigurationRef,
    TunnelRef,
    ZoneRef,
    access_application_from_object,
    access_application_from_value,
    access_discovery_from_value,
    access_policy_from_object,
    access_policy_from_value,
    account_from_value,
    cloudflare_error_hints,
    dns_record_from_object,
    dns_record_from_value,
    organization_from_object,
    service_token_from_object,
    service_token_ref_from_object,
    service_token_ref_from_value,
    tunnel_client_from_value,
    tunnel_cname,
    tunnel_configuration_from_object,
    tunnel_from_object,
    tunnel_from_value,
    zone_from_value,
)
from cloudflare_publish.cloudflare_pagination import collect_result_pages
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient, HttpResponse
from cloudflare_publish.json_types import (
    JsonArray,
    JsonObject,
    load_json_value,
    require_object,
)

_API_ROOT = "https://api.cloudflare.com/client/v4"


class CloudflareApi:
    """Execute typed Cloudflare API requests through curl."""

    def __init__(self, http: CurlHttpClient, api_token: str) -> None:
        """Store the shared HTTP client and bearer token."""

        self._http: CurlHttpClient = http
        self._api_token: str = api_token

    def list_accounts(self) -> tuple[AccountRef, ...]:
        """List accounts visible to the current API token."""

        items = self._result_array_pages("/accounts", per_page=50)
        return tuple(account_from_value(item) for item in items)

    def list_zones(self, *, name: str | None = None) -> tuple[ZoneRef, ...]:
        """List zones visible to the current API token."""

        query: dict[str, str] = {}
        if name is not None:
            query["name"] = name
        items = self._result_array_pages("/zones", query=query, per_page=50)
        return tuple(zone_from_value(item) for item in items)

    def list_tunnels(self, *, account_id: str) -> tuple[TunnelRef, ...]:
        """List tunnels owned by one account."""

        items = self._result_array_pages(f"/accounts/{account_id}/cfd_tunnel", per_page=1000)
        return tuple(tunnel_from_value(item) for item in items)

    def get_tunnel(self, *, account_id: str, tunnel_id: str) -> TunnelRef:
        """Fetch one tunnel by ID."""

        payload = self._result_object(self._get(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}"))
        return tunnel_from_object(payload)

    def create_tunnel(self, *, account_id: str, name: str) -> TunnelRef:
        """Create a remotely managed tunnel."""

        payload = self._result_object(
            self._post(
                f"/accounts/{account_id}/cfd_tunnel",
                {"name": name, "config_src": "cloudflare"},
            )
        )
        tunnel = tunnel_from_object(payload)
        if not tunnel.remote_config:
            raise AppError("Cloudflare returned a non-remote tunnel for a remote-managed request.")
        return tunnel

    def delete_tunnel(self, *, account_id: str, tunnel_id: str, missing_ok: bool = False) -> None:
        """Delete a managed tunnel."""

        self._require_success(
            self._delete(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}"),
            missing_ok=missing_ok,
        )

    def tunnel_is_deleted(self, *, account_id: str, tunnel_id: str) -> bool:
        """Confirm exact tunnel deletion, never inferring it from an offline connector."""

        response = self._get(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}")
        # The vendor documents no endpoint-specific not-found code. A generic 404
        # can also conceal an authorization or routing failure and is not a barrier.
        tunnel = tunnel_from_object(self._result_object(response))
        if tunnel.id != tunnel_id:
            raise AppError("Cloudflare returned a different tunnel for deletion confirmation.")
        if not tunnel.deleted_at:
            return False
        try:
            deleted_at = datetime.fromisoformat(tunnel.deleted_at)
        except ValueError as exc:
            raise AppError("Cloudflare returned an invalid tunnel deletion timestamp.") from exc
        if deleted_at.tzinfo is None:
            raise AppError("Cloudflare returned a tunnel deletion timestamp without a time zone.")
        return True

    def get_tunnel_token(self, *, account_id: str, tunnel_id: str) -> str:
        """Fetch the runtime token for a remotely managed tunnel."""

        payload = self._request_json(
            self._http.get(
                self._url(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"),
                headers=self._headers(),
            )
        )
        result = payload.get("result")
        if not isinstance(result, str):
            raise AppError("Cloudflare tunnel token response did not include a string token.")
        return result

    def cleanup_tunnel_connections(self, *, account_id: str, tunnel_id: str) -> None:
        """Delete every active connector for one shared tunnel."""

        self._require_success(
            self._delete(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections")
        )

    def get_tunnel_configuration(self, *, account_id: str, tunnel_id: str) -> JsonObject:
        """Fetch the remotely managed tunnel configuration object."""

        return self.get_tunnel_configuration_snapshot(
            account_id=account_id, tunnel_id=tunnel_id
        ).config

    def get_tunnel_configuration_snapshot(
        self, *, account_id: str, tunnel_id: str
    ) -> TunnelConfigurationRef:
        """Fetch the stored configuration and its version as one API observation."""

        payload = self._result_object(
            self._get(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations")
        )
        return tunnel_configuration_from_object(payload)

    def list_tunnel_connections(
        self, *, account_id: str, tunnel_id: str
    ) -> tuple[TunnelClientRef, ...]:
        """List every observed connector, preserving unknown configuration versions."""

        items = self._result_array_pages(
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections", per_page=1000
        )
        return tuple(tunnel_client_from_value(item) for item in items)

    def update_tunnel_configuration(
        self,
        *,
        account_id: str,
        tunnel_id: str,
        configuration: JsonObject,
    ) -> int | None:
        """Replace the configuration and return only the version actually observed."""

        payload = self._result_object(
            self._put(
                f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                configuration,
            )
        )
        return tunnel_configuration_from_object(payload).version

    def list_dns_records(
        self, *, zone_id: str, name: str | None = None
    ) -> tuple[DnsRecordRef, ...]:
        """List DNS records for a zone, optionally filtered by name."""

        query: dict[str, str] = {}
        if name is not None:
            query["name"] = name
        items = self._result_array_pages(
            f"/zones/{zone_id}/dns_records", query=query, per_page=1000
        )
        return tuple(dns_record_from_value(item) for item in items)

    def create_dns_record(self, *, zone_id: str, hostname: str, tunnel_id: str) -> DnsRecordRef:
        """Create a proxied CNAME to the shared tunnel."""

        payload = self._result_object(
            self._post(
                f"/zones/{zone_id}/dns_records",
                {
                    "type": "CNAME",
                    "name": hostname,
                    "content": tunnel_cname(tunnel_id),
                    "proxied": True,
                },
            )
        )
        return dns_record_from_object(payload)

    def update_dns_record(
        self,
        *,
        zone_id: str,
        record_id: str,
        hostname: str,
        tunnel_id: str,
    ) -> DnsRecordRef:
        """Update a managed proxied CNAME."""

        payload = self._result_object(
            self._put(
                f"/zones/{zone_id}/dns_records/{record_id}",
                {
                    "type": "CNAME",
                    "name": hostname,
                    "content": tunnel_cname(tunnel_id),
                    "proxied": True,
                },
            )
        )
        return dns_record_from_object(payload)

    def delete_dns_record(self, *, zone_id: str, record_id: str, missing_ok: bool = False) -> None:
        """Delete one managed DNS record."""

        self._require_success(
            self._delete(f"/zones/{zone_id}/dns_records/{record_id}"),
            missing_ok=missing_ok,
        )

    def list_access_applications(self, *, account_id: str) -> tuple[AccessApplicationRef, ...]:
        """List account-scoped Access applications."""

        items = self._result_array_pages(f"/accounts/{account_id}/access/apps", per_page=1000)
        return tuple(access_application_from_value(item) for item in items)

    def list_access_discovery(self, *, account_id: str) -> tuple[AccessDiscoveryRef, ...]:
        """Read allowlisted targeting fields without requiring every app to be public."""

        items = self._result_array_pages(f"/accounts/{account_id}/access/apps", per_page=1000)
        return tuple(access_discovery_from_value(item) for item in items)

    def get_access_application(
        self, *, account_id: str, application_id: str
    ) -> AccessApplicationRef:
        """Fetch one Access application."""

        payload = self._result_object(
            self._get(f"/accounts/{account_id}/access/apps/{application_id}")
        )
        return access_application_from_object(payload)

    def create_access_application(
        self,
        *,
        account_id: str,
        name: str,
        hostname: str,
    ) -> AccessApplicationRef:
        """Create a self-hosted Access application for one public hostname."""

        payload = self._result_object(
            self._post(
                f"/accounts/{account_id}/access/apps",
                {
                    "name": name,
                    "domain": hostname,
                    "type": "self_hosted",
                    "app_launcher_visible": False,
                    "destinations": [{"type": "public", "uri": hostname}],
                    "service_auth_401_redirect": True,
                },
            )
        )
        return access_application_from_object(payload)

    def update_access_application(
        self,
        *,
        account_id: str,
        application_id: str,
        name: str,
        hostname: str,
    ) -> AccessApplicationRef:
        """Update a self-hosted Access application in place."""

        payload = self._result_object(
            self._put(
                f"/accounts/{account_id}/access/apps/{application_id}",
                {
                    "name": name,
                    "domain": hostname,
                    "type": "self_hosted",
                    "app_launcher_visible": False,
                    "destinations": [{"type": "public", "uri": hostname}],
                    "service_auth_401_redirect": True,
                },
            )
        )
        return access_application_from_object(payload)

    def delete_access_application(
        self,
        *,
        account_id: str,
        application_id: str,
        missing_ok: bool = False,
    ) -> None:
        """Delete a managed Access application."""

        self._require_success(
            self._delete(f"/accounts/{account_id}/access/apps/{application_id}"),
            missing_ok=missing_ok,
        )

    def list_access_policies(
        self,
        *,
        account_id: str,
        application_id: str,
        missing_ok: bool = False,
    ) -> tuple[AccessPolicyRef, ...]:
        """List policies attached to one Access application."""

        items = self._result_array_pages(
            f"/accounts/{account_id}/access/apps/{application_id}/policies",
            per_page=200,
            missing_ok=missing_ok,
        )
        return tuple(access_policy_from_value(item) for item in items)

    def create_access_policy(
        self,
        *,
        account_id: str,
        application_id: str,
        name: str,
        decision: str,
        include: JsonArray,
        precedence: int,
    ) -> AccessPolicyRef:
        """Create one Access application policy."""

        payload = self._result_object(
            self._post(
                f"/accounts/{account_id}/access/apps/{application_id}/policies",
                {
                    "name": name,
                    "decision": decision,
                    "include": include,
                    "precedence": precedence,
                },
            )
        )
        return access_policy_from_object(payload)

    def delete_access_policy(
        self,
        *,
        account_id: str,
        application_id: str,
        policy_id: str,
        missing_ok: bool = False,
    ) -> None:
        """Delete one Access application policy."""

        self._require_success(
            self._delete(
                f"/accounts/{account_id}/access/apps/{application_id}/policies/{policy_id}"
            ),
            missing_ok=missing_ok,
        )

    def create_service_token(self, *, account_id: str, name: str) -> ServiceTokenSecret:
        """Create a service token and return the only-available client secret."""

        payload = self._result_object(
            self._post(
                f"/accounts/{account_id}/access/service_tokens",
                {"name": name, "duration": "8760h"},
            )
        )
        return service_token_from_object(payload)

    def list_service_tokens(self, *, account_id: str) -> tuple[ServiceTokenRef, ...]:
        """List recoverable token metadata without returning client secrets."""

        items = self._result_array_pages(
            f"/accounts/{account_id}/access/service_tokens", per_page=1000
        )
        return tuple(service_token_ref_from_value(item) for item in items)

    def get_service_token(self, *, account_id: str, service_token_id: str) -> ServiceTokenRef:
        """Fetch exact token metadata; the vendor does not recover its client secret."""

        payload = self._result_object(
            self._get(f"/accounts/{account_id}/access/service_tokens/{service_token_id}")
        )
        token = service_token_ref_from_object(payload)
        if token.id != service_token_id:
            raise AppError("Cloudflare returned a different service token for the requested ID.")
        return token

    def rotate_service_token(self, *, account_id: str, service_token_id: str) -> ServiceTokenSecret:
        """Rotate a service token client secret."""

        payload = self._result_object(
            self._post(
                f"/accounts/{account_id}/access/service_tokens/{service_token_id}/rotate",
                {},
            )
        )
        return service_token_from_object(payload)

    def delete_service_token(
        self,
        *,
        account_id: str,
        service_token_id: str,
        missing_ok: bool = False,
    ) -> None:
        """Delete one service token."""

        self._require_success(
            self._delete(f"/accounts/{account_id}/access/service_tokens/{service_token_id}"),
            missing_ok=missing_ok,
        )

    def get_organization(self, *, account_id: str) -> OrganizationRef:
        """Fetch the current Zero Trust organization settings."""

        payload = self._result_object(self._get(f"/accounts/{account_id}/access/organizations"))
        return organization_from_object(payload)

    def update_organization(
        self,
        *,
        account_id: str,
        payload: JsonObject,
    ) -> OrganizationRef:
        """Update account-level default-deny protection."""

        payload = self._result_object(
            self._put(
                f"/accounts/{account_id}/access/organizations",
                payload,
            )
        )
        return organization_from_object(payload)

    def _headers(self) -> dict[str, str]:
        """Return the canonical authorization header map."""

        return {"Authorization": f"Bearer {self._api_token}"}

    def _get(self, path: str) -> HttpResponse:
        """Send an authenticated GET request."""

        return self._http.get(self._url(path), headers=self._headers())

    def _post(self, path: str, payload: JsonObject) -> HttpResponse:
        """Send an authenticated JSON POST request."""

        return self._http.post_json(
            self._url(path),
            headers=self._headers(),
            json_body=json.dumps(payload),
        )

    def _put(self, path: str, payload: JsonObject) -> HttpResponse:
        """Send an authenticated JSON PUT request."""
        return self._http.put_json(
            self._url(path),
            headers=self._headers(),
            json_body=json.dumps(payload),
        )

    def _delete(self, path: str) -> HttpResponse:
        """Send an authenticated DELETE request."""
        return self._http.delete(self._url(path), headers=self._headers())

    def _request_json(self, response: HttpResponse) -> JsonObject:
        """Parse a Cloudflare API response envelope."""
        if response.status_code < 200 or response.status_code >= 300:
            try:
                error_payload = load_json_value(response.body, label="Cloudflare API")
            except AppError:
                error_payload = None
            raise AppError(
                f"Cloudflare API request failed with HTTP {response.status_code}.",
                hints=cloudflare_error_hints(error_payload)
                if isinstance(error_payload, dict)
                else (),
            )
        payload = require_object(
            load_json_value(response.body, label="Cloudflare API"),
            message="Cloudflare API did not return a JSON object.",
        )
        success_value = payload.get("success")
        if success_value is False:
            raise AppError(
                "Cloudflare API reported failure.", hints=cloudflare_error_hints(payload)
            )
        return payload

    def _result_object(self, response: HttpResponse) -> JsonObject:
        """Return a typed object result from an API envelope."""
        payload = self._request_json(response)
        return require_object(
            payload.get("result"), message="Cloudflare API result must be an object."
        )

    def _require_success(self, response: HttpResponse, *, missing_ok: bool = False) -> None:
        """Require a success envelope for endpoints whose result is not otherwise consumed."""
        if missing_ok and response.status_code == 404:
            return
        _ = self._request_json(response)

    def _result_array_pages(
        self,
        path: str,
        *,
        query: dict[str, str] | None = None,
        per_page: int,
        missing_ok: bool = False,
    ) -> JsonArray:
        """Return the concatenated paginated result array for one API list endpoint."""
        load_page = self._load_missing_ok_page_json if missing_ok else self._load_page_json
        return collect_result_pages(load_page=load_page, path=path, query=query, per_page=per_page)

    def _url(self, path: str) -> str:
        """Build a fully-qualified API URL."""

        return f"{_API_ROOT}{path}"

    def _load_page_json(self, path: str) -> JsonObject:
        """Load one Cloudflare JSON envelope for a paginated list path."""

        return self._request_json(self._get(path))

    def _load_missing_ok_page_json(self, path: str) -> JsonObject:
        """Load one paginated list path and turn 404 into an empty page."""

        response = self._get(path)
        if response.status_code == 404:
            return {"result": [], "result_info": {"total_pages": 1}}
        return self._request_json(response)
