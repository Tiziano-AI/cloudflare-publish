"""Observe connector application of one exact stored configuration version."""

from __future__ import annotations

from dataclasses import dataclass

from cloudflare_publish.cloudflare_api import CloudflareApi
from cloudflare_publish.errors import AppError
from cloudflare_publish.local_connector_observation import (
    LocalConnectorAcknowledgment,
    LocalConnectorObserver,
)


@dataclass(frozen=True)
class ConfigurationApplicationObservation:
    """A connector-list snapshot, not a lock or proof that sessions were drained."""

    expected_version: int
    active_connector_ids: tuple[str, ...]
    inactive_connector_ids: tuple[str, ...]
    locally_acknowledged_connector_ids: tuple[str, ...] = ()

    @property
    def no_active_connectors(self) -> bool:
        """Whether the snapshot observed no connector transport connections."""

        return not self.active_connector_ids


def require_configuration_applied(
    api: CloudflareApi,
    *,
    account_id: str,
    tunnel_id: str,
    expected_version: int | None,
    local_observer: LocalConnectorObserver | None = None,
) -> ConfigurationApplicationObservation:
    """Require every connected replica to report the exact target config version.

    A listed replica with no transport connections is inactive. An absent connection
    list is unknown rather than inactive. Reconnecting connections remain relevant:
    they are not evidence that this replica can no longer serve its old configuration.
    An empty result observes no active replicas; it does not prove a running local
    connector applied the configuration. Callers needing that stronger outcome must
    separately establish the local connector's presence.

    When the API omits a connected replica's version, the canonical PID-owned native
    server may supply it only for the exact correlated local connector identity.
    This never replaces a conflicting reported API version or another replica's
    missing version. The caller must first compare the complete remote configuration
    with its effective managed projection and use that snapshot's version.
    """

    if expected_version is None:
        raise AppError(
            "Cloudflare did not report the configuration version to observe.",
            code="configuration_application_unobserved",
            hints=("The pending operation must remain recoverable; no cleanup is confirmed.",),
        )
    if type(expected_version) is not int or expected_version < 0:
        raise AppError("The expected tunnel configuration version must be a nonnegative integer.")
    clients = api.list_tunnel_connections(account_id=account_id, tunnel_id=tunnel_id)
    seen: set[str] = set()
    active: list[str] = []
    inactive: list[str] = []
    local_acknowledgment: LocalConnectorAcknowledgment | None = None
    local_ids: list[str] = []
    for client in clients:
        if client.id in seen:
            raise AppError(
                "Cloudflare reported duplicate connector identities.",
                code="configuration_application_unobserved",
            )
        seen.add(client.id)
        if client.connections is None:
            raise AppError(
                "A connector's active connections could not be observed.",
                code="configuration_application_unobserved",
                data={"connector_id": client.id, "expected_version": expected_version},
            )
        if not client.connections:
            inactive.append(client.id)
            continue
        active.append(client.id)
        observed_version = client.config_version
        if observed_version is None and local_observer is not None:
            if local_acknowledgment is None:
                local_acknowledgment = local_observer.observe(tunnel_id=tunnel_id)
            if local_acknowledgment.connector_id == client.id:
                observed_version = local_acknowledgment.configuration_version
                local_ids.append(client.id)
        if observed_version != expected_version:
            raise AppError(
                "Not every active connector reports the target configuration version.",
                code="configuration_application_unobserved",
                hints=(
                    "Resume the same operation after connector application is observable.",
                    "Configuration application does not revoke tokens or drain existing sessions.",
                ),
                data={
                    "connector_id": client.id,
                    "expected_version": expected_version,
                    "observed_version": observed_version,
                },
            )
    return ConfigurationApplicationObservation(
        expected_version=expected_version,
        active_connector_ids=tuple(active),
        inactive_connector_ids=tuple(inactive),
        locally_acknowledged_connector_ids=tuple(local_ids),
    )
