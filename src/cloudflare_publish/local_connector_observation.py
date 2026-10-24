"""Read native connector acknowledgments from its PID-owned loopback listener."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from uuid import UUID

from cloudflare_publish.connector_service import ConnectorService
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient
from cloudflare_publish.json_types import JsonObject, load_json_value, require_object


@dataclass(frozen=True)
class LocalConnectorAcknowledgment:
    """One ready connector's exact native identity and applied configuration version."""

    connector_id: str
    configuration_version: int
    pid: int


class LocalConnectorObserver:
    """Inspect only the canonical native service process, never guessed ports."""

    def __init__(self, launchd: ConnectorService, http: CurlHttpClient) -> None:
        self._launchd: ConnectorService = launchd
        self._http: CurlHttpClient = http

    def observe(self, *, tunnel_id: str) -> LocalConnectorAcknowledgment:
        """Correlate readiness, tunnel identity and config on one owned native server.

        Native cloudflared 2025.4.0 and later provide these endpoints on the same
        metrics listener. `/config` serializes its version and effective ingress
        under one lock, after successful ingress application. This observation is
        not a session-drain barrier or proof that another replica applied anything.
        """

        try:
            pid = self._managed_pid()
            endpoint = self._owned_listener(pid)
            before_id = self._ready_identity(endpoint)
            self._require_tunnel_identity(endpoint, tunnel_id=tunnel_id, connector_id=before_id)
            version = self._configuration_version(endpoint)
            after_id = self._ready_identity(endpoint)
            self._require_tunnel_identity(endpoint, tunnel_id=tunnel_id, connector_id=after_id)
            if before_id != after_id:
                raise _unobserved("The local connector identity changed during observation.")
            if self._managed_pid() != pid or self._owned_listener(pid) != endpoint:
                raise _unobserved("The managed connector process or listener changed.")
        except (AppError, OSError, ValueError) as error:
            # Never echo lsof, diagnostics, arbitrary HTTP bodies, or subprocess
            # output. The retained operation is the recovery owner for this gap.
            raise _unobserved(
                "The managed connector's native acknowledgment is unavailable."
            ) from error
        return LocalConnectorAcknowledgment(
            connector_id=before_id, configuration_version=version, pid=pid
        )

    def _managed_pid(self) -> int:
        service = self._launchd.service()
        if service is None or service.pid is None or service.pid <= 0:
            raise _unobserved("The canonical connector is not running.")
        return service.pid

    def _owned_listener(self, pid: int) -> str:
        binary = self._launchd.which("lsof")
        if binary is None:
            raise _unobserved("PID-owned connector listener discovery requires lsof.")
        result = self._launchd.run(
            [str(binary), "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN", "-Fpn"],
            check=False,
        )
        if result.returncode != 0:
            raise _unobserved("The managed connector listener could not be observed.")
        endpoints = _loopback_listeners(result.stdout, pid=pid)
        if len(endpoints) != 1:
            raise _unobserved("The managed connector has no unique PID-owned loopback listener.")
        return next(iter(endpoints))

    def _get_object(self, endpoint: str, path: str) -> JsonObject:
        response = self._http.get(endpoint + path, max_time=3)
        if response.status_code != 200:
            raise _unobserved("The native connector observation endpoint is unavailable.")
        return require_object(
            load_json_value(response.body, label="Local connector"),
            message="The native connector observation must be a JSON object.",
        )

    def _ready_identity(self, endpoint: str) -> str:
        ready = self._get_object(endpoint, "/ready")
        connections = ready.get("readyConnections")
        if (
            type(ready.get("status")) is not int
            or ready.get("status") != 200
            or type(connections) is not int
            or connections <= 0
        ):
            raise _unobserved("The managed connector does not report ready connections.")
        return _connector_identity(ready, "connectorId")

    def _require_tunnel_identity(self, endpoint: str, *, tunnel_id: str, connector_id: str) -> None:
        diagnostic = self._get_object(endpoint, "/diag/tunnel")
        if (
            diagnostic.get("tunnelID") != tunnel_id
            or _connector_identity(diagnostic, "connectorID") != connector_id
        ):
            raise _unobserved("The native connector does not match this exact tunnel and client.")
        connections = diagnostic.get("connections")
        if not isinstance(connections, list) or not connections:
            raise _unobserved("The native tunnel diagnostic has no observable connections.")
        connected = False
        for connection in connections:
            if not isinstance(connection, dict) or type(connection.get("isConnected")) is not bool:
                raise _unobserved("The native tunnel connection observation is malformed.")
            connected = connected or connection.get("isConnected") is True
        if not connected:
            raise _unobserved("The native tunnel diagnostic has no connected transports.")

    def _configuration_version(self, endpoint: str) -> int:
        snapshot = self._get_object(endpoint, "/config")
        version = snapshot.get("version")
        if type(version) is not int or version < 0:
            raise _unobserved("The native applied configuration version is unavailable.")
        config = snapshot.get("config")
        if not isinstance(config, dict):
            raise _unobserved("The native applied configuration is malformed.")
        ingress = config.get("ingress")
        if not isinstance(ingress, list) or not ingress:
            raise _unobserved("The native applied ingress is unavailable.")
        for rule in ingress:
            if not isinstance(rule, dict) or not isinstance(rule.get("service"), str):
                raise _unobserved("The native applied ingress is malformed.")
        return version


def _loopback_listeners(output: str, *, pid: int) -> set[str]:
    """Decode only the requested lsof PID/name fields and literal loopback sockets."""

    owner: int | None = None
    endpoints: set[str] = set()
    for line in output.splitlines():
        if line.startswith("p"):
            owner = int(line[1:])
            if owner != pid:
                raise _unobserved("Listener discovery returned a different process.")
        elif line.startswith("f"):
            # lsof always emits descriptor fields even for the restricted -Fpn
            # selection. TCP listeners must have numeric descriptors.
            if owner != pid or not line[1:].isdecimal():
                raise _unobserved("Listener discovery returned a malformed descriptor.")
        elif line.startswith("n"):
            if owner != pid:
                raise _unobserved("Listener ownership could not be established.")
            host, separator, raw_port = line[1:].rpartition(":")
            if not separator or not raw_port.isdecimal():
                raise _unobserved("Listener discovery returned a malformed endpoint.")
            address = ip_address(host.removeprefix("[").removesuffix("]"))
            port = int(raw_port)
            if not 1 <= port <= 65535:
                raise _unobserved("Listener discovery returned an invalid port.")
            if address.is_loopback:
                authority = f"[{address}]" if address.version == 6 else str(address)
                endpoints.add(f"http://{authority}:{port}")
        elif line:
            raise _unobserved("Listener discovery returned unexpected fields.")
    return endpoints


def _connector_identity(payload: JsonObject, key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise _unobserved("The native connector identity is unavailable or malformed.")
    return value


def _unobserved(message: str) -> AppError:
    return AppError(message, code="configuration_application_unobserved")
