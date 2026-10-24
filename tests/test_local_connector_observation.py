"""Native identity/version evidence must remain tied to one owned local process."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient, HttpConnectToEntry, HttpResponse
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.launchd import Launchd, LaunchdService
from cloudflare_publish.local_connector_observation import LocalConnectorObserver
from cloudflare_publish.models import CANONICAL_LABEL
from cloudflare_publish.process import CommandResult

_CONNECTOR = "11111111-1111-4111-8111-111111111111"
_OTHER = "22222222-2222-4222-8222-222222222222"
_TUNNEL = "33333333-3333-4333-8333-333333333333"
_ENDPOINT = "http://127.0.0.1:49152"
_LISTENER = "p1234\nf3\nn127.0.0.1:49152\n"


class _OwnedProcess(Launchd):
    def __init__(self) -> None:
        self.pids: list[int | None] = [1234, 1234]
        self.listeners: list[str] = [_LISTENER, _LISTENER]
        self.commands: list[list[str]] = []
        self.lsof_status: int = 0

    def service(self, label: str = CANONICAL_LABEL) -> LaunchdService | None:
        assert label == CANONICAL_LABEL
        return LaunchdService(label=label, pid=self.pids.pop(0), status=0)

    def which(self, program: str) -> Path | None:
        assert program == "lsof"
        return Path("/usr/sbin/lsof")

    def run(
        self, command: list[str], *, check: bool = True, input_text: str | None = None
    ) -> CommandResult:
        assert check is False
        assert input_text is None
        self.commands.append(command)
        return CommandResult(
            command=tuple(command),
            returncode=self.lsof_status,
            stdout=self.listeners.pop(0),
            stderr="private diagnostic not for errors",
        )


class _NativeHttp(CurlHttpClient):
    def __init__(self) -> None:
        self.endpoint: str = _ENDPOINT
        ready: JsonObject = {"status": 200, "readyConnections": 4, "connectorId": _CONNECTOR}
        diagnostic: JsonObject = {
            "tunnelID": _TUNNEL,
            "connectorID": _CONNECTOR,
            "connections": [{"isConnected": True}],
        }
        config: JsonObject = {
            "version": 14,
            "config": {"ingress": [{"hostname": "", "service": "http_status:404"}]},
        }
        self.responses: dict[str, list[HttpResponse]] = {
            "/ready": [self.response(ready), self.response(ready)],
            "/diag/tunnel": [self.response(diagnostic), self.response(diagnostic)],
            "/config": [self.response(config)],
        }
        self.requests: list[str] = []

    @staticmethod
    def response(value: JsonObject) -> HttpResponse:
        return HttpResponse(status_code=200, body=json.dumps(value))

    def replace(self, path: str, value: JsonObject, *, status: int = 200) -> None:
        self.responses[path] = [HttpResponse(status_code=status, body=json.dumps(value))]

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
        assert url.startswith(self.endpoint)
        assert headers is None
        assert max_time == 3
        assert not follow_redirects and not insecure and not connect_to
        self.requests.append(url)
        return self.responses[url.removeprefix(self.endpoint)].pop(0)


def test_native_observation_correlates_exact_identity_and_applied_version() -> None:
    process = _OwnedProcess()
    http = _NativeHttp()

    result = LocalConnectorObserver(process, http).observe(tunnel_id=_TUNNEL)

    assert (result.connector_id, result.configuration_version, result.pid) == (_CONNECTOR, 14, 1234)
    assert http.requests == [
        _ENDPOINT + path for path in ["/ready", "/diag/tunnel", "/config", "/ready", "/diag/tunnel"]
    ]
    assert (
        process.commands
        == [["/usr/sbin/lsof", "-nP", "-a", "-p", "1234", "-iTCP", "-sTCP:LISTEN", "-Fpn"]] * 2
    )


@pytest.mark.parametrize("pid", [None, 0, -1])
def test_unloaded_or_invalid_managed_pid_does_not_guess_a_port(pid: int | None) -> None:
    process = _OwnedProcess()
    process.pids = [pid]
    http = _NativeHttp()

    with pytest.raises(AppError) as caught:
        LocalConnectorObserver(process, http).observe(tunnel_id=_TUNNEL)

    assert caught.value.code == "configuration_application_unobserved"
    assert process.commands == []
    assert http.requests == []


@pytest.mark.parametrize(
    "listener",
    [
        "",
        "p4321\nn127.0.0.1:49152\n",
        "n127.0.0.1:49152\n",
        "p1234\nn10.0.0.1:49152\n",
        "p1234\nn*:49152\n",
        "p1234\nn127.0.0.1:0\n",
        "p1234\nn127.0.0.1:not-port\n",
        "p1234\nfnot-numeric\nn127.0.0.1:49152\n",
        "unexpected\n" + _LISTENER,
        _LISTENER + "n127.0.0.1:49153\n",
    ],
)
def test_no_unowned_nonloopback_ambiguous_or_malformed_listener_is_probed(listener: str) -> None:
    process = _OwnedProcess()
    process.listeners = [listener]
    http = _NativeHttp()

    with pytest.raises(AppError):
        LocalConnectorObserver(process, http).observe(tunnel_id=_TUNNEL)

    assert http.requests == []


def test_failed_lsof_does_not_echo_private_command_output() -> None:
    process = _OwnedProcess()
    process.lsof_status = 1

    with pytest.raises(AppError) as caught:
        LocalConnectorObserver(process, _NativeHttp()).observe(tunnel_id=_TUNNEL)

    assert "private diagnostic" not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"status": 200, "readyConnections": 0, "connectorId": _CONNECTOR},
        {"status": 200, "readyConnections": True, "connectorId": _CONNECTOR},
        {"status": 503, "readyConnections": 4, "connectorId": _CONNECTOR},
        {"status": 200, "readyConnections": 4},
        {"status": 200, "readyConnections": 4, "connectorId": "not-a-uuid"},
    ],
)
def test_readiness_requires_positive_native_identity_and_connections(payload: JsonObject) -> None:
    http = _NativeHttp()
    http.replace("/ready", payload)

    with pytest.raises(AppError):
        LocalConnectorObserver(_OwnedProcess(), http).observe(tunnel_id=_TUNNEL)


@pytest.mark.parametrize(
    "payload",
    [
        {"tunnelID": _OTHER, "connectorID": _CONNECTOR, "connections": [{"isConnected": True}]},
        {"tunnelID": _TUNNEL, "connectorID": _OTHER, "connections": [{"isConnected": True}]},
        {"tunnelID": _TUNNEL, "connectorID": _CONNECTOR, "connections": []},
        {"tunnelID": _TUNNEL, "connectorID": _CONNECTOR, "connections": [{"isConnected": False}]},
        {"tunnelID": _TUNNEL, "connectorID": _CONNECTOR, "connections": [{}]},
    ],
)
def test_diagnostic_must_correlate_this_tunnel_and_connector(payload: JsonObject) -> None:
    http = _NativeHttp()
    http.replace("/diag/tunnel", payload)

    with pytest.raises(AppError):
        LocalConnectorObserver(_OwnedProcess(), http).observe(tunnel_id=_TUNNEL)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": None, "config": {}},
        {"version": True, "config": {}},
        {"version": -1, "config": {}},
        {"version": "14", "config": {}},
        {"version": 14},
        {"version": 14, "config": {"ingress": []}},
        {"version": 14, "config": {"ingress": [{}]}},
    ],
)
def test_absent_or_malformed_native_config_never_supplies_a_version(payload: JsonObject) -> None:
    http = _NativeHttp()
    http.replace("/config", payload)

    with pytest.raises(AppError):
        LocalConnectorObserver(_OwnedProcess(), http).observe(tunnel_id=_TUNNEL)


def test_connector_pid_change_invalidates_the_observation() -> None:
    process = _OwnedProcess()
    process.pids = [1234, 5678]

    with pytest.raises(AppError):
        LocalConnectorObserver(process, _NativeHttp()).observe(tunnel_id=_TUNNEL)


def test_connector_listener_change_invalidates_the_observation() -> None:
    process = _OwnedProcess()
    process.listeners[1] = "p1234\nn127.0.0.1:49153\n"

    with pytest.raises(AppError):
        LocalConnectorObserver(process, _NativeHttp()).observe(tunnel_id=_TUNNEL)


def test_pid_owned_ipv6_loopback_listener_is_supported_without_guessing_ipv4() -> None:
    process = _OwnedProcess()
    process.listeners = ["p1234\nf3\nn[::1]:49152\n"] * 2
    http = _NativeHttp()
    http.endpoint = "http://[::1]:49152"

    result = LocalConnectorObserver(process, http).observe(tunnel_id=_TUNNEL)

    assert result.connector_id == _CONNECTOR
    assert all(url.startswith("http://[::1]:49152/") for url in http.requests)


def test_changed_ready_identity_does_not_reuse_an_earlier_config_read() -> None:
    http = _NativeHttp()
    http.responses["/ready"][1] = http.response(
        {"status": 200, "readyConnections": 4, "connectorId": _OTHER}
    )
    http.responses["/diag/tunnel"][1] = http.response(
        {"tunnelID": _TUNNEL, "connectorID": _OTHER, "connections": [{"isConnected": True}]}
    )

    with pytest.raises(AppError):
        LocalConnectorObserver(_OwnedProcess(), http).observe(tunnel_id=_TUNNEL)


@pytest.mark.parametrize("path", ["/ready", "/diag/tunnel", "/config"])
def test_unavailable_native_endpoints_do_not_echo_arbitrary_bodies(path: str) -> None:
    http = _NativeHttp()
    http.responses[path] = [HttpResponse(status_code=500, body="private-body-not-for-output")]

    with pytest.raises(AppError) as caught:
        LocalConnectorObserver(_OwnedProcess(), http).observe(tunnel_id=_TUNNEL)

    assert "private-body" not in repr(caught.value)
