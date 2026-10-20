"""HTTP transport command-shape regression tests."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import override

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.http import CurlHttpClient, HttpConnectToEntry
from cloudflare_publish.process import CommandResult, CommandRunner


class _RecordingRunner(CommandRunner):
    """Command runner that records one request and returns a fake success response."""

    def __init__(self) -> None:
        """Initialize the recorded command slot."""

        super().__init__()
        self.recorded_command: tuple[str, ...] | None = None

    @override
    def run(
        self,
        command: list[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Record the curl command and write a fake HTTP response body."""

        del check, cwd, env, input_text
        self.recorded_command = tuple(command)
        output_path = Path(command[command.index("--output") + 1])
        _ = output_path.write_text('{"success":true,"result":{}}', encoding="utf-8")
        header_path = Path(command[command.index("--dump-header") + 1])
        _ = header_path.write_text(
            "HTTP/1.1 200\r\nLocation: https://example.com\r\n\r\n",
            encoding="utf-8",
        )
        return CommandResult(
            command=tuple(command),
            returncode=0,
            stdout="200",
            stderr="",
        )


class _FailingRunner(CommandRunner):
    """Command runner that simulates one curl transport failure."""

    @override
    def run(
        self,
        command: list[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Return a non-zero curl exit while still emitting the synthetic `000` status."""

        del command, check, cwd, env, input_text
        return CommandResult(
            command=("curl",),
            returncode=7,
            stdout="000",
            stderr="Failed to connect",
        )


def test_post_json_uses_curl_json_file_and_header_file() -> None:
    """JSON mutators keep secrets out of argv by passing curl temp files."""

    runner = _RecordingRunner()
    client = CurlHttpClient(runner)

    _ = client.post_json(
        "https://api.cloudflare.com/client/v4/accounts/acc/cfd_tunnel",
        headers={"Authorization": "Bearer token-value"},
        json_body='{"name":"demo"}',
    )

    command = runner.recorded_command
    assert command is not None
    assert "--json" in command
    assert "--data" not in command
    assert "--dump-header" in command
    assert "--header" in command
    assert "Authorization: Bearer token-value" not in command
    assert '{"name":"demo"}' not in command
    assert any(item.startswith("@") for item in command)


def test_get_uses_connect_to_mapping_when_requested() -> None:
    """Origin verification can preserve request host while connecting elsewhere."""

    runner = _RecordingRunner()
    client = CurlHttpClient(runner)

    _ = client.get(
        "https://origin.example.com/health",
        connect_to=(
            HttpConnectToEntry(
                request_host="origin.example.com",
                request_port=443,
                connect_host="127.0.0.1",
                connect_port=8443,
            ),
        ),
    )

    command = runner.recorded_command
    assert command is not None
    assert "--connect-to" in command
    assert "origin.example.com:443:127.0.0.1:8443" in command


def test_transport_failures_do_not_collapse_into_http_zero() -> None:
    """Curl transport failures surface the real error instead of a synthetic HTTP 0."""

    client = CurlHttpClient(_FailingRunner())

    with pytest.raises(AppError, match="curl failed"):
        _ = client.get("http://127.0.0.1:9")


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "[::1]"])
def test_literal_loopback_requests_bypass_environment_proxies(host: str) -> None:
    """Identity-bound native observations never traverse an inherited proxy."""

    runner = _RecordingRunner()
    _ = CurlHttpClient(runner).get(f"http://{host}:20241/ready")
    command = runner.recorded_command
    assert command is not None
    assert command[command.index("--noproxy") + 1] == host.strip("[]")
    assert command[:2] == ("curl", "-q")


@pytest.mark.parametrize("host", ["api.cloudflare.com", "localhost.example.com", "192.0.2.1"])
def test_other_requests_preserve_operator_proxy_selection(host: str) -> None:
    """The local-only exception does not disable normal remote proxy policy."""

    runner = _RecordingRunner()
    _ = CurlHttpClient(runner).get(f"https://{host}/")
    assert runner.recorded_command is not None
    assert "--noproxy" not in runner.recorded_command
