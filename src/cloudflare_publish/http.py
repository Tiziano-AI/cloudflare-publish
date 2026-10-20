"""HTTP transport implemented through the external `curl` binary."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from cloudflare_publish.errors import AppError
from cloudflare_publish.process import CommandRunner


@dataclass(frozen=True)
class HttpConnectToEntry:
    """One curl `--connect-to` mapping for request-host preservation."""

    request_host: str
    request_port: int
    connect_host: str
    connect_port: int


@dataclass(frozen=True)
class HttpResponse:
    """Captured HTTP status and body from a curl request."""

    status_code: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


class CurlHttpClient:
    """Runs HTTP requests through `curl` for deterministic operator parity."""

    def __init__(self, runner: CommandRunner) -> None:
        """Store the shared command runner."""

        self._runner: CommandRunner = runner

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
        """Send a GET request."""

        return self.request(
            url=url,
            method="GET",
            headers=headers or {},
            json_body=None,
            max_time=max_time,
            follow_redirects=follow_redirects,
            insecure=insecure,
            connect_to=connect_to,
        )

    def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: str,
        max_time: int = 30,
        follow_redirects: bool = False,
        insecure: bool = False,
        connect_to: tuple[HttpConnectToEntry, ...] = (),
    ) -> HttpResponse:
        """Send a JSON POST request."""

        return self.request(
            url=url,
            method="POST",
            headers=dict(headers or {}),
            json_body=json_body,
            max_time=max_time,
            follow_redirects=follow_redirects,
            insecure=insecure,
            connect_to=connect_to,
        )

    def put_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: str,
        max_time: int = 30,
        insecure: bool = False,
        connect_to: tuple[HttpConnectToEntry, ...] = (),
    ) -> HttpResponse:
        """Send a JSON PUT request."""

        return self.request(
            url=url,
            method="PUT",
            headers=dict(headers or {}),
            json_body=json_body,
            max_time=max_time,
            follow_redirects=False,
            insecure=insecure,
            connect_to=connect_to,
        )

    def delete(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_time: int = 30,
        insecure: bool = False,
        connect_to: tuple[HttpConnectToEntry, ...] = (),
    ) -> HttpResponse:
        """Send a DELETE request."""

        return self.request(
            url=url,
            method="DELETE",
            headers=headers or {},
            json_body=None,
            max_time=max_time,
            follow_redirects=False,
            insecure=insecure,
            connect_to=connect_to,
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
        """Send an HTTP request and capture status plus body."""

        with tempfile.TemporaryDirectory(prefix="cloudflare-publish-") as temp_dir:
            body_file = Path(temp_dir) / "body.txt"
            header_file = Path(temp_dir) / "headers.txt"
            request_header_file = Path(temp_dir) / "request-headers.txt"
            request_json_file = Path(temp_dir) / "request.json"
            command = [
                "curl",
                # This must be the first option: operator curlrc files must not
                # change credential handling, redirects, TLS, or probe results.
                "-q",
                "--silent",
                "--show-error",
                "--max-time",
                str(max_time),
                "--output",
                str(body_file),
                "--dump-header",
                str(header_file),
                "--write-out",
                "%{http_code}",
                "--request",
                method,
            ]
            # Native loopback observations must reach this process, not a proxy
            # inherited from the operator's shell. Do not resolve hostnames.
            hostname = urlsplit(url).hostname
            if hostname is not None:
                try:
                    loopback = ip_address(hostname).is_loopback
                except ValueError:
                    loopback = False
                if loopback:
                    command.extend(["--noproxy", hostname])
            if follow_redirects:
                command.append("--location")
            if insecure:
                command.append("--insecure")
            if headers:
                _ = request_header_file.write_text(
                    _render_header_file(headers),
                    encoding="utf-8",
                )
                request_header_file.chmod(0o600)
                command.extend(["--header", f"@{request_header_file}"])
            for entry in connect_to:
                command.extend(
                    [
                        "--connect-to",
                        (
                            f"{entry.request_host}:{entry.request_port}:"
                            f"{entry.connect_host}:{entry.connect_port}"
                        ),
                    ]
                )
            if json_body is not None:
                _ = request_json_file.write_text(json_body, encoding="utf-8")
                request_json_file.chmod(0o600)
                command.extend(["--json", f"@{request_json_file}"])
            command.append(url)
            result = self._runner.run(command, check=False)
            body = body_file.read_text(encoding="utf-8") if body_file.exists() else ""
            header_text = header_file.read_text(encoding="utf-8") if header_file.exists() else ""
            if result.returncode != 0:
                detail = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or f"exit code {result.returncode}"
                )
                raise AppError(f"curl failed for {method} {url}.", hints=(detail,))
            status_text = result.stdout.strip()
            if not status_text.isdigit():
                detail = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or f"exit code {result.returncode}"
                )
                raise AppError(f"curl failed for {method} {url}.", hints=(detail,))
            return HttpResponse(
                status_code=int(status_text),
                body=body,
                headers=_parse_headers(header_text),
            )


def _parse_headers(text: str) -> dict[str, str]:
    """Parse the final HTTP response header block from curl output."""

    headers: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line:
            continue
        if line.startswith("HTTP/"):
            headers = {}
            continue
        key, separator, value = line.partition(":")
        if not separator:
            continue
        headers[key.strip().lower()] = value.strip()
    return headers


def _render_header_file(headers: dict[str, str]) -> str:
    """Render curl headers into a temporary request file without argv secret exposure."""

    lines: list[str] = []
    for key, value in headers.items():
        if _contains_header_break(key) or _contains_header_break(value):
            raise AppError("HTTP headers must not contain line breaks.")
        lines.append(f"{key}: {value}")
    return "\n".join(lines) + "\n"


def _contains_header_break(value: str) -> bool:
    """Return whether a header key or value contains a forbidden line break."""

    return "\n" in value or "\r" in value
