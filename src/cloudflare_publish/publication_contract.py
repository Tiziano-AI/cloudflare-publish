"""Validation helpers for publication input and response expectations."""

from __future__ import annotations

import re
from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit, urlunsplit

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import (
    DEFAULT_EXPECT_STATUS,
    DEFAULT_VERIFY_PATH,
    OriginOptions,
    PublicationSpec,
    PublishRequest,
)
from cloudflare_publish.ssh import validate_ssh_host_key

_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HOSTNAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_STATUS_PATTERN = re.compile(r"^(?P<start>[1-5][0-9][0-9])-(?P<end>[1-5][0-9][0-9])$")


def build_publication_spec(request: PublishRequest) -> PublicationSpec:
    """Validate CLI publication input and build the canonical spec."""

    name = _normalize_name(request.name)
    hostname = _normalize_hostname(request.hostname)
    origin_url = _normalize_origin_url(request.origin_url)
    audience = _normalize_audience(request.audience)
    if urlsplit(origin_url).scheme == "ssh":
        return _build_ssh_spec(
            request, name=name, hostname=hostname, origin_url=origin_url, audience=audience
        )
    if request.ssh_host_key is not None:
        raise AppError("--ssh-host-key is only valid for SSH origins.")
    allowed_emails = tuple(_normalize_email_list(request.allowed_emails))
    allowed_email_domains = tuple(_normalize_domain_list(request.allowed_email_domains))
    if audience in {"human", "mixed"} and not allowed_emails and not allowed_email_domains:
        raise AppError(
            "Human-access publications require at least one --allow-email or --allow-domain value."
        )
    if audience == "public" and (allowed_emails or allowed_email_domains):
        raise AppError("Public publications must not include Access allow rules.")
    verify_path = _normalize_verify_path(request.verify_path)
    expect_status = _normalize_expect_status(request.expect_status)
    return PublicationSpec(
        kind="http_public",
        name=name,
        hostname=hostname,
        origin_url=origin_url,
        audience=audience,
        allowed_emails=allowed_emails,
        allowed_email_domains=allowed_email_domains,
        verify_path=verify_path,
        expect_status=expect_status,
        origin_options=OriginOptions(
            http_host_header=_normalize_optional_hostname(request.http_host_header),
            origin_server_name=_normalize_optional_hostname(request.origin_server_name),
            no_tls_verify=request.no_tls_verify,
        ),
    )


def _build_ssh_spec(
    request: PublishRequest, *, name: str, hostname: str, origin_url: str, audience: str
) -> PublicationSpec:
    """Build a machine-only SSH publication with an explicit server identity."""

    if audience != "machine":
        raise AppError("SSH publications require --audience machine.")
    if request.allowed_emails or request.allowed_email_domains:
        raise AppError("SSH publications must not include human Access allow rules.")
    if (
        any(
            value is not None
            for value in (
                request.verify_path,
                request.expect_status,
                request.http_host_header,
                request.origin_server_name,
            )
        )
        or request.no_tls_verify
    ):
        raise AppError("SSH publications must not include HTTP verification or origin options.")
    if request.ssh_host_key is None:
        raise AppError(
            "SSH publications require --ssh-host-key with the server's public Ed25519 key."
        )
    return PublicationSpec(
        kind="ssh_public",
        name=name,
        hostname=hostname,
        origin_url=origin_url,
        audience=audience,
        allowed_emails=(),
        allowed_email_domains=(),
        verify_path=None,
        expect_status=None,
        origin_options=OriginOptions(
            http_host_header=None, origin_server_name=None, no_tls_verify=False
        ),
        ssh_host_key=validate_ssh_host_key(request.ssh_host_key),
    )


def ensure_hostname_within_zone(*, hostname: str, zone_name: str) -> None:
    """Require the publication hostname to belong to the configured zone."""

    if hostname == zone_name:
        return
    if hostname.endswith(f".{zone_name}"):
        return
    raise AppError(
        f"Hostname {hostname!r} does not belong to configured zone {zone_name!r}.",
    )


def parse_status_range(spec: str) -> tuple[int, int]:
    """Parse and validate a closed inclusive HTTP status range."""

    matched = _STATUS_PATTERN.fullmatch(spec)
    if matched is None:
        raise AppError("Status ranges must use the form `200-399`.")
    start = int(matched.group("start"))
    end = int(matched.group("end"))
    if start > end:
        raise AppError("Status ranges must be ascending.")
    return start, end


def status_matches_range(spec: str, status_code: int) -> bool:
    """Return whether an HTTP status code falls within a configured range."""

    lower, upper = parse_status_range(spec)
    return lower <= status_code <= upper


def service_token_keychain_account(name: str) -> str:
    """Return the canonical opaque store account for one publication token."""

    return f"service-token:{name}"


def _normalize_name(value: str) -> str:
    """Validate and normalize the publication name."""

    name = value.strip().lower()
    if not _NAME_PATTERN.fullmatch(name):
        raise AppError(
            "Publication names must be lowercase slugs made of letters, digits, and hyphens."
        )
    return name


def _normalize_hostname(value: str) -> str:
    """Validate and normalize an exact public hostname."""

    hostname = value.strip().lower()
    if not hostname or "*" in hostname or "/" in hostname or "://" in hostname:
        raise AppError("Hostnames must be exact hostnames with no wildcard, path, or scheme.")
    return _normalize_dns_hostname(hostname, require_dot=True, label="Hostname")


def _normalize_origin_url(value: str) -> str:
    """Validate an HTTP, HTTPS or SSH origin URL without embedded credentials."""

    try:
        parts = urlsplit(value.strip())
    except ValueError as error:
        raise AppError("Origin URLs must use a valid host and TCP port.") from error
    if parts.scheme not in {"http", "https", "ssh"}:
        raise AppError("Origin URLs must use http://, https:// or ssh://.")
    if parts.username is not None or parts.password is not None:
        raise AppError("Origin URLs must not embed credentials.")
    if not parts.netloc or parts.hostname is None:
        raise AppError("Origin URLs must include a host and optional port.")
    if parts.path not in {"", "/"}:
        raise AppError("Origin URLs must not include a path.")
    if parts.query or parts.fragment:
        raise AppError("Origin URLs must not include a query or fragment.")
    host = _normalize_host_or_ip(parts.hostname, require_dot=False, label="Origin URL host")
    try:
        port = parts.port
    except ValueError as error:
        raise AppError("Origin URLs must use a valid TCP port.") from error
    if port is not None and port < 1:
        raise AppError("Origin URLs must use a valid TCP port.")
    netloc = _netloc_with_port(host, port)
    return urlunsplit(
        SplitResult(
            scheme=parts.scheme,
            netloc=netloc,
            path="",
            query="",
            fragment="",
        )
    )


def _normalize_audience(value: str) -> str:
    """Validate the publication audience mode."""

    audience = value.strip().lower()
    if audience not in {"human", "machine", "mixed", "public"}:
        raise AppError("Audience must be one of: human, machine, mixed, public.")
    return audience


def _normalize_email_list(values: tuple[str, ...]) -> list[str]:
    """Normalize and deduplicate email values."""

    normalized = {_normalize_email(item) for item in values}
    return sorted(normalized)


def _normalize_domain_list(values: tuple[str, ...]) -> list[str]:
    """Normalize and deduplicate email-domain values."""

    normalized = {_normalize_domain(item) for item in values}
    return sorted(normalized)


def _normalize_email(value: str) -> str:
    """Validate one email address."""

    email = value.strip().lower()
    if not _EMAIL_PATTERN.fullmatch(email):
        raise AppError(f"Invalid email value: {value!r}.")
    return email


def _normalize_domain(value: str) -> str:
    """Validate one domain name."""

    domain = value.strip().lower()
    try:
        return _normalize_dns_hostname(domain, require_dot=True, label="Email domain")
    except AppError as error:
        raise AppError(f"Invalid email domain value: {value!r}.") from error


def _normalize_verify_path(value: str | None) -> str:
    """Normalize the publication verification path."""

    path = DEFAULT_VERIFY_PATH if value is None or not value.strip() else value
    if not path.startswith("/"):
        raise AppError("Verification paths must begin with '/'.")
    if "?" in path or "#" in path:
        raise AppError("Verification paths must not include a query or fragment.")
    if path != path.strip() or any(character.isspace() for character in path):
        raise AppError("Verification paths must not include whitespace.")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise AppError("Verification paths must not include control characters.")
    return path


def _normalize_expect_status(value: str | None) -> str:
    """Normalize the expected verification status range."""

    status_spec = DEFAULT_EXPECT_STATUS if value is None or not value.strip() else value.strip()
    _ = parse_status_range(status_spec)
    return status_spec


def _normalize_optional_hostname(value: str | None) -> str | None:
    """Normalize an optional host header or SNI name."""

    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return _normalize_dns_hostname(
        stripped.lower(),
        require_dot=False,
        label="Origin host override",
    )


def _normalize_host_or_ip(value: str, *, require_dot: bool, label: str) -> str:
    """Normalize one host value that may be an IP literal or hostname."""

    try:
        _ = ip_address(value)
    except ValueError:
        return _normalize_dns_hostname(value.lower(), require_dot=require_dot, label=label)
    return value.lower()


def _normalize_dns_hostname(value: str, *, require_dot: bool, label: str) -> str:
    """Normalize and validate one DNS hostname."""

    if value.endswith("."):
        raise AppError(f"{label} must not end with a trailing dot.")
    if not _HOSTNAME_PATTERN.fullmatch(value):
        raise AppError(f"{label} must be a valid hostname.")
    labels = value.split(".")
    if require_dot and len(labels) < 2:
        raise AppError(f"{label} must be a dotted hostname.")
    for item in labels:
        if not _NAME_PATTERN.fullmatch(item):
            raise AppError(f"{label} must use valid DNS labels.")
    return value


def _netloc_with_port(host: str, port: int | None) -> str:
    """Return a URL netloc for one host and optional port."""

    bracketed_host = f"[{host}]" if ":" in host else host
    if port is None:
        return bracketed_host
    return f"{bracketed_host}:{port}"
