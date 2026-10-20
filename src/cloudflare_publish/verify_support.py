"""Shared verification helpers for policy, redirect, and error contracts."""

from __future__ import annotations

from urllib.parse import urlsplit

from cloudflare_publish.cloudflare_contract import policy_include_signature
from cloudflare_publish.errors import AppError
from cloudflare_publish.http import HttpResponse
from cloudflare_publish.json_types import JsonArray
from cloudflare_publish.models import CheckResult, ManagedPublication


def build_expected_policy_contracts(publication: ManagedPublication) -> tuple[str, ...]:
    """Return the canonical expected Access policy contract signatures."""

    signatures: list[str] = []
    if publication.spec.audience in {"human", "mixed"}:
        signatures.append(
            _serialize_policy_contract(
                precedence=1,
                decision="allow",
                include=_human_policy_include(publication),
            )
        )
    if publication.spec.audience in {"machine", "mixed"}:
        token_id = publication.state.service_token_id
        if token_id is None:
            raise AppError("Machine-access publication state is missing a service token ID.")
        machine_include: JsonArray = [{"service_token": {"token_id": token_id}}]
        signatures.append(
            _serialize_policy_contract(
                precedence=2,
                decision="non_identity",
                include=policy_include_signature(machine_include),
            )
        )
    return tuple(signatures)


def failed_check(label: str, error: AppError) -> CheckResult:
    """Return a failed verification check from one user-facing app error."""

    return CheckResult(label, ok=False, detail=render_error_detail(error))


def render_error_detail(error: AppError) -> str:
    """Render one compact AppError detail string."""

    if not error.hints:
        return error.message
    return f"{error.message} {' '.join(error.hints)}"


def is_denied_or_access_redirect(*, response: HttpResponse, auth_domain: str) -> bool:
    """Return whether the anonymous live response is an Access deny or auth redirect."""

    if response.status_code in {401, 403}:
        return True
    if response.status_code < 300 or response.status_code >= 400:
        return False
    location = response.headers.get("location")
    if location is None:
        return False
    return urlsplit(location).hostname == auth_domain


def live_response_detail(response: HttpResponse) -> str:
    """Return a compact live-response detail string."""

    location = response.headers.get("location")
    if location is None:
        return f"HTTP {response.status_code}"
    return f"HTTP {response.status_code} -> {location}"


def default_port(scheme: str) -> int:
    """Return the canonical default TCP port for one HTTP scheme."""

    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    raise AppError(f"Unsupported origin URL scheme: {scheme!r}.")


def netloc(host: str, port: int | None) -> str:
    """Return the URL netloc for one host and optional port."""

    bracketed_host = f"[{host}]" if ":" in host else host
    if port is None:
        return bracketed_host
    return f"{bracketed_host}:{port}"


def serialize_policy_contract(
    *,
    precedence: int | None,
    decision: str,
    include: tuple[str, ...],
) -> str:
    """Serialize one expected or actual Access policy contract."""

    return _serialize_policy_contract(precedence=precedence, decision=decision, include=include)


def _human_policy_include(publication: ManagedPublication) -> tuple[str, ...]:
    """Return the canonical human-policy include signature for one publication."""

    include: JsonArray = []
    for email in publication.spec.allowed_emails:
        include.append({"email": {"email": email}})
    for domain in publication.spec.allowed_email_domains:
        include.append({"email_domain": {"domain": domain}})
    return policy_include_signature(include)


def _serialize_policy_contract(
    *,
    precedence: int | None,
    decision: str,
    include: tuple[str, ...],
) -> str:
    """Serialize one expected or actual Access policy contract."""

    precedence_text = "none" if precedence is None else str(precedence)
    return f"{precedence_text}:{decision}:{'|'.join(include)}"
