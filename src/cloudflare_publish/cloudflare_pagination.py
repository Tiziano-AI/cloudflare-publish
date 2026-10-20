"""Shared pagination helpers for Cloudflare API list endpoints."""

from __future__ import annotations

from typing import Protocol
from urllib.parse import urlencode

from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import (
    JsonArray,
    JsonObject,
    JsonValue,
    require_array,
    require_object,
)


class JsonPageLoader(Protocol):
    """Load one Cloudflare JSON envelope for a fully encoded list path."""

    def __call__(self, path: str) -> JsonObject:
        """Return one decoded Cloudflare envelope for a list path."""

        ...


def collect_result_pages(
    *,
    load_page: JsonPageLoader,
    path: str,
    query: dict[str, str] | None,
    per_page: int,
) -> JsonArray:
    """Return the concatenated paginated result array for one Cloudflare list endpoint."""

    page = 1
    items: JsonArray = []
    while True:
        current_query: dict[str, str] = {"page": str(page), "per_page": str(per_page)}
        if query is not None:
            current_query.update(query)
        payload = load_page(build_query_path(path, current_query))
        page_items = require_array(
            payload.get("result"),
            message="Cloudflare API result must be an array.",
        )
        items.extend(page_items)
        total_pages = total_pages_from_result_info(payload.get("result_info"))
        if total_pages is not None:
            if page >= total_pages:
                return items
        elif len(page_items) < per_page:
            return items
        page += 1


def build_query_path(path: str, query: dict[str, str]) -> str:
    """Build an API path with encoded query parameters."""

    return f"{path}?{urlencode(query)}"


def total_pages_from_result_info(payload: JsonValue | None) -> int | None:
    """Return the paginated total-page count when present."""

    if payload is None:
        return None
    result_info = require_object(payload, message="Cloudflare API result_info must be an object.")
    total_pages = result_info.get("total_pages")
    if total_pages is None:
        return None
    if not isinstance(total_pages, int):
        raise AppError("Cloudflare API result_info.total_pages must be an integer.")
    return total_pages
