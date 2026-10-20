"""Canonical JSON value algebra and decoding helpers."""

from __future__ import annotations

import json

from cloudflare_publish.errors import AppError

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | JsonArray | JsonObject
type JsonArray = list[JsonValue]
type JsonObject = dict[str, JsonValue]


def parse_json_value(text: str) -> JsonValue:
    """Parse JSON text into the canonical JSON value algebra."""

    return json.loads(text)


def load_json_value(text: str, *, label: str) -> JsonValue:
    """Parse JSON text and wrap decode failures with a contextual app error."""

    try:
        return parse_json_value(text)
    except json.JSONDecodeError as error:
        raise AppError(f"{label} did not return valid JSON.") from error


def require_object(payload: JsonValue, *, message: str) -> JsonObject:
    """Require a JSON object."""

    if not isinstance(payload, dict):
        raise AppError(message)
    return payload


def require_array(payload: JsonValue, *, message: str) -> JsonArray:
    """Require a JSON array."""

    if not isinstance(payload, list):
        raise AppError(message)
    return payload
