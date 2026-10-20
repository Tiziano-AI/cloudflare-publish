"""Fake curl binary script body for hermetic CLI tests."""

from __future__ import annotations

from tests.fake_curl_script_api import FAKE_CURL_API_PART
from tests.fake_curl_script_public import FAKE_CURL_PUBLIC_PART


def curl_script() -> str:
    """Return the fake curl helper script."""

    return FAKE_CURL_API_PART + FAKE_CURL_PUBLIC_PART
