"""Select the supported native host without environment-based manager switching."""

from __future__ import annotations

import sys
from typing import Literal

from cloudflare_publish.errors import AppError

HostPlatform = Literal["darwin", "linux"]


def host_platform(platform: str | None = None) -> HostPlatform:
    """Require one supported OS; explicit injection is for callers and hermetic tests."""

    selected = sys.platform if platform is None else platform
    if selected == "darwin":
        return "darwin"
    if selected == "linux":
        return "linux"
    raise AppError("Only macOS and Linux hosts are supported.", code="unsupported_platform")
