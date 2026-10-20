"""Human-readable console output helpers."""

from __future__ import annotations

import sys

from cloudflare_publish.models import CheckResult


class Console:
    """Writes stable human-readable CLI output without using print()."""

    def line(self, text: str = "") -> None:
        """Write a single line to stdout."""

        _ = sys.stdout.write(f"{text}\n")

    def section(self, title: str) -> None:
        """Write a section heading."""

        self.line(f"== {title} ==")

    def note(self, text: str) -> None:
        """Write a secondary informational line."""

        self.line(f"  {text}")

    def error(self, text: str) -> None:
        """Write a single line to stderr."""

        _ = sys.stderr.write(f"ERROR: {text}\n")

    def show_check(self, result: CheckResult) -> None:
        """Render a local or live verification check result."""

        prefix = "[OK]" if result.ok else "[FAIL]"
        identity = "" if result.hostname is None else f" ({result.hostname})"
        self.line(f"{prefix} {result.label}{identity}")
        if result.detail is not None:
            self.note(result.detail)
