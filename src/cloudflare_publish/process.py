"""Process execution helpers for external tool adapters."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.errors import AppError


@dataclass(frozen=True)
class CommandResult:
    """Captured result from an external process execution."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    """Runs external commands through a single typed surface."""

    def which(self, program: str) -> Path | None:
        """Resolve a program on PATH."""

        location = shutil.which(program)
        if location is None:
            return None
        return Path(location)

    def run(
        self,
        command: list[str],
        *,
        check: bool = True,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Run a command and optionally fail with a typed error."""

        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            cwd=cwd,
            env=_build_env(env),
            input=input_text,
            text=True,
        )
        result = CommandResult(
            command=tuple(command),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and result.returncode != 0:
            detail = (
                result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
            )
            raise AppError(f"Command failed: {' '.join(command)}", hints=(detail,))
        return result


def _build_env(overrides: Mapping[str, str] | None) -> dict[str, str]:
    """Create the child environment map for a command execution."""

    environment = dict(os.environ)
    if overrides is not None:
        environment.update(overrides)
    return environment
