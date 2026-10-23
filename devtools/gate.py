#!/usr/bin/env python3
"""Canonical local gate runner for cloudflare-publish."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    """Run the repo gate and return a process exit code."""

    repo_root = Path(__file__).resolve().parents[1]
    commands = [
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "ruff", "format", "--check", "."],
        ["npm", "run", "typecheck"],
        [sys.executable, "-m", "pytest"],
        ["bash", "-n", "bin/cloudflare-publish"],
        ["./bin/cloudflare-publish", "--help"],
        [sys.executable, "devtools/validate_package.py"],
    ]
    for command in commands:
        _run(command, cwd=repo_root)
    if shutil.which("shellcheck") is not None:
        _run(["shellcheck", "bin/cloudflare-publish"], cwd=repo_root)
    else:
        _ = sys.stdout.write("SKIP shellcheck (not installed locally)\n")
    if shutil.which("shfmt") is not None:
        _run(["shfmt", "-d", "bin/cloudflare-publish"], cwd=repo_root)
    else:
        _ = sys.stdout.write("SKIP shfmt (not installed locally)\n")
    return 0


def _run(command: list[str], *, cwd: Path) -> None:
    """Run a gate command and stop on the first failure."""

    _ = sys.stdout.write(f"+ {' '.join(command)}\n")
    completed = subprocess.run(command, cwd=cwd, env=dict(os.environ), check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
