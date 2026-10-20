"""Live-verification host-header behavior coverage."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_verify_models_effective_tunnel_host_header(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fail when the origin rejects the public Host header and pass with an override."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "ollama",
                "--yes",
                "--hostname",
                "ollama.example.com",
                "--to",
                "http://127.0.0.1:11434",
                "--audience",
                "machine",
                "--verify-path",
                "/api/tags",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["--json", "verify", "ollama", "--live"], repo_root=fake_environment.repo_root) == 1
    failed = json.loads(capsys.readouterr().out)
    assert failed["output_class"] == "evidence_error"
    checks = {check["label"]: check for check in failed["data"]["checks"]}
    authenticated = checks["ollama: authenticated request succeeds"]
    assert authenticated["ok"] is False
    assert "HTTP 403" in authenticated["detail"]
    assert "Set --http-host-header" in authenticated["detail"]

    assert (
        main(
            [
                "publish",
                "apply",
                "ollama",
                "--yes",
                "--hostname",
                "ollama.example.com",
                "--to",
                "http://127.0.0.1:11434",
                "--audience",
                "machine",
                "--verify-path",
                "/api/tags",
                "--http-host-header",
                "127.0.0.1",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["--json", "verify", "ollama", "--live"], repo_root=fake_environment.repo_root) == 0
    passed = json.loads(capsys.readouterr().out)
    passed_checks = {check["label"]: check for check in passed["data"]["checks"]}
    assert passed_checks["ollama: authenticated request succeeds"]["ok"] is True


def _setup(fake_environment: FakeEnvironment) -> int:
    """Run the common initial manager setup."""

    return main(
        [
            "setup",
            "--api-token",
            "token-1",
            "--account-id",
            "acc-123",
            "--zone",
            "example.com",
        ],
        repo_root=fake_environment.repo_root,
    )
