"""Live-verification origin TLS option coverage."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_verify_models_effective_tunnel_tls_origin_options(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fail missing TLS origin options and pass originServerName and noTLSVerify branches."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "secure",
                "--yes",
                "--hostname",
                "secure.example.com",
                "--to",
                "https://127.0.0.1:8443",
                "--audience",
                "machine",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["--json", "verify", "secure", "--live"], repo_root=fake_environment.repo_root) == 1
    failed = json.loads(capsys.readouterr().out)
    checks = {check["label"]: check for check in failed["data"]["checks"]}
    assert checks["secure: origin reachable"]["detail"] == "HTTP 526"
    assert checks["secure: authenticated request succeeds"]["detail"].startswith("HTTP 526")

    assert (
        main(
            [
                "publish",
                "apply",
                "secure",
                "--yes",
                "--hostname",
                "secure.example.com",
                "--to",
                "https://127.0.0.1:8443",
                "--audience",
                "machine",
                "--origin-server-name",
                "tls.internal",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["--json", "verify", "secure", "--live"], repo_root=fake_environment.repo_root) == 0
    origin_server_name_passed = json.loads(capsys.readouterr().out)
    checks = {check["label"]: check for check in origin_server_name_passed["data"]["checks"]}
    assert checks["secure: origin reachable"]["ok"] is True
    assert checks["secure: authenticated request succeeds"]["ok"] is True

    assert (
        main(
            [
                "publish",
                "apply",
                "insecure",
                "--yes",
                "--hostname",
                "insecure.example.com",
                "--to",
                "https://127.0.0.1:8443",
                "--audience",
                "machine",
                "--no-tls-verify",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert (
        main(["--json", "verify", "insecure", "--live"], repo_root=fake_environment.repo_root) == 0
    )
    no_tls_verify_passed = json.loads(capsys.readouterr().out)
    checks = {check["label"]: check for check in no_tls_verify_passed["data"]["checks"]}
    assert checks["insecure: origin reachable"]["ok"] is True
    assert checks["insecure: authenticated request succeeds"]["ok"] is True


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
