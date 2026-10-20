"""Focused inspect-command regression coverage."""

from __future__ import annotations

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_inspect_renders_operator_contract_without_secrets(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Inspect renders the local publication contract without machine-token secrets."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "dashboard",
                "--yes",
                "--hostname",
                "dashboard.example.com",
                "--to",
                "https://127.0.0.1:8443",
                "--audience",
                "mixed",
                "--allow-domain",
                "example.com",
                "--verify-path",
                "/healthz",
                "--expect-status",
                "200-204",
                "--http-host-header",
                "dashboard.internal",
                "--origin-server-name",
                "origin.internal",
                "--no-tls-verify",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["inspect", "dashboard"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Public verify URL: https://dashboard.example.com/healthz" in captured.out
    assert "Origin: https://127.0.0.1:8443" in captured.out
    assert "Audience: mixed" in captured.out
    assert "Verify path: /healthz" in captured.out
    assert "Expect status: 200-204" in captured.out
    assert "Allowed domains: example.com" in captured.out
    assert "Origin Host header: dashboard.internal" in captured.out
    assert "Origin server name: origin.internal" in captured.out
    assert "Origin TLS verification: disabled" in captured.out
    assert "Service token client ID: client-token-1" in captured.out
    assert "Service token client secret" not in captured.out
    assert "secret-" not in captured.out


def test_inspect_reports_tls_not_applicable_for_plain_http(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Inspect does not imply TLS verification exists for plain HTTP origins."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "grafana",
                "--yes",
                "--hostname",
                "grafana.example.com",
                "--to",
                "http://127.0.0.1:3000",
                "--audience",
                "machine",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    _ = capsys.readouterr()

    assert main(["inspect", "grafana"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Origin: http://127.0.0.1:3000" in captured.out
    assert "Origin TLS verification: not applicable" in captured.out


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
