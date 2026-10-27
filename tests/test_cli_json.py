"""JSON-first CLI contract coverage."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from cloudflare_publish.cli import main
from cloudflare_publish.cli_output import write_json_error
from cloudflare_publish.errors import AppError
from tests.fake_environment import FakeEnvironment


def test_help_shows_major_capability_groups(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Top-level help exposes the PATH-global command families and JSON mode."""

    with pytest.raises(SystemExit) as exit_info:
        main(["--help"], repo_root=fake_environment.repo_root)

    assert exit_info.value.code == 0
    captured = capsys.readouterr()
    assert "--json" in captured.out
    for command in (
        "doctor",
        "discover",
        "publish",
        "apply",
        "ls",
        "inspect",
        "verify",
        "repair",
        "service",
        "tunnel",
        "rm",
        "token",
        "guard",
        "teardown",
    ):
        assert command in captured.out

    with pytest.raises(SystemExit) as apply_exit_info:
        main(["publish", "apply", "--help"], repo_root=fake_environment.repo_root)

    assert apply_exit_info.value.code == 0
    apply_help = capsys.readouterr()
    assert "--yes" in apply_help.out


def test_doctor_json_reports_missing_state_without_crashing(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Doctor remains diagnostic when auth and manager state are missing."""

    assert main(["--json", "doctor"], repo_root=fake_environment.repo_root) == 0

    payload = _json_payload(capsys)
    assert payload["ok"] is True
    assert payload["command"] == "doctor"
    assert payload["data"]["ready"] is False
    assert payload["data"]["auth_source"] == "missing"
    checks = payload["data"]["checks"]
    labels = {check["label"]: check for check in checks}
    assert labels["state.json exists"]["ok"] is False
    assert labels["api token available"]["ok"] is False


def test_doctor_json_reports_private_dotenv_auth_without_leaking_token(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Doctor reports local app-slice auth as metadata only."""

    fake_environment.write_private_dotenv({"CLOUDFLARE_API_TOKEN": "token-1"})

    assert main(["--json", "doctor"], repo_root=fake_environment.repo_root) == 0

    stdout = capsys.readouterr().out
    assert "token-1" not in stdout
    payload = json.loads(stdout)
    assert payload["ok"] is True
    assert payload["data"]["auth_source"] == "private_dotenv"
    labels = {check["label"]: check for check in payload["data"]["checks"]}
    assert labels["api token available"]["detail"] == "private_dotenv"


def test_missing_subcommand_error_uses_public_terms(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Usage errors do not expose internal argparse destination names."""

    assert main(["discover"], repo_root=fake_environment.repo_root) == 2

    captured = capsys.readouterr()
    assert "discover subcommand" in captured.err
    assert "discover_command" not in captured.err


def test_raw_api_command_is_removed(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Raw Cloudflare API commands are rejected before any HTTP call."""

    before_state = fake_environment.tool_state()

    assert main(["--json", "--api-token", "token-1", "api", "get", "/accounts"]) == 2

    payload = _json_payload(capsys)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "usage_error"
    assert fake_environment.tool_state() == before_state


def test_read_commands_emit_stable_json_schemas(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Local read commands serialize stable public contracts without secrets."""

    assert _setup(fake_environment) == 0
    assert _publish_machine(fake_environment, json_mode=False) == 0
    _ = capsys.readouterr()

    for command in (["ls"], ["inspect", "grafana"], ["service", "status"], ["guard", "status"]):
        assert main(["--json", *command], repo_root=fake_environment.repo_root) == 0
        payload = _json_payload(capsys)
        assert payload["ok"] is True
        assert payload["data"]

    assert main(["--json", "verify"], repo_root=fake_environment.repo_root) == 0
    verify = _json_payload(capsys)
    assert verify["data"]["failures"] == 0
    assert verify["data"]["checks"]

    assert main(["--json", "inspect", "grafana"], repo_root=fake_environment.repo_root) == 0
    inspect_stdout = capsys.readouterr().out
    assert "secret-1" not in inspect_stdout
    inspect_payload = json.loads(inspect_stdout)
    assert inspect_payload["data"]["publication"]["spec"]["name"] == "grafana"


def test_verify_json_failure_preserves_executed_check_evidence(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verification failures that run checks return evidence data and a nonzero exit."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflared_version"] = "cloudflared version 2026.10.2"
    fake_environment.write_tool_state(tool_state)
    _ = capsys.readouterr()

    assert main(["--json", "verify"], repo_root=fake_environment.repo_root) == 1

    payload = _json_payload(capsys)
    assert payload["ok"] is False
    assert payload["output_class"] == "evidence_error"
    assert payload["error"]["code"] == "verify_failed"
    assert payload["data"]["failures"] >= 1
    labels = {check["label"]: check for check in payload["data"]["checks"]}
    assert labels["cloudflared meets security minimum"]["ok"] is False


def test_verify_json_missing_manager_remains_public_diagnostic(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing manager state is a normal JSON error and does not invent check evidence."""

    assert main(["--json", "verify"], repo_root=fake_environment.repo_root) == 1

    payload = _json_payload(capsys)
    assert payload["ok"] is False
    assert payload["output_class"] == "public_diagnostic"
    assert payload["error"]["code"] == "app_error"
    assert "data" not in payload


def test_plan_commands_do_not_mutate_state(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Plan commands validate and report effects without touching local or fake remote state."""

    assert _setup(fake_environment) == 0
    _ = capsys.readouterr()
    before_tool_state = deepcopy(fake_environment.tool_state())
    before_manifest = _manifest_text(fake_environment)

    assert (
        main(
            [
                "--json",
                "publish",
                "plan",
                "grafana",
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
    publish_plan = _json_payload(capsys)
    assert publish_plan["data"]["plan"] is True
    assert publish_plan["data"]["mode"] == "create"
    assert fake_environment.tool_state() == before_tool_state
    assert _manifest_text(fake_environment) == before_manifest

    assert _publish_machine(fake_environment, json_mode=False) == 0
    _ = capsys.readouterr()
    before_tool_state = deepcopy(fake_environment.tool_state())
    before_manifest = _manifest_text(fake_environment)

    assert (
        main(
            [
                "--json",
                "publish",
                "plan",
                "grafana",
                "--hostname",
                "grafana.example.com",
                "--to",
                "http://127.0.0.1:3001",
                "--audience",
                "machine",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    update_plan = _json_payload(capsys)
    assert update_plan["data"]["mode"] == "update"
    assert "http://127.0.0.1:3001" in json.dumps(update_plan["data"]["tunnel_configuration"])
    assert fake_environment.tool_state() == before_tool_state
    assert _manifest_text(fake_environment) == before_manifest

    for command in (
        ["rm", "plan", "grafana"],
        ["guard", "plan"],
        ["tunnel", "recover", "plan"],
        ["repair", "plan"],
    ):
        assert main(["--json", *command], repo_root=fake_environment.repo_root) == 0
        plan = _json_payload(capsys)
        assert plan["data"]["plan"] is True or plan["data"]["action"] == "repair plan"
        assert fake_environment.tool_state() == before_tool_state
        assert _manifest_text(fake_environment) == before_manifest


def test_json_credential_handoff_is_limited_to_explicit_success_commands(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """JSON secrets appear only on successful publish and token-rotate handoff commands."""

    assert _setup(fake_environment) == 0
    _ = capsys.readouterr()

    assert _publish_machine(fake_environment, json_mode=True) == 0
    publish_stdout = capsys.readouterr().out
    assert "secret-1" in publish_stdout
    publish_payload = json.loads(publish_stdout)
    assert publish_payload["output_class"] == "credential_handoff"
    assert (
        publish_payload["data"]["credential_handoff"]["service_token"]["client_secret"]
        == "secret-1"
    )
    assert "service_token_client_secret" not in json.dumps(publish_payload["data"]["publication"])

    assert main(["--json", "inspect", "grafana"], repo_root=fake_environment.repo_root) == 0
    inspect_stdout = capsys.readouterr().out
    assert "secret-1" not in inspect_stdout

    assert main(["--json", "token", "rotate", "grafana"], repo_root=fake_environment.repo_root) == 1
    denied_stdout = capsys.readouterr().out
    assert "secret-1" not in denied_stdout
    denied = json.loads(denied_stdout)
    assert denied["error"]["code"] == "confirmation_required"

    assert (
        main(
            ["--json", "token", "rotate", "grafana", "--yes"],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    rotated = _json_payload(capsys)
    assert rotated["output_class"] == "credential_handoff"
    assert rotated["data"]["service_token"]["client_secret"] == "secret-2"


def test_json_error_renderer_redacts_credentials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Machine-readable errors redact bearer, dotenv, and service-token secret shapes."""

    write_json_error(
        command="test",
        error=AppError(
            "Bearer token-1 failed with client_secret=secret-2 and CLOUDFLARE_API_TOKEN=token-7",
            hints=("CF-Access-Client-Secret: secret-3",),
        ),
    )

    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert payload["ok"] is False
    assert "token-1" not in stdout
    assert "secret-2" not in stdout
    assert "secret-3" not in stdout
    assert "token-7" not in stdout
    assert "[redacted]" in stdout

    write_json_error(
        command="test",
        error=AppError(
            "failed",
            data={
                "nested": [
                    "Bearer token-4",
                    {"detail": "client_secret=secret-5"},
                    ["CF-Access-Client-Secret: secret-6"],
                    "CLOUDFLARE_API_TOKEN=token-8",
                ]
            },
        ),
    )

    data_stdout = capsys.readouterr().out
    assert "token-4" not in data_stdout
    assert "secret-5" not in data_stdout
    assert "secret-6" not in data_stdout
    assert "token-8" not in data_stdout
    assert "[redacted]" in data_stdout


def _setup(fake_environment: FakeEnvironment) -> int:
    """Run the common manager setup."""

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


def _publish_machine(fake_environment: FakeEnvironment, *, json_mode: bool) -> int:
    """Publish the common machine-only fixture."""

    prefix = ["--json"] if json_mode else []
    return main(
        [
            *prefix,
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


def _manifest_text(fake_environment: FakeEnvironment) -> str:
    """Return the raw state manifest text."""

    state_file = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )
    return state_file.read_text(encoding="utf-8")


def _json_payload(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    """Return the captured JSON stdout payload and require quiet stderr."""

    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert isinstance(payload, dict)
    return payload
