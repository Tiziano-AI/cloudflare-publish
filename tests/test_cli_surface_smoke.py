"""Full CLI-surface smoke coverage through the hermetic fake toolchain."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_doctor_treats_arbitrary_directory_bin_as_optional(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PATH-global doctor does not mistake an arbitrary `bin/` folder for the source checkout."""

    (fake_environment.repo_root / "bin").mkdir()

    payload = _run_json(
        fake_environment,
        capsys,
        ["doctor"],
    )

    labels = {item["label"]: item for item in _objects(payload["data"]["checks"])}
    assert labels["repo development wrapper optional"]["ok"] is True


def test_every_cli_surface_smokes_in_fake_environment(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise every public CLI command family without live Cloudflare writes."""

    with pytest.raises(SystemExit) as help_exit:
        main(["--help"], repo_root=fake_environment.repo_root)
    assert help_exit.value.code == 0
    _ = capsys.readouterr()

    doctor_before = _run_json(fake_environment, capsys, ["doctor"])
    assert doctor_before["data"]["ready"] is False

    accounts = _run_json(
        fake_environment,
        capsys,
        ["--api-token", "token-1", "discover", "accounts"],
    )
    assert _objects(accounts["data"]["accounts"])[0]["id"] == "acc-123"

    zones = _run_json(
        fake_environment,
        capsys,
        ["--api-token", "token-1", "discover", "zones", "--account-id", "acc-123"],
    )
    assert _objects(zones["data"]["zones"])[0]["name"] == "example.com"

    resolved = _run_json(
        fake_environment,
        capsys,
        [
            "--api-token",
            "token-1",
            "discover",
            "zone",
            "example.com",
            "--account-id",
            "acc-123",
        ],
    )
    assert resolved["data"]["zone"]["id"] == "zone-123"

    organization = _run_json(
        fake_environment,
        capsys,
        ["--api-token", "token-1", "discover", "organization", "--account-id", "acc-123"],
    )
    assert organization["data"]["organization"]["auth_domain"] == "example.cloudflareaccess.com"

    _run_human(
        fake_environment,
        capsys,
        [
            "setup",
            "--api-token",
            "token-1",
            "--account-id",
            "acc-123",
            "--zone",
            "example.com",
        ],
    )
    _run_json(fake_environment, capsys, ["setup", "--refresh-only"])

    tunnels = _run_json(
        fake_environment,
        capsys,
        ["discover", "tunnels", "--account-id", "acc-123"],
    )
    assert _objects(tunnels["data"]["tunnels"])[0]["id"] == "tunnel-1"

    _run_json(fake_environment, capsys, ["service", "status"])
    _run_json(fake_environment, capsys, ["service", "stop"])
    _run_json(fake_environment, capsys, ["service", "start"])
    _run_json(fake_environment, capsys, ["service", "restart"])
    _run_json(fake_environment, capsys, ["service", "logs", "--lines", "3"])

    publish_plan = _run_json(
        fake_environment,
        capsys,
        [
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
    )
    assert publish_plan["data"]["plan"] is True

    _run_json(
        fake_environment,
        capsys,
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
    )
    _run_json(
        fake_environment,
        capsys,
        [
            "publish",
            "apply",
            "portal",
            "--yes",
            "--hostname",
            "portal.example.com",
            "--to",
            "http://127.0.0.1:3001",
            "--audience",
            "human",
            "--allow-domain",
            "example.com",
        ],
    )
    _run_json(
        fake_environment,
        capsys,
        [
            "publish",
            "apply",
            "app",
            "--yes",
            "--hostname",
            "app.example.com",
            "--to",
            "https://127.0.0.1:9443",
            "--audience",
            "mixed",
            "--allow-email",
            "ops@example.com",
            "--http-host-header",
            "internal.example.com",
            "--origin-server-name",
            "internal.example.com",
            "--no-tls-verify",
        ],
    )

    listed = _run_json(fake_environment, capsys, ["ls"])
    assert set(_object_map(listed["data"]["publications"])) == {"app", "grafana", "portal"}
    inspected = _run_json(fake_environment, capsys, ["inspect", "grafana"])
    assert inspected["data"]["publication"]["spec"]["name"] == "grafana"
    _run_json(fake_environment, capsys, ["verify"])
    _run_json(fake_environment, capsys, ["verify", "grafana", "--live"])

    rotated = _run_json(fake_environment, capsys, ["token", "rotate", "grafana", "--yes"])
    assert rotated["data"]["service_token"]["client_secret"] == "secret-3"

    _run_json(fake_environment, capsys, ["guard", "status"])
    guard_plan = _run_json(fake_environment, capsys, ["guard", "plan"])
    assert guard_plan["data"]["plan"] is True
    _run_json(fake_environment, capsys, ["guard", "apply", "--yes"])

    remove_plan = _run_json(fake_environment, capsys, ["rm", "plan", "portal"])
    assert remove_plan["data"]["plan"] is True
    _run_json(fake_environment, capsys, ["rm", "apply", "portal", "--yes"])

    recover_plan = _run_json(fake_environment, capsys, ["tunnel", "recover", "plan"])
    assert recover_plan["data"]["plan"] is True
    _run_json(fake_environment, capsys, ["tunnel", "recover", "apply", "--yes"])

    _run_json(fake_environment, capsys, ["teardown", "--yes"])
    assert fake_environment.tool_state()["cloudflare"]["tunnels"] == {}


def _run_json(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
) -> dict[str, object]:
    """Run one JSON CLI command and return the decoded success envelope."""

    exit_code = main(["--json", *command], repo_root=fake_environment.repo_root)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert exit_code == 0, captured.out
    payload = json.loads(captured.out)
    assert isinstance(payload, dict)
    assert payload["ok"] is True
    return payload


def _run_human(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
) -> str:
    """Run one human CLI command and return stdout."""

    exit_code = main(command, repo_root=fake_environment.repo_root)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert exit_code == 0, captured.out
    return captured.out


def _objects(value: object) -> list[dict[str, object]]:
    """Return a JSON array of object items."""

    assert isinstance(value, list)
    objects: list[dict[str, object]] = []
    for item in value:
        assert isinstance(item, dict)
        objects.append(item)
    return objects


def _object_map(value: object) -> dict[str, object]:
    """Return a JSON object map."""

    assert isinstance(value, dict)
    return value
