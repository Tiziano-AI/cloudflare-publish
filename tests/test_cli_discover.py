"""Typed Cloudflare discovery CLI contract coverage."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_discover_commands_emit_typed_json(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Discovery commands use typed Cloudflare adapter payloads."""

    tool_state = fake_environment.tool_state()
    cloudflare = tool_state["cloudflare"]
    for index in range(51):
        cloudflare["accounts"].append({"id": f"acc-extra-{index}", "name": f"Extra {index}"})
        cloudflare["zones"].append(
            {
                "id": f"zone-extra-{index}",
                "name": f"extra-{index}.example.com",
                "account": {"id": "acc-123"},
                "status": "active",
                "type": "full",
            }
        )
    for index in range(1001):
        cloudflare["tunnels"][f"tunnel-extra-{index}"] = {
            "id": f"tunnel-extra-{index}",
            "name": f"remote-{index}",
            "created_at": "2026-04-26T00:00:00Z",
            "remote_config": True,
            "status": "healthy",
        }
    fake_environment.write_tool_state(tool_state)

    assert main(["--json", "--api-token", "token-1", "discover", "accounts"]) == 0
    accounts = _json_payload(capsys)
    account_items = accounts["data"]["accounts"]
    assert len(account_items) == 52
    assert account_items[-1]["id"] == "acc-extra-50"
    assert "result" not in json.dumps(accounts["data"])

    assert (
        main(
            [
                "--json",
                "--api-token",
                "token-1",
                "discover",
                "zones",
                "--account-id",
                "acc-123",
            ]
        )
        == 0
    )
    zones = _json_payload(capsys)
    zone_items = zones["data"]["zones"]
    assert len(zone_items) == 52
    assert zone_items[-1]["id"] == "zone-extra-50"
    assert "result" not in json.dumps(zones["data"])

    assert (
        main(
            [
                "--json",
                "--api-token",
                "token-1",
                "discover",
                "zone",
                "example.com",
                "--account-id",
                "acc-123",
            ]
        )
        == 0
    )
    resolved = _json_payload(capsys)
    assert resolved["data"]["zone"]["id"] == "zone-123"

    assert (
        main(["--json", "--api-token", "token-1", "discover", "tunnels", "--account-id", "acc-123"])
        == 0
    )
    tunnels = _json_payload(capsys)
    tunnel_items = tunnels["data"]["tunnels"]
    assert len(tunnel_items) == 1001
    assert tunnel_items[-1]["id"] == "tunnel-extra-1000"
    assert "result" not in json.dumps(tunnels["data"])

    assert (
        main(
            [
                "--json",
                "--api-token",
                "token-1",
                "discover",
                "organization",
                "--account-id",
                "acc-123",
            ]
        )
        == 0
    )
    organization = _json_payload(capsys)
    assert organization["data"]["organization"]["auth_domain"] == "example.cloudflareaccess.com"


def test_discovery_reads_api_token_from_private_dotenv(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Discovery accepts the private dotenv without requiring argv token exposure."""

    fake_environment.write_private_dotenv({"CLOUDFLARE_API_TOKEN": "token-1"})

    assert main(["--json", "discover", "accounts"], repo_root=fake_environment.repo_root) == 0

    accounts = _json_payload(capsys)
    assert accounts["data"]["accounts"][0]["id"] == "acc-123"


def test_discovery_and_doctor_emit_human_output(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Discovery commands render useful human output without requiring --json."""

    assert main(["doctor"], repo_root=fake_environment.repo_root) == 0
    doctor = capsys.readouterr()
    assert "== Doctor ==" in doctor.out
    assert "Ready: no" in doctor.out

    assert main(["--api-token", "token-1", "discover", "accounts"]) == 0
    accounts = capsys.readouterr()
    assert "== Accounts ==" in accounts.out
    assert "acc-123\tExample Account" in accounts.out

    assert (
        main(
            [
                "--api-token",
                "token-1",
                "discover",
                "zones",
                "--account-id",
                "acc-123",
            ]
        )
        == 0
    )
    zones = capsys.readouterr()
    assert "== Zones ==" in zones.out
    assert "zone-123\texample.com\tactive\tfull\tacc-123" in zones.out

    assert (
        main(
            [
                "--api-token",
                "token-1",
                "discover",
                "zone",
                "example.com",
                "--account-id",
                "acc-123",
            ]
        )
        == 0
    )
    resolved = capsys.readouterr()
    assert "== Zone ==" in resolved.out
    assert "ID: zone-123" in resolved.out

    assert _setup(fake_environment) == 0
    _ = capsys.readouterr()
    assert (
        main(
            ["discover", "tunnels", "--account-id", "acc-123"],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    tunnels = capsys.readouterr()
    assert "== Tunnels ==" in tunnels.out
    state_file = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )
    manager = json.loads(state_file.read_text(encoding="utf-8"))["manager"]
    tunnel_id = manager["tunnel_id"]
    remote_name = fake_environment.tool_state()["cloudflare"]["tunnels"][tunnel_id]["name"]
    assert remote_name.startswith(f"{manager['tunnel_name']}:")
    assert f"{tunnel_id}\t{remote_name}\thealthy\tremote_config=True" in tunnels.out

    assert (
        main(["--api-token", "token-1", "discover", "organization", "--account-id", "acc-123"]) == 0
    )
    organization = capsys.readouterr()
    assert "== Organization ==" in organization.out
    assert "Auth domain: example.cloudflareaccess.com" in organization.out


def test_setup_reads_noninteractive_defaults_from_private_dotenv(
    fake_environment: FakeEnvironment,
) -> None:
    """Setup can bootstrap from the private dotenv without token-on-argv."""

    fake_environment.write_private_dotenv(
        {
            "CLOUDFLARE_API_TOKEN": "token-1",
            "CLOUDFLARE_ACCOUNT_ID": "acc-123",
            "CLOUDFLARE_ZONE": "example.com",
        }
    )

    assert main(["setup"], repo_root=fake_environment.repo_root) == 0

    state_file = (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )
    manifest = json.loads(state_file.read_text(encoding="utf-8"))
    assert manifest["manager"]["account_id"] == "acc-123"
    assert manifest["manager"]["zone_name"] == "example.com"
    assert "token-1" not in fake_environment.last_security_argv()


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


def _json_payload(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    """Return the captured JSON stdout payload and require quiet stderr."""

    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert isinstance(payload, dict)
    return payload
