"""Adversarial CLI regression coverage for reviewed failure modes."""

from __future__ import annotations

import json

import pytest

from cloudflare_publish.cli import main
from tests.fake_environment import FakeEnvironment


def test_setup_rejects_zone_owned_by_different_account(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Setup fails closed when the selected zone belongs to another account."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["zones"][0]["account"]["id"] = "acc-other"
    _write_tool_state(fake_environment, tool_state)

    assert _setup(fake_environment) == 1
    captured = capsys.readouterr()
    assert "owned by account" in captured.err
    assert not _state_path(fake_environment).exists()


def test_setup_rejects_partial_zone(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Setup fails closed when the selected zone is not a full Cloudflare-managed zone."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["zones"][0]["type"] = "partial"
    _write_tool_state(fake_environment, tool_state)

    assert _setup(fake_environment) == 1
    captured = capsys.readouterr()
    assert "must be a full Cloudflare-managed zone" in captured.err
    assert not _state_path(fake_environment).exists()


def test_setup_resolves_zone_name_within_selected_account(
    fake_environment: FakeEnvironment,
) -> None:
    """Setup picks the selected-account zone even when another account exposes the same name."""

    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["accounts"].append({"id": "acc-456", "name": "Second Account"})
    tool_state["cloudflare"]["zones"].append(
        {
            "id": "zone-456",
            "name": "example.com",
            "account": {"id": "acc-456"},
            "status": "active",
            "type": "full",
        }
    )
    _write_tool_state(fake_environment, tool_state)

    assert _setup(fake_environment) == 0
    manifest = _load_manifest(fake_environment)
    assert manifest["manager"]["account_id"] == "acc-123"
    assert manifest["manager"]["zone_id"] == "zone-123"


def test_publish_preflights_unmanaged_dns_before_auth_mutations(
    fake_environment: FakeEnvironment,
) -> None:
    """Publish rejects unmanaged hostnames before creating Access or service-token state."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["dns_records"]["dns-existing"] = {
        "id": "dns-existing",
        "zone_id": "zone-123",
        "name": "grafana.example.com",
        "content": "unmanaged.example.net",
        "proxied": False,
    }
    _write_tool_state(fake_environment, tool_state)

    exit_code = main(
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

    assert exit_code == 1
    manifest = _load_manifest(fake_environment)
    assert manifest["publications"] == {}
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["access_apps"] == {}
    assert tool_state["cloudflare"]["access_policies"] == {}
    assert tool_state["cloudflare"]["service_tokens"] == {}
    assert not any(
        key.startswith("cloudflare-publish:service-token:grafana") for key in tool_state["keychain"]
    )


def test_publish_hands_off_machine_secret_but_requires_explicit_missing_secret_recovery(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing reused secret cannot silently rotate credentials or trap a new transition."""

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
    captured = capsys.readouterr()
    assert "Service token client ID: client-token-1" in captured.out
    assert "Service token client secret: secret-1" in captured.out

    tool_state = fake_environment.tool_state()
    account = _load_manifest(fake_environment)["publications"]["grafana"]["state"][
        "service_token_keychain_account"
    ]
    tool_state["keychain"].pop(f"cloudflare-publish:{account}")
    _write_tool_state(fake_environment, tool_state)

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
        == 1
    )
    captured = capsys.readouterr()
    assert "no publication change was started" in captured.err
    assert "token rotate grafana --yes" in captured.out
    assert "Service token client secret:" not in captured.out
    assert fake_environment.tool_state()["cloudflare"]["next_ids"]["secret"] == 2
    assert _load_manifest(fake_environment)["pending"] is None
    assert main(["token", "rotate", "grafana", "--yes"], repo_root=fake_environment.repo_root) == 0
    captured = capsys.readouterr()
    assert "Client secret: secret-2" in captured.out
    assert fake_environment.tool_state()["keychain"][f"cloudflare-publish:{account}"] == "secret-2"


def test_remove_retries_cleanly_after_tunnel_config_failure(
    fake_environment: FakeEnvironment,
) -> None:
    """Remove keeps remote state intact until the tunnel-config rewrite succeeds."""

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
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["fail_tunnel_config_put_once"] = True
    _write_tool_state(fake_environment, tool_state)

    assert main(["rm", "apply", "grafana", "--yes"], repo_root=fake_environment.repo_root) == 1
    manifest = _load_manifest(fake_environment)
    assert "grafana" in manifest["publications"]
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["dns_records"]
    assert tool_state["cloudflare"]["access_apps"]
    assert tool_state["cloudflare"]["service_tokens"]

    assert main(["rm", "apply", "grafana", "--yes"], repo_root=fake_environment.repo_root) == 0
    manifest = _load_manifest(fake_environment)
    assert manifest["publications"] == {}
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["dns_records"] == {}
    assert tool_state["cloudflare"]["access_apps"] == {}
    assert tool_state["cloudflare"]["service_tokens"] == {}


def test_guard_enable_preserves_unrelated_organization_fields(
    fake_environment: FakeEnvironment,
) -> None:
    """Guard enable rewrites the full org payload instead of clobbering sibling settings."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["organization"]["deny_unmatched_requests_exempted_zone_names"] = [
        "public.example.com"
    ]
    tool_state["cloudflare"]["organization"]["is_ui_read_only"] = True
    _write_tool_state(fake_environment, tool_state)

    assert main(["guard", "apply", "--yes"], repo_root=fake_environment.repo_root) == 0
    organization = fake_environment.tool_state()["cloudflare"]["organization"]
    assert organization["deny_unmatched_requests"] is True
    assert organization["deny_unmatched_requests_exempted_zone_names"] == ["public.example.com"]
    assert organization["is_ui_read_only"] is True


def test_human_publication_round_trip_is_supported(
    fake_environment: FakeEnvironment,
) -> None:
    """Human-only publications remain a supported product path and verify live cleanly."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "portal",
                "--yes",
                "--hostname",
                "portal.example.com",
                "--to",
                "http://127.0.0.1:3000",
                "--audience",
                "human",
                "--allow-domain",
                "example.com",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    assert main(["verify", "--live"], repo_root=fake_environment.repo_root) == 0
    manifest = _load_manifest(fake_environment)
    state = manifest["publications"]["portal"]["state"]
    assert state["service_token_id"] is None
    assert state["service_token_client_id"] is None
    assert state["service_token_keychain_account"] is None


def test_public_publication_round_trip_uses_no_access_resources(
    fake_environment: FakeEnvironment,
) -> None:
    """Public publications expose one tunnel route without Access or token custody."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "video-ingress",
                "--yes",
                "--hostname",
                "video-ingress.example.com",
                "--to",
                "http://127.0.0.1:4751",
                "--audience",
                "public",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )

    manifest = _load_manifest(fake_environment)
    publication = manifest["publications"]["video-ingress"]
    state = publication["state"]
    assert publication["spec"]["audience"] == "public"
    assert state["access_application_id"] is None
    assert state["access_aud"] is None
    assert state["policy_ids"] == []
    assert state["service_token_id"] is None
    assert state["service_token_client_id"] is None
    assert state["service_token_keychain_account"] is None

    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["access_apps"] == {}
    assert tool_state["cloudflare"]["access_policies"] == {}
    assert tool_state["cloudflare"]["service_tokens"] == {}
    assert main(["verify", "video-ingress", "--live"], repo_root=fake_environment.repo_root) == 0

    assert (
        main(
            ["rm", "apply", "video-ingress", "--yes"],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["dns_records"] == {}
    assert tool_state["cloudflare"]["access_apps"] == {}


def test_publication_can_transition_between_public_and_machine_access(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One managed publication retires and recreates Access resources across audience changes."""

    assert _setup(fake_environment) == 0
    common = [
        "publish",
        "apply",
        "video-ingress",
        "--yes",
        "--hostname",
        "video-ingress.example.com",
        "--to",
        "http://127.0.0.1:4751",
        "--audience",
    ]
    assert main([*common, "machine"], repo_root=fake_environment.repo_root) == 0
    assert fake_environment.tool_state()["cloudflare"]["access_apps"]
    _ = capsys.readouterr()

    assert (
        main(
            [
                "--json",
                "publish",
                "plan",
                "video-ingress",
                "--hostname",
                "video-ingress.example.com",
                "--to",
                "http://127.0.0.1:4751",
                "--audience",
                "public",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    public_plan = json.loads(capsys.readouterr().out)
    public_effects = public_plan["data"]["effects"]
    assert public_effects[0] == "persist normalized intent and partial resource ownership"
    assert (
        public_effects.index("withdraw the old ingress and observe every active connector")
        < public_effects.index(
            "retire the old Access application only after withdrawal is observed"
        )
        < public_effects.index(
            "apply candidate routing with native per-route Access guard when protected"
        )
        < public_effects.index("observe the exact configuration version on every active connector")
        < public_effects.index("retire superseded owned resources and commit publication state")
    )
    assert "the new public origin owns fail-closed request authentication" in public_effects
    assert "delete service token" in public_effects
    assert "delete service-token stored secret" in public_effects
    assert "create Access application with a distinct AUD" not in public_effects

    assert main([*common, "public"], repo_root=fake_environment.repo_root) == 0
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["access_apps"] == {}
    assert tool_state["cloudflare"]["access_policies"] == {}
    assert tool_state["cloudflare"]["service_tokens"] == {}
    assert not any(
        key.startswith("cloudflare-publish:service-token:video-ingress")
        for key in tool_state["keychain"]
    )
    _ = capsys.readouterr()

    assert (
        main(
            [
                "--json",
                "publish",
                "plan",
                "video-ingress",
                "--hostname",
                "video-ingress.example.com",
                "--to",
                "http://127.0.0.1:4751",
                "--audience",
                "machine",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    machine_plan = json.loads(capsys.readouterr().out)
    machine_effects = machine_plan["data"]["effects"]
    assert machine_effects[0] == "persist normalized intent and partial resource ownership"
    assert (
        machine_effects.index("withdraw the old ingress and observe every active connector")
        < machine_effects.index("create Access application with a distinct AUD")
        < machine_effects.index("verify exact Access policies")
        < machine_effects.index("create service token")
        < machine_effects.index(
            "apply candidate routing with native per-route Access guard when protected"
        )
        < machine_effects.index("observe the exact configuration version on every active connector")
        < machine_effects.index("retire superseded owned resources and commit publication state")
    )

    assert main([*common, "machine"], repo_root=fake_environment.repo_root) == 0
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["access_apps"]
    assert tool_state["cloudflare"]["access_policies"]
    assert tool_state["cloudflare"]["service_tokens"]


def test_public_publication_is_denied_when_account_guard_would_block_it(
    fake_environment: FakeEnvironment,
) -> None:
    """Public publication fails before mutation when unmatched hostnames are denied."""

    assert _setup(fake_environment) == 0
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["organization"]["deny_unmatched_requests"] = True
    _write_tool_state(fake_environment, tool_state)

    assert (
        main(
            [
                "publish",
                "apply",
                "video-ingress",
                "--yes",
                "--hostname",
                "video-ingress.example.com",
                "--to",
                "http://127.0.0.1:4751",
                "--audience",
                "public",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 1
    )
    manifest = _load_manifest(fake_environment)
    assert manifest["publications"] == {}
    tool_state = fake_environment.tool_state()
    assert tool_state["cloudflare"]["dns_records"] == {}
    assert tool_state["cloudflare"]["access_apps"] == {}


def test_verify_detects_guard_drift_that_blocks_a_public_publication(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Local verification rejects an account guard enabled after public publication."""

    assert _setup(fake_environment) == 0
    assert (
        main(
            [
                "publish",
                "apply",
                "video-ingress",
                "--yes",
                "--hostname",
                "video-ingress.example.com",
                "--to",
                "http://127.0.0.1:4751",
                "--audience",
                "public",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["organization"]["deny_unmatched_requests"] = True
    _write_tool_state(fake_environment, tool_state)
    _ = capsys.readouterr()

    assert main(["verify", "video-ingress"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "[FAIL] video-ingress: public guard is compatible" in captured.out
    assert "account require-protection blocks this public publication" in captured.out


def test_verify_fails_when_remote_tunnel_is_down(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify fails closed when the shared tunnel has no healthy edge connection."""

    assert _setup(fake_environment) == 0
    manifest = _load_manifest(fake_environment)
    tunnel_id = manifest["manager"]["tunnel_id"]
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["tunnels"][tunnel_id]["status"] = "down"
    _write_tool_state(fake_environment, tool_state)

    assert main(["verify"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "[FAIL] remote tunnel reachable" in captured.out
    assert "status=down" in captured.out


def test_verify_reports_missing_remote_tunnel_without_aborting(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify emits a failing tunnel check and continues with the rest of the doctor output."""

    assert _setup(fake_environment) == 0
    manifest = _load_manifest(fake_environment)
    tunnel_id = manifest["manager"]["tunnel_id"]
    tool_state = fake_environment.tool_state()
    tool_state["cloudflare"]["tunnels"].pop(tunnel_id, None)
    _write_tool_state(fake_environment, tool_state)

    assert main(["verify"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "[FAIL] remote tunnel reachable" in captured.out
    assert "[OK] Zero Trust organization reachable" in captured.out


def test_verify_detects_tunnel_config_and_policy_precedence_drift(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify fails when remote tunnel options or policy precedence drift away from state."""

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
                "https://127.0.0.1:8443",
                "--audience",
                "mixed",
                "--allow-domain",
                "example.com",
                "--http-host-header",
                "grafana.internal",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    manifest = _load_manifest(fake_environment)
    publication = manifest["publications"]["grafana"]
    tunnel_id = manifest["manager"]["tunnel_id"]
    tool_state = fake_environment.tool_state()
    ingress = tool_state["cloudflare"]["tunnel_configurations"][tunnel_id]["config"]["ingress"]
    for rule in ingress:
        if rule.get("hostname") == "grafana.example.com":
            rule.setdefault("originRequest", {})["disableChunkedEncoding"] = True
    for policy_id in publication["state"]["policy_ids"]:
        tool_state["cloudflare"]["access_policies"][policy_id]["precedence"] = 9
    _write_tool_state(fake_environment, tool_state)

    assert main(["verify"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "[FAIL] remote tunnel config matches local state" in captured.out
    assert "[FAIL] grafana: Access policies match state" in captured.out


def test_verify_detects_remote_dns_app_and_policy_drift(
    fake_environment: FakeEnvironment,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify fails when remote publication resources drift away from the local contract."""

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
                "mixed",
                "--allow-domain",
                "example.com",
            ],
            repo_root=fake_environment.repo_root,
        )
        == 0
    )
    manifest = _load_manifest(fake_environment)
    publication = manifest["publications"]["grafana"]
    tool_state = fake_environment.tool_state()
    dns_record = tool_state["cloudflare"]["dns_records"][publication["state"]["dns_record_id"]]
    dns_record["content"] = "wrong-target.example.net"
    dns_record["proxied"] = False
    app = tool_state["cloudflare"]["access_apps"][publication["state"]["access_application_id"]]
    app["domain"] = "wrong.example.com"
    for policy_id in publication["state"]["policy_ids"]:
        policy = tool_state["cloudflare"]["access_policies"][policy_id]
        policy["decision"] = "allow"
        policy["include"] = [{"email_domain": {"domain": "wrong.example.com"}}]
    _write_tool_state(fake_environment, tool_state)

    assert main(["verify"], repo_root=fake_environment.repo_root) == 1
    captured = capsys.readouterr()
    assert "[FAIL] grafana: DNS record matches state" in captured.out
    assert "[FAIL] grafana: Access app matches state" in captured.out
    assert "[FAIL] grafana: Access policies match state" in captured.out


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


def _load_manifest(fake_environment: FakeEnvironment) -> dict[str, object]:
    """Load the current local manifest JSON."""

    return json.loads(_state_path(fake_environment).read_text(encoding="utf-8"))


def _state_path(fake_environment: FakeEnvironment):
    """Return the canonical state manifest path for the fake environment."""

    return (
        fake_environment.home
        / "Library"
        / "Application Support"
        / "cloudflare-publish"
        / "state.json"
    )


def _write_tool_state(fake_environment: FakeEnvironment, state: dict[str, object]) -> None:
    """Persist fake-binary state mutations for one test."""

    fake_environment.state_file.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
