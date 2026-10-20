"""Native plugin closure, independent installation and private local diagnostics."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "devtools" / "validate_package.py"
SOURCE_ROOT = REPO_ROOT / "skills" / "cloudflare-publish"


def _copy_package(destination: Path) -> Path:
    destination.mkdir()
    for relative in ("plugin.json", "pyproject.toml", "LICENSE"):
        shutil.copy2(REPO_ROOT / relative, destination / relative)
    for relative in ("skills", ".claude-plugin"):
        shutil.copytree(REPO_ROOT / relative, destination / relative)
    return destination


def _validate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), "--root", str(root)],
        capture_output=True,
        check=False,
        cwd=root,
        text=True,
    )


def test_package_validates_outside_checkout(tmp_path: Path) -> None:
    """The published skill and metadata need no private overlays or live installation."""

    package = _copy_package(tmp_path / "package")
    completed = _validate(package)
    assert completed.returncode == 0, completed.stderr
    assert "no installation or live checks performed" in completed.stdout


def test_package_rejects_version_drift(tmp_path: Path) -> None:
    """The host must not present a plugin version that disagrees with the CLI."""

    package = _copy_package(tmp_path / "package")
    manifest = package / ".claude-plugin" / "plugin.json"
    payload = json.loads(manifest.read_text())
    payload["version"] = "9.9.9"
    manifest.write_text(json.dumps(payload))
    completed = _validate(package)
    assert completed.returncode == 1
    assert "version" in completed.stderr


@pytest.mark.parametrize("target", ["missing.md", "../../../LICENSE"])
def test_skill_references_are_self_contained(tmp_path: Path, target: str) -> None:
    """A cached skill cannot rely on missing files or material outside its own tree."""

    package = _copy_package(tmp_path / "package")
    skill = package / "skills" / "cloudflare-publish" / "SKILL.md"
    skill.write_text(skill.read_text() + f"\n[Broken reference]({target})\n")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "missing or escaping skill reference" in completed.stderr


def test_skill_cannot_reference_personal_checkout(tmp_path: Path) -> None:
    """Public instructions must not select one developer's home or private secret tooling."""

    package = _copy_package(tmp_path / "package")
    skill = package / "skills" / "cloudflare-publish" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nInstall from /Users/example/Code/private-checkout.\n")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "private workstation dependency" in completed.stderr


def test_skill_rejects_linked_files(tmp_path: Path) -> None:
    """No link may acquire bytes from a neighbouring private checkout during packaging."""

    package = _copy_package(tmp_path / "package")
    (package / "skills" / "cloudflare-publish" / "linked").symlink_to(package / "LICENSE")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "non-regular entry" in completed.stderr


@pytest.mark.parametrize("surface", ["hooks", "mcp.json"])
def test_guidance_only_package_has_no_automatic_execution(tmp_path: Path, surface: str) -> None:
    """Unexpected execution surfaces must not silently change this package's install effects."""

    package = _copy_package(tmp_path / "package")
    (package / surface).touch()
    completed = _validate(package)
    assert completed.returncode == 1
    assert "execution surface" in completed.stderr


def test_cli_installer_does_not_write_global_skills() -> None:
    """The CLI-only recipe must leave plugin ownership with the native host."""

    completed = subprocess.run(
        ["make", "-n", "install-local"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == "uv tool install --reinstall ."


def test_diagnostic_resolves_only_path_not_nearby_checkout(tmp_path: Path) -> None:
    """A source wrapper is not an installed command, even when the skill lives beside it."""

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    completed = subprocess.run(
        ["bash", str(SOURCE_ROOT / "scripts" / "inspect-manager.sh")],
        capture_output=True,
        check=False,
        cwd=REPO_ROOT,
        env={"HOME": str(user_dir), "PATH": "/usr/bin:/bin"},
        text=True,
    )
    assert completed.returncode == 0
    assert "not found on PATH" in completed.stdout
    assert str(REPO_ROOT / "bin" / "cloudflare-publish") not in completed.stdout


def test_diagnostic_reports_actual_path_command(tmp_path: Path) -> None:
    """Discovery identifies the selected installed command without executing it."""

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    command = binaries / "cloudflare-publish"
    command.write_text("#!/bin/sh\nexit 99\n")
    command.chmod(0o755)
    completed = subprocess.run(
        ["bash", str(SOURCE_ROOT / "scripts" / "inspect-manager.sh")],
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env={"HOME": str(user_dir), "PATH": f"{binaries}:/usr/bin:/bin"},
        text=True,
    )
    assert completed.returncode == 0
    assert str(command) in completed.stdout


def test_diagnostic_outputs_no_secret_publication_contract(tmp_path: Path) -> None:
    """Offline local evidence stays allowlisted even if a manifest contains secret fields."""

    user_dir = tmp_path / "user"
    state_dir = user_dir / "Library" / "Application Support" / "cloudflare-publish"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "manager": {"account_name": "Example", "zone_name": "example.com"},
                "publications": {
                    "dashboard": {
                        "spec": {
                            "hostname": "dashboard.example.com",
                            "audience": "mixed",
                            "origin_url": "https://127.0.0.1:8443",
                            "verify_path": "/healthz",
                            "origin_options": {
                                "http_host_header": "dashboard.internal",
                                "origin_server_name": "origin.internal",
                                "no_tls_verify": True,
                            },
                        },
                        "state": {
                            "service_token_client_id": "client-1",
                            "service_token_client_secret": "secret-that-must-not-escape",
                        },
                    }
                },
            }
        )
    )
    completed = subprocess.run(
        ["bash", str(SOURCE_ROOT / "scripts" / "inspect-manager.sh")],
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env={"HOME": str(user_dir), "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"},
        text=True,
    )
    assert completed.returncode == 0
    assert "public_verify_url=https://dashboard.example.com/healthz" in completed.stdout
    assert "origin_host_header=dashboard.internal" in completed.stdout
    assert "origin_server_name=origin.internal" in completed.stdout
    assert "origin_tls_verification=disabled" in completed.stdout
    assert "service_token_client_id=client-1" in completed.stdout
    assert "secret-that-must-not-escape" not in completed.stdout
