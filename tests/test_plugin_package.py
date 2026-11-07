"""Native plugin closure, independent installation and private local diagnostics."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "devtools" / "validate_package.py"
VERSION = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["version"]
INSTALL = f"git+https://github.com/Tiziano-AI/cloudflare-publish@v{VERSION}"
SOURCE_ROOT = REPO_ROOT / "plugin" / "skills" / "cloudflare-publish"


def _copy_package(destination: Path) -> Path:
    destination.mkdir()
    for relative in ("pyproject.toml", "LICENSE", "README.md"):
        shutil.copy2(REPO_ROOT / relative, destination / relative)
    plugin = destination / "plugin"
    plugin.mkdir()
    for relative in ("plugin.json", "LICENSE"):
        shutil.copy2(REPO_ROOT / "plugin" / relative, plugin / relative)
    for relative in ("skills", ".claude-plugin"):
        shutil.copytree(REPO_ROOT / "plugin" / relative, plugin / relative)
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
    manifest = package / "plugin" / ".claude-plugin" / "plugin.json"
    payload = json.loads(manifest.read_text())
    payload["version"] = "9.9.9"
    manifest.write_text(json.dumps(payload))
    completed = _validate(package)
    assert completed.returncode == 1
    assert "version" in completed.stderr


def test_skill_pins_the_package_version(tmp_path: Path) -> None:
    """The skill's preflight compares the CLI with the version this package releases."""

    package = _copy_package(tmp_path / "package")
    skill = package / "plugin" / "skills" / "cloudflare-publish" / "SKILL.md"
    pin = f"written for CLI version `{VERSION}`"
    assert pin in skill.read_text()
    skill.write_text(skill.read_text().replace(pin, "written for CLI version `9.9.9`"))
    completed = _validate(package)
    assert completed.returncode == 1
    assert f"SKILL.md pins CLI 9.9.9 but pyproject.toml is {VERSION}" in completed.stderr


def test_skill_states_one_pin(tmp_path: Path) -> None:
    """Two pins would leave the preflight comparing against an ambiguous version."""

    package = _copy_package(tmp_path / "package")
    skill = package / "plugin" / "skills" / "cloudflare-publish" / "SKILL.md"
    skill.write_text(skill.read_text() + f"\nAlso written for CLI version `{VERSION}`.\n")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "exactly one pinned CLI version" in completed.stderr


@pytest.mark.parametrize(
    "relative",
    [
        "README.md",
        "plugin/skills/cloudflare-publish/SKILL.md",
        "plugin/skills/cloudflare-publish/references/source-and-discovery.md",
        "plugin/skills/cloudflare-publish/references/product-contract.md",
    ],
)
def test_install_commands_pin_the_package_version(tmp_path: Path, relative: str) -> None:
    """A stale release tag in any install command would install a CLI the skill does not expect."""

    package = _copy_package(tmp_path / "package")
    document = package / relative
    assert INSTALL in document.read_text()
    stale = "git+https://github.com/Tiziano-AI/cloudflare-publish@v0.3.2"
    document.write_text(document.read_text().replace(INSTALL, stale))
    completed = _validate(package)
    assert completed.returncode == 1
    assert f"pins v0.3.2, expected v{VERSION}" in completed.stderr


def test_package_requires_native_listing_icon(tmp_path: Path) -> None:
    """Claude presentation metadata is required without becoming shared identity."""

    package = _copy_package(tmp_path / "package")
    manifest = package / "plugin" / ".claude-plugin" / "plugin.json"
    payload = json.loads(manifest.read_text())
    del payload["icon"]
    manifest.write_text(json.dumps(payload))
    completed = _validate(package)
    assert completed.returncode == 1
    assert "icon metadata" in completed.stderr


def test_native_icon_reuses_portable_listing_image(tmp_path: Path) -> None:
    """Both hosts present the same image rather than drifting to separate artwork."""

    package = _copy_package(tmp_path / "package")
    manifest = package / "plugin" / ".claude-plugin" / "plugin.json"
    payload = json.loads(manifest.read_text())
    payload["icon"] = "./skills/cloudflare-publish/assets/icon-small.svg"
    manifest.write_text(json.dumps(payload))
    completed = _validate(package)
    assert completed.returncode == 1
    assert "reuse the portable listing image" in completed.stderr


@pytest.mark.parametrize("target", ["missing.png", "../LICENSE"])
def test_listing_icons_stay_in_package(tmp_path: Path, target: str) -> None:
    """Matching host metadata cannot admit a missing image or one outside the plugin payload."""

    package = _copy_package(tmp_path / "package")
    portable_path = package / "plugin" / "plugin.json"
    portable = json.loads(portable_path.read_text())
    portable["extensions"]["com.openai"]["interface"]["logo"] = target
    portable_path.write_text(json.dumps(portable))
    native_path = package / "plugin" / ".claude-plugin" / "plugin.json"
    native = json.loads(native_path.read_text())
    native["icon"] = target
    native_path.write_text(json.dumps(native))
    completed = _validate(package)
    assert completed.returncode == 1
    assert "missing or escaping skill reference" in completed.stderr


def test_composer_icon_stays_in_package(tmp_path: Path) -> None:
    """The portable composer icon resolves inside the installed plugin payload."""

    package = _copy_package(tmp_path / "package")
    portable_path = package / "plugin" / "plugin.json"
    portable = json.loads(portable_path.read_text())
    portable["extensions"]["com.openai"]["interface"]["composerIcon"] = "../README.md"
    portable_path.write_text(json.dumps(portable))
    completed = _validate(package)
    assert completed.returncode == 1
    assert "missing or escaping skill reference" in completed.stderr


@pytest.mark.parametrize("target", ["missing.md", "../../LICENSE"])
def test_skill_references_are_self_contained(tmp_path: Path, target: str) -> None:
    """A cached skill cannot rely on missing files or material outside its own tree."""

    package = _copy_package(tmp_path / "package")
    skill = package / "plugin" / "skills" / "cloudflare-publish" / "SKILL.md"
    skill.write_text(skill.read_text() + f"\n[Broken reference]({target})\n")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "missing or escaping skill reference" in completed.stderr


def test_skill_cannot_reference_personal_checkout(tmp_path: Path) -> None:
    """Public instructions must not select one developer's home or private secret tooling."""

    package = _copy_package(tmp_path / "package")
    skill = package / "plugin" / "skills" / "cloudflare-publish" / "SKILL.md"
    skill.write_text(skill.read_text() + "\nInstall from /Users/example/Code/private-checkout.\n")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "private workstation dependency" in completed.stderr


def test_skill_rejects_linked_files(tmp_path: Path) -> None:
    """No link may acquire bytes from a neighbouring private checkout during packaging."""

    package = _copy_package(tmp_path / "package")
    skill = package / "plugin" / "skills" / "cloudflare-publish"
    (skill / "linked").symlink_to(package / "LICENSE")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "non-regular entry" in completed.stderr


@pytest.mark.parametrize(
    "entry",
    [
        "bin",
        "hooks",
        "mcp.json",
        ".mcp.json",
        ".codex-plugin",
        "package.json",
        "pyproject.toml",
        "src",
        ".claude-plugin/hooks.json",
    ],
)
def test_plugin_payload_admits_only_guidance(tmp_path: Path, entry: str) -> None:
    """The host-installed subdirectory never carries the CLI, hooks, MCP or development files."""

    package = _copy_package(tmp_path / "package")
    (package / "plugin" / entry).touch()
    completed = _validate(package)
    assert completed.returncode == 1
    assert "must contain only its manifests, LICENSE and skills/" in completed.stderr
    assert entry.rsplit("/", maxsplit=1)[-1] in completed.stderr


def test_plugin_license_matches_root_license(tmp_path: Path) -> None:
    """The license notice that ships with the guidance is the repository's own license."""

    package = _copy_package(tmp_path / "package")
    license_path = package / "plugin" / "LICENSE"
    license_path.write_text(license_path.read_text() + "\nAmended.\n")
    completed = _validate(package)
    assert completed.returncode == 1
    assert "exact copy of the root LICENSE" in completed.stderr


def test_diagnostic_resolves_only_path_not_nearby_checkout(tmp_path: Path) -> None:
    """A checkout's development environment is not an installed command beside the skill."""

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
    assert str(REPO_ROOT) not in completed.stdout


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


def _fake_cli(directory: Path) -> Path:
    directory.mkdir(parents=True)
    command = directory / "cloudflare-publish"
    command.write_text("#!/bin/sh\nexit 99\n")
    command.chmod(0o755)
    return command


def _inspect(tmp_path: Path, path_entries: list[Path]) -> subprocess.CompletedProcess[str]:
    user_dir = tmp_path / "user"
    user_dir.mkdir()
    return subprocess.run(
        ["bash", str(SOURCE_ROOT / "scripts" / "inspect-manager.sh")],
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env={"HOME": str(user_dir), "PATH": ":".join([*map(str, path_entries), "/usr/bin:/bin"])},
        text=True,
    )


def test_diagnostic_falls_back_to_uv_tool_directory(tmp_path: Path) -> None:
    """A fresh uv install is found by absolute path before the shell's PATH includes it."""

    installed = _fake_cli(tmp_path / "uv-tools" / "bin")
    tools = tmp_path / "tools"
    tools.mkdir()
    uv = tools / "uv"
    uv.write_text(
        f'#!/bin/sh\n[ "$*" = "tool dir --bin" ] || exit 2\nprintf "%s\\n" "{installed.parent}"\n'
    )
    uv.chmod(0o755)
    completed = _inspect(tmp_path, [tools])
    assert completed.returncode == 0, completed.stderr
    assert f"{installed}\n" in completed.stdout
    assert "not on PATH; call it by this absolute path" in completed.stdout


def test_diagnostic_names_shadowed_path_copies(tmp_path: Path) -> None:
    """The first PATH copy answers; a later copy, such as a stale plugin cache, is named."""

    selected = _fake_cli(tmp_path / "first")
    shadowed = _fake_cli(tmp_path / "second")
    completed = _inspect(tmp_path, [selected.parent, shadowed.parent, selected.parent])
    assert completed.returncode == 0, completed.stderr
    assert f"{selected}\nalso_on_path={shadowed} (not selected)\n" in completed.stdout
    assert completed.stdout.count("also_on_path=") == 1


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
