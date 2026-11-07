#!/usr/bin/env python3
"""Check the skills-only plugin payload without installing it or reading manager state."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import tomllib
import xml.etree.ElementTree as element_tree
from pathlib import Path
from typing import cast

REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = "plugin"
SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
IDENTITY_FIELDS = (
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
)
# The host installs only this subdirectory. It carries guidance, never the CLI or dev tooling.
PLUGIN_PAYLOAD = frozenset({"plugin.json", ".claude-plugin", "LICENSE", "skills"})
NATIVE_MANIFEST_DIR = frozenset({"plugin.json"})
# Manifest keys that declare hooks, MCP servers, apps or commands would add execution surfaces.
PORTABLE_KEYS = frozenset({"$schema", *IDENTITY_FIELDS, "extensions"})
OPENAI_EXTENSION_KEYS = frozenset({"requires_local_executor", "interface"})
# Every skill file has one of these shapes; only the inspection scripts may be executable.
SKILL_FILE_SHAPES = (
    re.compile(r"SKILL\.md"),
    re.compile(r"agents/openai\.yaml"),
    re.compile(r"references/[a-z0-9-]+\.md"),
    re.compile(r"scripts/[a-z0-9-]+\.sh"),
    re.compile(r"assets/[a-z0-9-]+\.(?:svg|png)"),
)
SKILL_DIRECTORIES = frozenset({"agents", "references", "scripts", "assets"})
SKILL_SHAPES_TEXT = (
    "SKILL.md, agents/openai.yaml, references/*.md, scripts/*.sh and assets/*.svg|png"
)
# Finder metadata is ignored by Git and excluded from the sdist; it never reaches a host install.
IGNORED_OS_FILES = frozenset({".DS_Store"})
REQUIRED_SKILL_FILES = (
    "SKILL.md",
    "agents/openai.yaml",
    "references/product-contract.md",
    "references/operator-recipes.md",
    "references/state-and-recovery.md",
    "references/mental-model.md",
    "references/source-and-discovery.md",
    "references/cloudflare-api-and-permissions.md",
    "scripts/inspect-manager.sh",
    "assets/icon-small.svg",
    "assets/icon-large.png",
)
SKILL_PIN = re.compile(r"written for CLI version `([^`]+)`")
# GitHub matches the owner case-insensitively and accepts a `.git` suffix, so a stale pin can hide
# in either spelling. The ref stops at whitespace, quoting or closing punctuation.
INSTALL_SOURCE = re.compile(
    r"git\+https://github\.com/tiziano-ai/cloudflare-publish(?:\.git)?(@[^\s`'\")\],;:]*)?",
    re.IGNORECASE,
)
# A release ref is `@v` plus a version; a sentence's closing period is not part of it.
RELEASE_REF = re.compile(r"@v(\d[\w.+-]*?)\.?")
# There is no package-index release: an index install would fetch an unrelated or absent project.
INDEX_INSTALL = re.compile(
    r"\b(?:uv\s+tool\s+install|uv\s+pip\s+install|uvx|pipx\s+(?:install|run)|pip3?\s+install)"
    + r"(?:\s+-\S+)*\s+['\"]?cloudflare-publish(?![\w./-])",
    re.IGNORECASE,
)


def validate_package(root: Path) -> None:
    """Validate payload closure and coherent versions, not host activation or Cloudflare."""

    project = cast(
        dict[str, object],
        tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"],
    )
    plugin = root / PLUGIN_DIR
    _validate_payload(plugin)
    if (plugin / "LICENSE").read_bytes() != (root / "LICENSE").read_bytes():
        raise ValueError("plugin/LICENSE must be an exact copy of the root LICENSE")
    portable = json.loads((plugin / "plugin.json").read_text(encoding="utf-8"))
    native = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    if not isinstance(portable, dict) or not isinstance(native, dict):
        raise ValueError("plugin manifests must contain JSON objects")
    for key in IDENTITY_FIELDS:
        if not portable.get(key) or portable.get(key) != native.get(key):
            raise ValueError(f"plugin identity differs or is missing: {key}")
    if portable.get("$schema") != SCHEMA:
        raise ValueError("portable manifest must declare Agent Plugins 1.0.0")
    if (portable["name"], portable["version"], portable["license"]) != (
        project["name"],
        project["version"],
        project["license"],
    ):
        raise ValueError("plugin and Python package name, version, or license differ")
    if frozenset(portable) != PORTABLE_KEYS:
        unexpected = ", ".join(sorted(frozenset(portable) - PORTABLE_KEYS)) or "none"
        raise ValueError(
            "portable manifest must contain $schema, identity and extensions only; "
            + f"extra: {unexpected}"
        )
    extensions = portable.get("extensions")
    if not isinstance(extensions, dict) or set(extensions) != {"com.openai"}:
        raise ValueError("portable manifest must declare only the com.openai extension")
    openai = extensions.get("com.openai")
    if not isinstance(openai, dict) or openai.get("requires_local_executor") is not True:
        raise ValueError("plugin requires a local executor")
    if frozenset(openai) != OPENAI_EXTENSION_KEYS:
        unexpected = ", ".join(sorted(frozenset(openai) - OPENAI_EXTENSION_KEYS)) or "none"
        raise ValueError(
            "com.openai extension must contain requires_local_executor and interface only; "
            + f"extra: {unexpected}"
        )
    interface = openai.get("interface")
    if not isinstance(interface, dict):
        raise ValueError("plugin listing metadata is missing")
    if set(native) != {*IDENTITY_FIELDS, "icon"}:
        raise ValueError("Claude manifest must contain identity and icon metadata only")
    icon = native.get("icon")
    if not isinstance(icon, str) or icon != interface.get("logo"):
        raise ValueError("Claude icon must reuse the portable listing image")
    composer_icon = interface.get("composerIcon")
    if not isinstance(composer_icon, str):
        raise ValueError("portable listing must declare composerIcon")
    for target in (icon, composer_icon):
        _validate_local_target(plugin / "plugin.json", plugin, target)
    skills = plugin / "skills"
    if skills.is_symlink() or not skills.is_dir():
        raise ValueError(f"{PLUGIN_DIR}/skills must be a real directory")
    if {path.name for path in skills.iterdir()} - IGNORED_OS_FILES != {"cloudflare-publish"}:
        raise ValueError("package must contain exactly the cloudflare-publish skill")
    skill = skills / "cloudflare-publish"
    validate_skill(skill)
    _validate_cli_pin(root, plugin, skill, str(project["version"]))


def _validate_payload(plugin: Path) -> None:
    """Admit only manifests, the license and skills; no CLI, hooks, MCP or dev files."""

    if not plugin.is_dir() or plugin.is_symlink():
        raise ValueError(f"{PLUGIN_DIR}/ must be a real directory")
    for directory, expected in (
        (plugin, PLUGIN_PAYLOAD),
        (plugin / ".claude-plugin", NATIVE_MANIFEST_DIR),
    ):
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"missing plugin directory: {directory.name}")
        names = {path.name for path in directory.iterdir()} - IGNORED_OS_FILES
        unexpected = ", ".join(sorted(names - expected))
        if unexpected:
            allowed = "manifests, LICENSE and skills/"
            raise ValueError(f"{PLUGIN_DIR}/ must contain only its {allowed}; remove: {unexpected}")
        if expected - names:
            raise ValueError(f"plugin payload is missing: {', '.join(sorted(expected - names))}")
    for path in (plugin / "plugin.json", plugin / ".claude-plugin" / "plugin.json"):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"plugin manifest must be a regular file: {path.name}")
    if (plugin / "LICENSE").is_symlink() or not (plugin / "LICENSE").is_file():
        raise ValueError("plugin/LICENSE must be a regular file")


def _validate_cli_pin(root: Path, plugin: Path, skill: Path, version: str) -> None:
    """Bind the skill's CLI pin and every pinned install command to the package version."""

    skill_text = (skill / "SKILL.md").read_text(encoding="utf-8")
    pins = [match.group(1) for match in SKILL_PIN.finditer(skill_text)]
    if len(pins) != 1:
        raise ValueError("SKILL.md must state exactly one pinned CLI version")
    if pins[0] != version:
        raise ValueError(f"SKILL.md pins CLI {pins[0]} but pyproject.toml is {version}")
    sources = [path for path in sorted(skill.rglob("*")) if path.suffix in {".md", ".sh", ".yaml"}]
    sources.extend(sorted(root.glob("*.md")))
    sources.extend(sorted((root / "devtools").glob("*.md")))
    sources.extend((plugin / "plugin.json", plugin / ".claude-plugin" / "plugin.json"))
    for path in sources:
        for pinned in _install_pins(path):
            if pinned != version:
                raise ValueError(
                    f"install command in {path.name} pins v{pinned}, expected v{version}"
                )
    for required in (skill / "SKILL.md", root / "README.md"):
        if version not in _install_pins(required):
            raise ValueError(f"pinned install command is missing from {required.name}")


def _install_pins(path: Path) -> list[str]:
    """Return the release versions one file's install commands name; reject other install forms."""

    text = path.read_text(encoding="utf-8")
    if match := INDEX_INSTALL.search(text):
        raise ValueError(f"package-index install in {path.name}; use the release tag: {match[0]}")
    pins: list[str] = []
    for match in INSTALL_SOURCE.finditer(text):
        ref = match.group(1) or ""
        if ref.startswith("@v<"):
            continue  # a placeholder such as `@v<version>` documents the form, not a release
        release = RELEASE_REF.fullmatch(ref)
        if release is None:
            raise ValueError(
                f"install command in {path.name} must name a tag @v<version>: {match[0]}"
            )
        pins.append(release.group(1))
    return pins


def validate_skill(root: Path) -> None:
    """Require a regular, portable skill tree whose local references stay in the package."""

    if not root.is_dir() or root.is_symlink():
        raise ValueError("skill source must be a real directory")
    entries = sorted(path for path in root.rglob("*") if path.name not in IGNORED_OS_FILES)
    if len(entries) > 256:
        raise ValueError("skill package exceeds 256 entries")
    total_bytes = 0
    for path in entries:
        mode = path.lstat().st_mode
        if path.is_symlink() or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"skill contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            if relative not in SKILL_DIRECTORIES:
                raise ValueError(f"skill may contain only {SKILL_SHAPES_TEXT}; remove: {relative}")
            continue
        if not any(shape.fullmatch(relative) for shape in SKILL_FILE_SHAPES):
            raise ValueError(f"skill may contain only {SKILL_SHAPES_TEXT}; remove: {relative}")
        expected_mode = 0o755 if path.suffix == ".sh" else 0o644
        if stat.S_IMODE(mode) != expected_mode:
            raise ValueError(f"skill file must have mode {expected_mode:04o}: {path}")
        total_bytes += path.stat().st_size
        if total_bytes > 16 * 1024 * 1024 or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("skill package exceeds size limits")
        if path.suffix in {".md", ".yaml", ".sh", ".svg"}:
            text = path.read_text(encoding="utf-8")
            for pattern in (r"/Users/", r"/home/", r"envs\.envset", r"tiz-home", r"~/Code/"):
                if re.search(pattern, text):
                    raise ValueError(f"skill contains a private workstation dependency: {path}")
            if path.suffix == ".md":
                _validate_links(path, root)
        if path.suffix == ".sh":
            completed = subprocess.run(["bash", "-n", str(path)], capture_output=True, check=False)
            if completed.returncode:
                raise ValueError(f"invalid skill shell script: {path}")
    for relative in REQUIRED_SKILL_FILES:
        if not (root / relative).is_file():
            raise ValueError(f"required skill file is missing: {relative}")
    if (
        not (root / "SKILL.md")
        .read_text(encoding="utf-8")
        .startswith("---\nname: cloudflare-publish\ndescription: ")
    ):
        raise ValueError("skill identity or description is missing")
    svg = element_tree.fromstring((root / "assets" / "icon-small.svg").read_text(encoding="utf-8"))
    if svg.tag.rsplit("}", maxsplit=1)[-1] != "svg":
        raise ValueError("small icon must be an SVG document")
    if not (root / "assets" / "icon-large.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("large icon must be a PNG")
    metadata = (root / "agents" / "openai.yaml").read_text(encoding="utf-8")
    for key in ("display_name", "short_description", "default_prompt", "allow_implicit_invocation"):
        if not re.search(rf"^  {key}: .+", metadata, re.MULTILINE):
            raise ValueError(f"skill presentation metadata is missing: {key}")
    for match in re.finditer(r'^  icon_(?:small|large): "([^"]+)"', metadata, re.MULTILINE):
        _validate_local_target(root / "SKILL.md", root, match.group(1))


def _validate_links(path: Path, root: Path) -> None:
    """Check local Markdown links without fetching external references."""

    for match in re.finditer(r"\]\(([^\s)]+)\)", path.read_text(encoding="utf-8")):
        target = match.group(1)
        if target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        _validate_local_target(path, root, target.split("#", maxsplit=1)[0])


def _validate_local_target(path: Path, root: Path, target: str) -> None:
    resolved = (path.parent / target).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError(f"missing or escaping skill reference in {path}: {target}")


class PackageArgs(argparse.Namespace):
    """Typed source selection; no default points at an installed consumer."""

    def __init__(self) -> None:
        super().__init__()
        self.root: Path = REPO_ROOT


def main() -> int:
    """Read the source tree only; installation belongs to the host and the CLI installer."""

    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(namespace=PackageArgs())
    try:
        validate_package(Path(args.root))
    except (ValueError, OSError, element_tree.ParseError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print("Plugin payload and skill closure valid; no installation or live checks performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
