#!/usr/bin/env python3
"""Check this skill-only plugin without installing it or reading manager state."""

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


def validate_package(root: Path) -> None:
    """Validate package closure and coherent metadata, not host activation or Cloudflare."""

    portable = json.loads((root / "plugin.json").read_text(encoding="utf-8"))
    native = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    if not isinstance(portable, dict) or not isinstance(native, dict):
        raise ValueError("plugin manifests must contain JSON objects")
    for key in IDENTITY_FIELDS:
        if not portable.get(key) or portable.get(key) != native.get(key):
            raise ValueError(f"plugin identity differs or is missing: {key}")
    if portable.get("$schema") != SCHEMA:
        raise ValueError("portable manifest must declare Agent Plugins 1.0.0")
    project = cast(
        dict[str, object],
        tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"],
    )
    if (portable["name"], portable["version"], portable["license"]) != (
        project["name"],
        project["version"],
        project["license"],
    ):
        raise ValueError("plugin and Python package name, version, or license differ")
    extensions = portable.get("extensions")
    if not isinstance(extensions, dict):
        raise ValueError("portable manifest must declare local-executor support")
    openai = extensions.get("com.openai")
    if not isinstance(openai, dict) or openai.get("requires_local_executor") is not True:
        raise ValueError("plugin requires a local executor")
    interface = openai.get("interface")
    if not isinstance(interface, dict):
        raise ValueError("plugin listing metadata is missing")
    for path in ("hooks", "mcp.json", ".mcp.json", ".codex-plugin"):
        if (root / path).exists():
            raise ValueError(f"this skill-only package must not add an execution surface: {path}")
    if set(native) != {*IDENTITY_FIELDS, "icon"}:
        raise ValueError("Claude manifest must contain identity and icon metadata only")
    icon = native.get("icon")
    if not isinstance(icon, str) or icon != interface.get("logo"):
        raise ValueError("Claude icon must reuse the portable listing image")
    _validate_local_target(root / "plugin.json", root, icon)
    if not (root / "LICENSE").is_file():
        raise ValueError("LICENSE is missing from the package")
    skills = root / "skills"
    if skills.is_symlink() or {path.name for path in skills.iterdir()} != {"cloudflare-publish"}:
        raise ValueError("package must contain exactly the cloudflare-publish skill")
    validate_skill(skills / "cloudflare-publish")


def validate_skill(root: Path) -> None:
    """Require a regular, portable skill tree whose local references stay in the package."""

    if not root.is_dir() or root.is_symlink():
        raise ValueError("skill source must be a real directory")
    entries = sorted(root.rglob("*"))
    if len(entries) > 256:
        raise ValueError("skill package exceeds 256 entries")
    total_bytes = 0
    for path in entries:
        mode = path.lstat().st_mode
        if path.is_symlink() or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"skill contains a non-regular entry: {path}")
        if path.is_dir():
            continue
        if stat.S_IMODE(mode) not in {0o644, 0o755}:
            raise ValueError(f"skill file must have mode 0644 or 0755: {path}")
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
            if not mode & stat.S_IXUSR:
                raise ValueError(f"skill script is not executable: {path}")
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
    """Read the package only; installation belongs to the host and the CLI installer."""

    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(namespace=PackageArgs())
    try:
        validate_package(Path(args.root))
    except (ValueError, OSError, element_tree.ParseError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print("Plugin metadata and skill closure valid; no installation or live checks performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
