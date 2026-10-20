"""Hermetic fake-binary test environment for cloudflare-publish."""

from __future__ import annotations

import json
import os
import plistlib
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from cloudflare_publish.json_types import JsonObject, JsonValue, load_json_value, require_object
from cloudflare_publish.local_secrets import LOCAL_DOTENV_ENV_VAR, SECRET_ENV_KEYS
from tests.fake_curl_script import curl_script
from tests.fake_tool_scripts import (
    brew_script,
    cloudflared_script,
    initial_tool_state,
    launchctl_script,
    plutil_script,
    security_script,
    ssh_script,
    write_executable,
)


@dataclass(frozen=True)
class FakeEnvironment:
    """Hermetic temporary paths and fake-tool state."""

    repo_root: Path
    home: Path
    bin_dir: Path
    state_file: Path

    def install_conflicting_local_state(self) -> None:
        """Create conflicting local `cloudflared` artifacts that require takeover."""

        cloudflared_dir = self.home / ".cloudflared"
        cloudflared_dir.mkdir(parents=True, exist_ok=True)
        _ = (cloudflared_dir / "config.yml").write_text(
            "conflict-config\n",
            encoding="utf-8",
        )
        _ = (cloudflared_dir / "cert.pem").write_text("conflict-cert\n", encoding="utf-8")
        launch_agents_dir = self.home / "Library" / "LaunchAgents"
        launch_agents_dir.mkdir(parents=True, exist_ok=True)
        with (launch_agents_dir / "com.cloudflare.cloudflared.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "Label": "com.cloudflare.cloudflared",
                    "ProgramArguments": ["/fake/cloudflared", "tunnel", "run"],
                    "RunAtLoad": True,
                },
                handle,
            )
        state = self.tool_state()
        labels: list[JsonValue] = ["com.cloudflare.cloudflared"]
        state["launchd_labels"] = labels
        self.write_tool_state(state)

    def tool_state(self) -> JsonObject:
        """Load the shared fake-tool state."""

        return require_object(
            load_json_value(self.state_file.read_text(encoding="utf-8"), label="fake tool state"),
            message="fake tool state must be an object.",
        )

    def write_tool_state(self, state: JsonObject) -> None:
        """Persist fake-binary state mutations for one test."""

        _ = self.state_file.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    def inject_api_fault(
        self, method: str, path: str, *, mode: str = "before", occurrence: int = 1
    ) -> None:
        """Fail one exact write before rejection or after its accepted response is lost."""

        if mode not in {"before", "after", "kill"}:
            raise ValueError("fault mode must be before, after, or kill")
        state = self.tool_state()
        cloudflare = _object_map(state.get("cloudflare"))
        faults = cloudflare.setdefault("faults", [])
        if not isinstance(faults, list):
            raise ValueError("fake faults must be a list")
        faults.append({"method": method, "path": path, "mode": mode, "occurrence": occurrence})
        self.write_tool_state(state)

    def add_foreign_connector(self, *, tunnel_id: str = "tunnel-1", version: int = 1) -> None:
        """Add an independently managed active replica that local bootout cannot stop."""

        state = self.tool_state()
        cloudflare = _object_map(state.get("cloudflare"))
        connections = _object_map(cloudflare.setdefault("tunnel_connections", {}))
        clients = connections.setdefault(tunnel_id, [])
        if not isinstance(clients, list):
            raise ValueError("fake clients must be a list")
        clients.append(
            {
                "id": "foreign-client",
                "config_version": version,
                "conns": [{"id": "foreign-connection", "is_pending_reconnect": False}],
            }
        )
        cloudflare["tunnel_connections"] = connections
        self.write_tool_state(state)

    def launchd_labels(self) -> tuple[str, ...]:
        """Return loaded fake launchd labels."""

        return _string_tuple(self.tool_state().get("launchd_labels"))

    def cleaned_tunnel_ids(self) -> tuple[str, ...]:
        """Return fake Cloudflare tunnel cleanup calls."""

        cloudflare = _object_map(self.tool_state().get("cloudflare"))
        return _string_tuple(cloudflare.get("cleaned_tunnel_ids"))

    def kickstart_count(self) -> int:
        """Return fake launchctl kickstart call count."""

        value = self.tool_state().get("launchctl_kickstart_count")
        return value if isinstance(value, int) else 0

    def set_cloudflared_version(self, version: str) -> None:
        """Set the fake `cloudflared --version` output."""

        state = self.tool_state()
        state["cloudflared_version"] = version
        self.write_tool_state(state)

    def crash_launchd_label(self, label: str, *, status: int) -> None:
        """Mark a fake launchd label as loaded but not running."""

        state = self.tool_state()
        pids = _object_map(state.get("launchd_pids"))
        statuses = _object_map(state.get("launchd_statuses"))
        pids[label] = "-"
        statuses[label] = status
        state["launchd_pids"] = pids
        state["launchd_statuses"] = statuses
        self.write_tool_state(state)

    def fail_next_bootout(self) -> None:
        """Make the next fake launchctl bootout fail."""

        state = self.tool_state()
        state["launchctl_fail_bootout_once"] = True
        self.write_tool_state(state)

    def linger_after_bootout(self, checks: int) -> None:
        """Keep a booted-out fake launchd label registered for N status checks."""

        state = self.tool_state()
        state["launchctl_bootout_linger_checks"] = checks
        self.write_tool_state(state)

    def last_security_argv(self) -> tuple[str, ...]:
        """Return the last fake security argv without stdout secret material."""

        return _string_tuple(self.tool_state().get("last_security_argv"))

    def write_private_dotenv(self, assignments: dict[str, str]) -> Path:
        """Write a strict private dotenv file for tests and point the CLI at it."""

        secret_dir = self.home / "private"
        secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = secret_dir / "cloudflare-publish.env"
        lines = ["# test private dotenv"]
        for key, value in assignments.items():
            lines.append(f"{key}={value}")
        _ = path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path.chmod(0o600)
        os.environ[LOCAL_DOTENV_ENV_VAR] = str(path)
        return path


def make_fake_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[FakeEnvironment]:
    """Create a hermetic fake HOME and fake binary directory for CLI tests."""

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    state_file = tmp_path / "fake-tool-state.json"
    _ = state_file.write_text(initial_tool_state(), encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    for key in SECRET_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv(LOCAL_DOTENV_ENV_VAR, raising=False)
    monkeypatch.setenv("CLOUDFLARE_PUBLISH_TEST_STATE", str(state_file))
    monkeypatch.setenv("CLOUDFLARE_PUBLISH_FAKE_BIN_DIR", str(bin_dir))
    python_dir = Path(sys.executable).resolve().parent
    monkeypatch.setenv("PATH", os.pathsep.join((str(bin_dir), str(python_dir), "/usr/bin", "/bin")))

    write_executable(bin_dir / "cloudflared-source", cloudflared_script())
    write_executable(bin_dir / "cloudflared", cloudflared_script())
    write_executable(bin_dir / "launchctl", launchctl_script())
    write_executable(bin_dir / "curl", curl_script())
    write_executable(bin_dir / "security", security_script())
    write_executable(bin_dir / "brew", brew_script())
    write_executable(bin_dir / "plutil", plutil_script())
    write_executable(bin_dir / "ssh", ssh_script())
    yield FakeEnvironment(repo_root=repo_root, home=home, bin_dir=bin_dir, state_file=state_file)


def _object_map(value: JsonValue | None) -> JsonObject:
    """Return a string-keyed object map from fake JSON state."""

    if not isinstance(value, dict):
        return {}
    return value


def _string_tuple(value: JsonValue | None) -> tuple[str, ...]:
    """Return string items from fake JSON state arrays."""

    if not isinstance(value, list):
        return ()
    items: list[str] = []
    for item in value:
        if isinstance(item, str):
            items.append(item)
    return tuple(items)
