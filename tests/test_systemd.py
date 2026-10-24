"""Hermetic ownership, quoting and lifecycle checks; not a live Linux claim."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import override

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import AppPaths
from cloudflare_publish.paths import build_paths
from cloudflare_publish.process import CommandResult, CommandRunner
from cloudflare_publish.render import render_systemd_unit
from cloudflare_publish.systemd import UNIT, Systemd
from cloudflare_publish.workflow_support import remove_local_manager_artifacts


class NativeRunner(CommandRunner):
    """Model independent native state and explicit systemctl effects."""

    def __init__(self, paths: AppPaths) -> None:
        self.paths: AppPaths = paths
        self.binary: Path = Path("/opt/cloudflared")
        self.commands: list[list[str]] = []
        self.version: str = "systemd 240 (240)\n"
        self.bus_status: int = 0
        self.linger: str = "yes\n"
        self.missing: set[str] = set()
        self.active: bool = False
        self.enabled: bool = False
        self.pid: int = 0
        self.dropins: str = ""
        self.fragment: str | None = None
        self.foreign_exec: bool = False
        self.reload_needed: str = "no"
        self.stop_stuck: bool = False
        self.loaded: bool = False
        self.reload_failures: int = 0
        self.interrupt_reload: bool = False

    @override
    def which(self, program: str) -> Path | None:
        return None if program in self.missing else Path("/usr/bin") / program

    @override
    def run(
        self,
        command: list[str],
        *,
        check: bool = True,
        input_text: str | None = None,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        assert input_text is None and cwd is None and env is None
        self.commands.append(command)
        status = 0
        output = ""
        if command == ["systemctl", "--version"]:
            output = self.version
        elif command == ["systemctl", "--user", "show", "--property=Version", "--value"]:
            status = self.bus_status
        elif command == ["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"]:
            output = self.linger
        elif command[:4] == ["systemctl", "--user", "show", UNIT]:
            output = self.observation()
        elif command == [
            "systemctl",
            "--user",
            "show",
            "cloudflared.service",
            "--property=LoadState",
        ]:
            output = "LoadState=not-found\n"
        elif command == ["systemctl", "--user", "daemon-reload"]:
            if self.interrupt_reload:
                raise KeyboardInterrupt
            if self.reload_failures:
                self.reload_failures -= 1
                status = 1
            else:
                self.loaded = self.paths.service_file.exists()
        elif command == ["systemctl", "--user", "enable", "--now", UNIT]:
            self.enabled, self.active, self.pid = True, True, 4500
        elif command == ["systemctl", "--user", "disable", "--now", UNIT]:
            if not self.stop_stuck:
                self.enabled, self.active, self.pid = False, False, 0
        elif command == ["systemctl", "--user", "restart", UNIT]:
            self.active, self.pid = True, self.pid + 1
        else:
            raise AssertionError(command)
        assert check is False or status == 0
        return CommandResult(tuple(command), status, output, "private diagnostic")

    def observation(self) -> str:
        binary = "/foreign/cloudflared" if self.foreign_exec else str(self.binary)
        token = str(self.paths.tunnel_token_file).replace("$", "$$")
        values: dict[str, str] = {
            "LoadState": "loaded" if self.loaded else "not-found",
            "ActiveState": "active" if self.active else "inactive",
            "MainPID": str(self.pid),
            "ExecMainStatus": "0",
            "FragmentPath": (self.fragment or str(self.paths.service_file)) if self.loaded else "",
            "DropInPaths": self.dropins,
            "UnitFileState": "enabled" if self.enabled else "disabled",
            "ExecStart": (
                f"{{ path={binary} ; argv[]={binary} tunnel run --token-file {token} ; "
                + "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
                + "pid=0 ; code=(null) ; status=0/0 }"
            )
            if self.loaded
            else "",
            "NeedDaemonReload": self.reload_needed,
        }
        return "".join(f"{key}={value}\n" for key, value in values.items())


@pytest.fixture
def native(tmp_path: Path) -> tuple[AppPaths, NativeRunner, Systemd]:
    paths = build_paths(tmp_path, tmp_path / "home", platform="linux")
    paths.service_dir.mkdir(parents=True)
    paths.state_dir.mkdir(parents=True, mode=0o700)
    paths.logs_dir.mkdir(mode=0o700)
    runner = NativeRunner(paths)
    return paths, runner, Systemd(runner, paths)


def _definition(paths: AppPaths, runner: NativeRunner) -> None:
    _ = paths.service_file.write_text(render_systemd_unit(paths, str(runner.binary)))
    paths.service_file.chmod(0o600)
    runner.loaded = True


@pytest.mark.parametrize("problem", ["old", "bus", "linger", "tool", "private-directory"])
def test_preflight_fails_without_any_service_mutation(
    native: tuple[AppPaths, NativeRunner, Systemd], problem: str
) -> None:
    paths, runner, service = native
    if problem == "old":
        runner.version = "systemd 239\n"
    elif problem == "bus":
        runner.bus_status = 1
    elif problem == "linger":
        runner.linger = "no\n"
    elif problem == "tool":
        runner.missing.add("lsof")
    else:
        paths.state_dir.chmod(0o755)
    with pytest.raises(AppError):
        service.preflight()
    assert not any(
        command[2:3] in (["enable"], ["disable"], ["restart"], ["daemon-reload"])
        for command in runner.commands
    )
    assert not any("enable-linger" in command for command in runner.commands)


def test_install_start_stop_restart_and_owned_removal(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    service.install(runner.binary)
    assert paths.service_file.stat().st_mode & 0o777 == 0o600
    process = service.service()
    assert process is not None
    assert process.pid == 4500
    service.restart()
    assert runner.pid == 4501
    service.stop()
    assert paths.service_file.exists()
    assert not service.is_loaded()
    assert not service.is_registered()
    service.start()
    assert runner.enabled and runner.active
    with pytest.raises(AppError, match="still active"):
        service.remove_definition()
    service.stop()
    service.remove_definition()
    assert not paths.service_file.exists()
    assert not runner.loaded
    assert not paths.service_file.with_name(".cloudflare-publish.service.retiring").exists()


@pytest.mark.parametrize("problem", ["unit", "dropin", "fragment", "exec", "reload", "symlink"])
def test_start_and_restart_refuse_foreign_or_unapplied_definition(
    native: tuple[AppPaths, NativeRunner, Systemd], problem: str
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    if problem == "unit":
        with paths.service_file.open("a") as handle:
            _ = handle.write("Environment=FOREIGN=value\n")
    elif problem == "dropin":
        runner.dropins = "/etc/systemd/user/cloudflare-publish.service.d/foreign.conf"
    elif problem == "fragment":
        runner.fragment = "/etc/systemd/user/cloudflare-publish.service"
    elif problem == "exec":
        runner.foreign_exec = True
    elif problem == "reload":
        runner.reload_needed = "yes"
    else:
        other = paths.service_file.with_suffix(".other")
        _ = paths.service_file.rename(other)
        paths.service_file.symlink_to(other)
    for operation in (service.start, service.restart):
        with pytest.raises(AppError):
            operation()
    assert not any(command[2:3] in (["enable"], ["restart"]) for command in runner.commands)


def test_setup_does_not_overwrite_foreign_unit(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    _ = paths.service_file.write_text("[Service]\nExecStart=/foreign/cloudflared\n")
    with pytest.raises(AppError, match="not the exact owned"):
        service.install(runner.binary)
    assert paths.service_file.read_text() == "[Service]\nExecStart=/foreign/cloudflared\n"
    assert not any("daemon-reload" in command for command in runner.commands)


def test_stop_requires_positive_disabled_inactive_readback(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    runner.active, runner.enabled, runner.pid, runner.stop_stuck = True, True, 99, True
    with pytest.raises(AppError, match="still active or enabled"):
        service.stop()
    assert paths.service_file.exists()


def test_restart_does_not_implicitly_enable_stopped_unit(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    with pytest.raises(AppError, match="not enabled or active"):
        service.restart()
    assert not runner.enabled and not runner.active


def test_lifecycle_accepts_literal_special_paths(tmp_path: Path) -> None:
    """Exercise readback/lifecycle, not only the renderer's quoting assertions."""

    paths = build_paths(tmp_path, tmp_path / 'space %i $ENV \\ "quote', platform="linux")
    paths.state_dir.mkdir(parents=True, mode=0o700)
    paths.logs_dir.mkdir(mode=0o700)
    runner = NativeRunner(paths)
    runner.binary = Path('/opt/space %f \\ "quote/cloudflared')
    service = Systemd(runner, paths)
    service.install(runner.binary)
    assert service.validate_definition() == runner.binary
    service.restart()
    service.stop()
    service.start()
    service.stop()
    service.remove_definition()
    assert not paths.service_file.exists()
    assert not runner.loaded
    assert not paths.service_file.with_name(".cloudflare-publish.service.retiring").exists()


@pytest.mark.parametrize("unsafe", ["symlink", "writable"])
@pytest.mark.parametrize("parent", [".config", ".config/systemd", ".config/systemd/user"])
def test_unit_parent_drift_blocks_install_and_removal(
    native: tuple[AppPaths, NativeRunner, Systemd], parent: str, unsafe: str
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    selected = paths.home / parent
    if unsafe == "symlink":
        moved = selected.with_name(selected.name + "-original")
        _ = selected.rename(moved)
        selected.symlink_to(moved, target_is_directory=True)
    else:
        selected.chmod(0o777)
    original = paths.service_file.read_bytes()
    for operation in (lambda: service.install(runner.binary), service.remove_definition):
        with pytest.raises(AppError, match="not the exact owned"):
            operation()
    assert paths.service_file.read_bytes() == original
    assert not any("daemon-reload" in command for command in runner.commands)


@pytest.mark.parametrize("failure", ["failure", "interrupt", "already-reloaded"])
def test_unit_retirement_resumes_without_losing_exact_definition_custody(
    native: tuple[AppPaths, NativeRunner, Systemd], failure: str
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    definition = paths.service_file.read_bytes()
    retired = paths.service_file.with_name(".cloudflare-publish.service.retiring")
    if failure == "failure":
        runner.reload_failures = 1
        with pytest.raises(AppError, match="native user-service command failed"):
            service.remove_definition()
    else:
        runner.interrupt_reload = True
        with pytest.raises(KeyboardInterrupt):
            service.remove_definition()
        runner.interrupt_reload = False
        if failure == "already-reloaded":
            runner.loaded = False
    assert retired.read_bytes() == definition
    assert not paths.service_file.exists()
    for operation in (service.preflight, service.start, lambda: service.install(runner.binary)):
        with pytest.raises(AppError, match="retirement is incomplete"):
            operation()
    service.remove_definition()
    assert not retired.exists()
    assert not paths.service_file.exists()
    assert not runner.loaded


@pytest.mark.parametrize("foreign", ["canonical-file", "custody-file", "native-fragment", "exec"])
def test_retirement_recovery_never_adopts_foreign_state(
    native: tuple[AppPaths, NativeRunner, Systemd], foreign: str
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    runner.reload_failures = 1
    with pytest.raises(AppError):
        service.remove_definition()
    retired = paths.service_file.with_name(".cloudflare-publish.service.retiring")
    if foreign == "canonical-file":
        _ = paths.service_file.write_text("[Service]\nExecStart=/foreign/cloudflared\n")
    elif foreign == "custody-file":
        _ = retired.write_text("[Service]\nExecStart=/foreign/cloudflared\n")
    elif foreign == "native-fragment":
        runner.fragment = "/etc/systemd/user/cloudflare-publish.service"
    else:
        runner.foreign_exec = True
    before = len(runner.commands)
    with pytest.raises(AppError, match="not the exact owned"):
        service.remove_definition()
    assert retired.exists()
    assert not any("daemon-reload" in command for command in runner.commands[before:])


def test_absent_unit_without_retirement_cannot_adopt_cached_native_definition(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    runner.loaded = True
    with pytest.raises(AppError, match="not the exact owned"):
        service.remove_definition()
    assert not paths.service_file.exists()
    assert not any("daemon-reload" in command for command in runner.commands)


@pytest.mark.parametrize(
    ("field", "contradiction"),
    [
        ("ActiveState=inactive", "ActiveState=active"),
        ("MainPID=0", "MainPID=9876"),
        ("FragmentPath=", "FragmentPath=/foreign/definition"),
        ("DropInPaths=", "DropInPaths=/foreign/override"),
        ("UnitFileState=disabled", "UnitFileState=enabled"),
        ("ExecStart=", "ExecStart=foreign-command"),
    ],
)
def test_native_not_found_must_not_hide_serving_or_foreign_state(
    native: tuple[AppPaths, NativeRunner, Systemd],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    contradiction: str,
) -> None:
    _, runner, service = native
    observed = runner.observation().replace(field + "\n", contradiction + "\n")
    monkeypatch.setattr(runner, "observation", lambda: observed)
    for operation in (service.is_registered, service.stop, service.remove_definition):
        with pytest.raises(AppError, match="not the exact owned"):
            _ = operation()
    assert not any("daemon-reload" in command for command in runner.commands)


def test_dangling_unit_symlink_never_counts_as_verified_absence(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    paths.service_file.symlink_to(paths.service_file.with_name("absent-foreign-unit"))
    for operation in (service.is_registered, service.stop, service.remove_definition):
        with pytest.raises(AppError, match="not the exact owned"):
            _ = operation()
    assert paths.service_file.is_symlink()
    assert not any("daemon-reload" in command for command in runner.commands)


def test_linux_local_cleanup_preserves_unknown_entries(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, _, _ = native
    credentials = paths.state_dir / "credentials"
    credentials.mkdir(mode=0o700)
    unknowns = (
        paths.state_dir / "operator-note",
        paths.logs_dir / "operator-log",
        credentials / "unexplained-credential",
        paths.state_dir / "manager.lock",
    )
    for path in (*unknowns, paths.state_file, paths.tunnel_token_file):
        _ = path.write_text("retained or known")
    remove_local_manager_artifacts(paths)
    assert all(path.read_text() == "retained or known" for path in unknowns)
    assert not paths.state_file.exists()
    assert not paths.tunnel_token_file.exists()


def test_render_uses_systemd_not_shell_quoting(tmp_path: Path) -> None:
    paths = build_paths(tmp_path, tmp_path / 'space %i $ENV \\ "quote', platform="linux")
    text = render_systemd_unit(paths, '/opt/space %f \\ "quote/cloudflared')
    assert '"/opt/space %%f \\\\ \\"quote/cloudflared"' in text
    assert "$${" not in text
    assert "$$ENV" in text
    assert "StandardOutput=append:" + str(paths.stdout_log_file).replace("%", "%%") in text
    assert "Restart=on-failure\n" in text
    assert "UMask=0077\nNoNewPrivileges=yes\n" in text
    assert "Environment=" not in text


@pytest.mark.parametrize(
    "binary", ["relative/cloudflared", "/a\nb", "/a\rb", "/a\x00b", "/a;bad", "/$ENV/cloudflared"]
)
def test_render_refuses_ambiguous_or_control_injecting_binary(tmp_path: Path, binary: str) -> None:
    paths = build_paths(tmp_path, tmp_path, platform="linux")
    with pytest.raises(AppError):
        _ = render_systemd_unit(paths, binary)
