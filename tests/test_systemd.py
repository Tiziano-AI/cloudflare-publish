"""Hermetic ownership, quoting and lifecycle checks; not a live Linux claim."""

from __future__ import annotations

import os
import shlex
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
        self.loaded_binary: Path | None = None
        self.loaded_definition: str | None = None
        self.running_binary: Path | None = None
        self.running_token: str | None = None
        self.next_pid: int = 4500
        self.reload_failures: int = 0
        self.interrupt_reload: bool = False
        self.reload_attempts: int = 0
        self.fail_reload_at: int | None = None
        self.interrupt_reload_at: int | None = None
        self.interrupt_after_reload_at: int | None = None
        self.stop_failures: int = 0
        self.start_failures: int = 0
        self.start_stuck: bool = False

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
            self.reload_attempts += 1
            if self.interrupt_reload or self.interrupt_reload_at == self.reload_attempts:
                raise KeyboardInterrupt
            if self.reload_failures or self.fail_reload_at == self.reload_attempts:
                self.reload_failures = max(0, self.reload_failures - 1)
                status = 1
            else:
                self.load_definition()
                if self.interrupt_after_reload_at == self.reload_attempts:
                    raise KeyboardInterrupt
        elif command == ["systemctl", "--user", "enable", "--now", UNIT]:
            if self.start_failures:
                self.start_failures -= 1
                status = 1
            else:
                self.enabled = True
                if not self.active and not self.start_stuck:
                    self.start_process()
        elif command == ["systemctl", "--user", "disable", "--now", UNIT]:
            if self.stop_failures:
                self.stop_failures -= 1
                status = 1
            elif not self.stop_stuck:
                self.enabled, self.active, self.pid = False, False, 0
        elif command == ["systemctl", "--user", "restart", UNIT]:
            self.start_process()
        else:
            raise AssertionError(command)
        assert check is False or status == 0
        return CommandResult(tuple(command), status, output, "private diagnostic")

    def load_definition(self) -> None:
        """Native reload updates cached configuration, never a running process."""

        self.loaded = self.paths.service_file.exists()
        self.loaded_definition = self.paths.service_file.read_text() if self.loaded else None
        if self.loaded_definition is None:
            self.loaded_binary = None
            return
        command = next(
            line.removeprefix("ExecStart=")
            for line in self.loaded_definition.splitlines()
            if line.startswith("ExecStart=")
        )
        self.loaded_binary = Path(shlex.split(command)[0].replace("%%", "%"))

    def start_process(self) -> None:
        """Only real native start/restart captures the loaded binary and current token."""

        self.active, self.pid = True, self.next_pid
        self.next_pid += 1
        self.running_binary = self.loaded_binary
        self.running_token = (
            self.paths.tunnel_token_file.read_text()
            if self.paths.tunnel_token_file.exists()
            else None
        )

    def observation(self) -> str:
        binary = "/foreign/cloudflared" if self.foreign_exec else str(self.loaded_binary)
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
            "NeedDaemonReload": "yes"
            if self.loaded
            and (
                not self.paths.service_file.exists()
                or self.paths.service_file.read_text() != self.loaded_definition
            )
            else self.reload_needed,
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
    runner.load_definition()


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


def test_reinstall_replaces_running_executable_and_loaded_token(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    _ = paths.tunnel_token_file.write_text("old-token")
    paths.tunnel_token_file.chmod(0o600)
    service.install(runner.binary)
    old_pid = runner.pid
    previous_binary = runner.binary
    assert runner.running_token == "old-token"
    runner.commands.clear()
    replacement = Path("/opt/replacement/cloudflared")
    _ = paths.tunnel_token_file.write_text("replacement-token")

    service.install(replacement)

    assert runner.active and runner.enabled and runner.pid != old_pid
    assert runner.running_binary == replacement != previous_binary
    assert runner.running_token == "replacement-token"
    assert paths.service_file.read_text() == render_systemd_unit(paths, str(replacement))
    assert not paths.service_file.with_name(".cloudflare-publish.service.replacing").exists()
    effects = [
        command[2:]
        for command in runner.commands
        if command[2:3] in (["disable"], ["daemon-reload"], ["enable"])
    ]
    assert effects == [
        ["disable", "--now", UNIT],
        ["daemon-reload"],
        ["daemon-reload"],
        ["enable", "--now", UNIT],
    ]


@pytest.mark.parametrize("failure", ["command", "readback"])
def test_reinstall_stop_failure_preserves_old_definition_and_process(
    native: tuple[AppPaths, NativeRunner, Systemd], failure: str
) -> None:
    paths, runner, service = native
    service.install(runner.binary)
    old_pid, old_definition = runner.pid, paths.service_file.read_bytes()
    runner.commands.clear()
    if failure == "command":
        runner.stop_failures = 1
    else:
        runner.stop_stuck = True
    with pytest.raises(AppError):
        service.install(Path("/opt/replacement/cloudflared"))
    assert paths.service_file.read_bytes() == old_definition
    assert runner.pid == old_pid and runner.active and runner.enabled
    assert not paths.service_file.with_name(".cloudflare-publish.service.replacing").exists()
    assert not any(command[2:3] in (["daemon-reload"], ["enable"]) for command in runner.commands)


@pytest.mark.parametrize("failure", ["failure", "interrupt", "already-reloaded"])
def test_reinstall_recovers_exact_old_definition_custody(
    native: tuple[AppPaths, NativeRunner, Systemd], failure: str
) -> None:
    paths, runner, service = native
    service.install(runner.binary)
    definition, old_pid = paths.service_file.read_bytes(), runner.pid
    replacement = Path("/opt/replacement/cloudflared")
    next_reload = runner.reload_attempts + 1
    if failure == "failure":
        runner.fail_reload_at = next_reload
        expected = AppError
    elif failure == "interrupt":
        runner.interrupt_reload_at = next_reload
        expected = KeyboardInterrupt
    else:
        runner.interrupt_after_reload_at = next_reload
        expected = KeyboardInterrupt
    with pytest.raises(expected):
        service.install(replacement)
    retained = paths.service_file.with_name(".cloudflare-publish.service.replacing")
    assert retained.read_bytes() == definition
    assert not paths.service_file.exists()
    assert not runner.active and not runner.enabled and runner.pid == 0
    before = len(runner.commands)
    service.preflight()
    for operation in (
        service.service,
        service.validate_definition,
        service.start,
        service.stop,
        service.restart,
        service.remove_definition,
    ):
        with pytest.raises(AppError, match="replacement is incomplete"):
            _ = operation()
    assert not any(
        command[2:3] in (["daemon-reload"], ["enable"], ["disable"], ["restart"])
        for command in runner.commands[before:]
    )
    service.install(replacement)
    assert not retained.exists()
    assert runner.active and runner.enabled and runner.pid != old_pid
    assert runner.running_binary == replacement


def test_reinstall_recovers_absence_after_old_custody_removal(
    native: tuple[AppPaths, NativeRunner, Systemd], monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, runner, service = native
    service.install(runner.binary)
    replacement = Path("/opt/replacement/cloudflared")
    original_replace = Path.replace

    def interrupted_write(source: Path, target: str | Path) -> Path:
        if source.name.startswith(".cloudflare-publish-") and target == paths.service_file:
            raise KeyboardInterrupt
        return original_replace(source, target)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "replace", interrupted_write)
        with pytest.raises(KeyboardInterrupt):
            service.install(replacement)
    assert not paths.service_file.exists()
    assert not paths.service_file.with_name(".cloudflare-publish.service.replacing").exists()
    assert not runner.loaded and not runner.active and not runner.enabled
    assert not list(paths.service_dir.glob(".cloudflare-publish-*"))
    service.preflight()
    service.install(replacement)
    assert runner.active and runner.enabled and runner.running_binary == replacement


@pytest.mark.parametrize("failure", ["failure", "interrupt", "already-reloaded"])
def test_reinstall_recovers_new_definition_after_uncertain_reload(
    native: tuple[AppPaths, NativeRunner, Systemd], failure: str
) -> None:
    paths, runner, service = native
    service.install(runner.binary)
    replacement = Path("/opt/replacement/cloudflared")
    new_reload = runner.reload_attempts + 2
    if failure == "failure":
        runner.fail_reload_at = new_reload
        expected = AppError
    elif failure == "interrupt":
        runner.interrupt_reload_at = new_reload
        expected = KeyboardInterrupt
    else:
        runner.interrupt_after_reload_at = new_reload
        expected = KeyboardInterrupt
    with pytest.raises(expected):
        service.install(replacement)
    assert paths.service_file.read_text() == render_systemd_unit(paths, str(replacement))
    assert not paths.service_file.with_name(".cloudflare-publish.service.replacing").exists()
    assert not runner.active and not runner.enabled and runner.pid == 0
    service.preflight()
    service.install(replacement)
    assert runner.active and runner.enabled and runner.running_binary == replacement


@pytest.mark.parametrize("failure", ["command", "no-process"])
def test_reinstall_requires_running_process_and_can_retry_failed_start(
    native: tuple[AppPaths, NativeRunner, Systemd], failure: str
) -> None:
    paths, runner, service = native
    service.install(runner.binary)
    replacement = Path("/opt/replacement/cloudflared")
    if failure == "command":
        runner.start_failures = 1
    else:
        runner.start_stuck = True
    with pytest.raises(AppError):
        service.install(replacement)
    assert paths.service_file.read_text() == render_systemd_unit(paths, str(replacement))
    assert not paths.service_file.with_name(".cloudflare-publish.service.replacing").exists()
    assert runner.loaded and not runner.active and runner.pid == 0
    runner.start_stuck = False
    service.install(replacement)
    assert runner.active and runner.enabled and runner.running_binary == replacement


@pytest.mark.parametrize(
    "foreign",
    ["canonical", "custody", "symlink", "fragment", "exec", "dropin", "active", "enabled", "pid"],
)
def test_reinstall_custody_never_adopts_foreign_or_serving_state(
    native: tuple[AppPaths, NativeRunner, Systemd], foreign: str
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    retained = paths.service_file.with_name(".cloudflare-publish.service.replacing")
    _ = paths.service_file.rename(retained)
    if foreign == "canonical":
        _ = paths.service_file.write_text("[Service]\nExecStart=/foreign/cloudflared\n")
    elif foreign == "custody":
        _ = retained.write_text("[Service]\nExecStart=/foreign/cloudflared\n")
    elif foreign == "symlink":
        other = retained.with_suffix(".other")
        _ = retained.rename(other)
        retained.symlink_to(other)
    elif foreign == "fragment":
        runner.fragment = "/etc/systemd/user/cloudflare-publish.service"
    elif foreign == "exec":
        runner.foreign_exec = True
    elif foreign == "dropin":
        runner.dropins = "/etc/systemd/user/cloudflare-publish.service.d/foreign.conf"
    elif foreign == "active":
        runner.active = True
    elif foreign == "enabled":
        runner.enabled = True
    else:
        runner.pid = 3456
    for operation in (service.preflight, lambda: service.install(Path("/opt/new/cloudflared"))):
        with pytest.raises(AppError):
            operation()
    assert retained.exists()
    assert not any(
        command[2:3] in (["daemon-reload"], ["enable"], ["disable"], ["restart"])
        for command in runner.commands
    )


def test_reinstall_does_not_adopt_canonical_shaped_cached_binary_without_old_custody(
    native: tuple[AppPaths, NativeRunner, Systemd],
) -> None:
    paths, runner, service = native
    _definition(paths, runner)
    replacement = Path("/opt/replacement/cloudflared")
    _ = paths.service_file.write_text(render_systemd_unit(paths, str(replacement)))
    with pytest.raises(AppError, match="not the exact owned"):
        service.install(replacement)
    assert not any(
        command[2:3] in (["daemon-reload"], ["enable"], ["disable"]) for command in runner.commands
    )


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
