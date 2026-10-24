"""Fail-closed systemd user-service ownership and lifecycle on Linux."""

from __future__ import annotations

import os
import re
import shlex
import stat
import tempfile
from pathlib import Path
from typing import Literal

from cloudflare_publish.errors import AppError
from cloudflare_publish.models import AppPaths, ConnectorStatus
from cloudflare_publish.private_files import private_directory_available, read_private_file
from cloudflare_publish.process import CommandResult, CommandRunner
from cloudflare_publish.render import render_systemd_unit

UNIT = "cloudflare-publish.service"
_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "MainPID",
    "ExecMainStatus",
    "FragmentPath",
    "DropInPaths",
    "UnitFileState",
    "ExecStart",
    "NeedDaemonReload",
)


class Systemd:
    """Manage only this user's exact unit; never install packages or enable linger."""

    def __init__(self, runner: CommandRunner, paths: AppPaths) -> None:
        self._runner: CommandRunner = runner
        self._paths: AppPaths = paths

    @property
    def platform(self) -> Literal["linux"]:
        """Identify this Linux native adapter."""

        return "linux"

    def which(self, program: str) -> Path | None:
        return self._runner.which(program)

    def run(
        self, command: list[str], *, check: bool = True, input_text: str | None = None
    ) -> CommandResult:
        # Native error output can include a foreign unit's inline credentials.
        # Keep it out of the product error envelope, even during ownership failure.
        result = self._runner.run(command, check=False, input_text=input_text)
        if check and result.returncode != 0:
            raise AppError("The native user-service command failed.", code="service_command_failed")
        return result

    def preflight(self) -> None:
        """Establish the unattended native baseline before remote or lifecycle effects."""

        self._require_no_retirement()
        for program in ("systemctl", "loginctl", "curl", "lsof"):
            if self.which(program) is None:
                raise AppError(f"Linux requires {program!r} on PATH.", code="platform_not_ready")
        result = self.run(["systemctl", "--version"])
        match = re.match(r"systemd (\d+)(?:\s|$)", result.stdout)
        if match is None or int(match.group(1)) < 240:
            raise AppError("Linux requires systemd 240 or newer.", code="platform_not_ready")
        bus = self.run(
            ["systemctl", "--user", "show", "--property=Version", "--value"], check=False
        )
        if bus.returncode != 0:
            raise AppError(
                "The systemd user manager is unavailable.",
                hints=("Establish a working user session and user bus before setup.",),
                code="platform_not_ready",
            )
        linger = self.run(
            ["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"],
            check=False,
        )
        if linger.returncode != 0 or linger.stdout.strip() != "yes":
            raise AppError(
                "Persistent Linux operation requires user lingering.",
                hints=(
                    "Ask the host administrator to enable lingering for this user "
                    + "with `loginctl enable-linger USER`; this CLI never runs it.",
                ),
                code="platform_not_ready",
            )
        self._require_private_existing_state()
        if self._replacement_pending():
            _ = self._validate_definition_removal(self._replacement_file)
            return
        if self._paths.service_file.exists() or self._paths.service_file.is_symlink():
            _ = self._file_binary()
            self._validate_effective(self._show(), allow_missing=True, allow_reload=True)
        else:
            self._validate_effective(self._show(), allow_missing=True, allow_reload=True)

    def service(self) -> ConnectorStatus | None:
        """Report only the verified enabled or active canonical connector."""

        self._require_no_retirement()
        self._require_no_replacement()
        values = self._show()
        if (
            values["LoadState"] == "not-found"
            and not self._paths.service_file.exists()
            and not self._paths.service_file.is_symlink()
        ):
            self._require_service_directory()
            self._validate_effective(values, allow_missing=True)
            return None
        binary = self._file_binary()
        self._validate_effective(values, binary=binary)
        if not self._serving(values):
            return None
        return ConnectorStatus(
            pid=_integer(values, "MainPID") or None,
            status=_integer(values, "ExecMainStatus"),
        )

    def is_loaded(self) -> bool:
        return self.service() is not None

    def is_registered(self) -> bool:
        """A known but disabled/inactive unit is not a running registration."""

        return self.is_loaded()

    def conflicting_services(self) -> tuple[str, ...]:
        result = self.run(
            ["systemctl", "--user", "show", "cloudflared.service", "--property=LoadState"],
            check=False,
        )
        if result.returncode != 0:
            raise AppError("Could not establish legacy user-service ownership.")
        return () if result.stdout.strip() == "LoadState=not-found" else ("cloudflared.service",)

    def validate_definition(self) -> Path:
        self._require_no_replacement()
        binary = self._file_binary()
        self._validate_effective(self._show(), binary=binary)
        return binary

    def install(self, binary: Path) -> None:
        """Stop the owned process and clear native old-config custody before replacement."""

        self.preflight()
        definition = render_systemd_unit(self._paths, str(binary))
        self._paths.service_dir.mkdir(parents=True, exist_ok=True)
        self._require_service_directory()
        if self._replacement_pending():
            self._finish_definition_removal(self._replacement_file)
        elif self._paths.service_file.exists():
            previous_binary = self._file_binary()
            values = self._show()
            self._validate_effective(
                values, binary=previous_binary, allow_missing=True, allow_reload=True
            )
            if values["LoadState"] != "not-found":
                self._ctl("disable", "--now", UNIT)
                values = self._show()
                self._validate_effective(values, binary=previous_binary, allow_reload=True)
                if self._serving(values):
                    raise AppError("The connector is still active or enabled after native stop.")
                _ = self._paths.service_file.replace(self._replacement_file)
                self._finish_definition_removal(self._replacement_file)
        self._write_definition(definition)
        self._ctl("daemon-reload")
        _ = self.validate_definition()
        self._ctl("enable", "--now", UNIT)
        self._require_running()

    def _write_definition(self, definition: str) -> None:
        """Atomically install the desired unit after native absence is established."""

        descriptor, temporary = tempfile.mkstemp(
            prefix=".cloudflare-publish-", dir=self._paths.service_dir
        )
        staged = Path(temporary)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                _ = handle.write(definition)
                handle.flush()
                os.fsync(handle.fileno())
            staged.chmod(0o600)
            _ = staged.replace(self._paths.service_file)
        finally:
            staged.unlink(missing_ok=True)

    def start(self) -> None:
        self._require_no_replacement()
        self.preflight()
        _ = self.validate_definition()
        self._ctl("enable", "--now", UNIT)
        self._require_running()

    def _require_running(self) -> None:
        """An enabled unit is not proof that the desired process actually started."""

        values = self._show()
        self._validate_effective(values, binary=self._file_binary())
        if values["ActiveState"] != "active" or _integer(values, "MainPID") <= 0:
            raise AppError("The native connector did not become a running process.")

    def stop(self) -> None:
        """Disable automatic startup and stop, retaining the canonical definition."""

        self._require_no_retirement()
        self._require_no_replacement()
        if not self._paths.service_file.exists() and not self._paths.service_file.is_symlink():
            self._require_service_directory()
            values = self._show()
            self._validate_effective(values, allow_missing=True)
            return
        _ = self.validate_definition()
        self._ctl("disable", "--now", UNIT)
        self.wait_until_stopped()

    def restart(self) -> None:
        self._require_no_replacement()
        self.preflight()
        _ = self.validate_definition()
        if not self.is_loaded():
            raise AppError("Connector is not enabled or active. Run service start first.")
        self._ctl("restart", UNIT)
        self._require_running()

    def wait_until_stopped(self) -> None:
        if self.is_registered():
            raise AppError(
                "The connector is still active or enabled after systemctl disable --now."
            )

    def remove_definition(self) -> None:
        """Remove the owned inactive unit and reload; never delete foreign definitions."""

        self._require_no_replacement()
        if self._retirement_file.exists() or self._retirement_file.is_symlink():
            self._finish_definition_removal(self._retirement_file)
            return
        self.wait_until_stopped()
        if self._paths.service_file.exists() or self._paths.service_file.is_symlink():
            _ = self.validate_definition()
            _ = self._paths.service_file.replace(self._retirement_file)
            self._finish_definition_removal(self._retirement_file)

    @property
    def _replacement_file(self) -> Path:
        """Retain old bytes only until the user manager forgets the old definition."""

        return self._paths.service_file.with_name(".cloudflare-publish.service.replacing")

    def _replacement_pending(self) -> bool:
        return self._replacement_file.exists() or self._replacement_file.is_symlink()

    def _require_no_replacement(self) -> None:
        if self._replacement_pending():
            raise AppError(
                "Connector unit replacement is incomplete; resume setup or tunnel recovery.",
                code="service_replacement_pending",
            )

    @property
    def _retirement_file(self) -> Path:
        """Keep the exact definition across uncertain native removal effects."""

        return self._paths.service_file.with_name(".cloudflare-publish.service.retiring")

    def _require_no_retirement(self) -> None:
        if self._retirement_file.exists() or self._retirement_file.is_symlink():
            raise AppError(
                "Connector unit retirement is incomplete; resume teardown.",
                code="service_retirement_pending",
            )

    def _validate_definition_removal(self, custody: Path) -> Path:
        """Validate stopped old-definition custody without performing native effects."""

        if self._paths.service_file.exists() or self._paths.service_file.is_symlink():
            raise _foreign()
        binary = self._file_binary(custody)
        values = self._show()
        self._validate_effective(values, binary=binary, allow_missing=True, allow_reload=True)
        if self._serving(values):
            raise AppError("The retained connector definition is still active or enabled.")
        return binary

    def _finish_definition_removal(self, custody: Path) -> None:
        binary = self._validate_definition_removal(custody)
        self._ctl("daemon-reload")
        values = self._show()
        self._validate_effective(values, binary=binary, allow_missing=True)
        if values["LoadState"] != "not-found" or self._serving(values):
            raise AppError("The user manager has not confirmed connector unit removal.")
        custody.unlink()

    def _ctl(self, *arguments: str) -> None:
        _ = self.run(["systemctl", "--user", *arguments])

    def _show(self) -> dict[str, str]:
        result = self.run(
            ["systemctl", "--user", "show", UNIT, "--property=" + ",".join(_PROPERTIES)],
            check=False,
        )
        if result.returncode != 0:
            raise AppError(
                "Could not read the systemd user-service state.", code="service_unobserved"
            )
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in _PROPERTIES or key in values:
                raise AppError("The systemd user-service observation is malformed.")
            values[key] = value
        if set(values) != set(_PROPERTIES):
            raise AppError("The systemd user-service observation is incomplete.")
        return values

    def _file_binary(self, definition: Path | None = None) -> Path:
        self._require_service_directory()
        selected = self._paths.service_file if definition is None else definition
        try:
            metadata = selected.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o022
            ):
                raise _foreign()
            text = selected.read_text(encoding="utf-8")
            lines = [
                line.removeprefix("ExecStart=")
                for line in text.splitlines()
                if line.startswith("ExecStart=")
            ]
            if len(lines) != 1:
                raise _foreign()
            arguments = shlex.split(lines[0])
            if not arguments:
                raise _foreign()
            binary = Path(arguments[0].replace("%%", "%"))
            if text != render_systemd_unit(self._paths, str(binary)):
                raise _foreign()
            return binary
        except (OSError, UnicodeError, ValueError) as error:
            raise _foreign() from error

    def _validate_effective(
        self,
        values: dict[str, str],
        *,
        binary: Path | None = None,
        allow_missing: bool = False,
        allow_reload: bool = False,
    ) -> None:
        if values["DropInPaths"]:
            raise _foreign()
        if values["LoadState"] == "not-found":
            if (
                allow_missing
                and not values["FragmentPath"]
                and not values["ExecStart"]
                and not self._serving(values)
            ):
                return
            raise _foreign()
        if values["LoadState"] != "loaded" or values["FragmentPath"] != str(
            self._paths.service_file
        ):
            raise _foreign()
        if not allow_reload and values["NeedDaemonReload"] != "no":
            raise AppError(
                "The user manager needs daemon-reload; run setup to reconcile the owned unit."
            )
        selected = self._file_binary() if binary is None else binary
        start = values["ExecStart"]
        match = re.fullmatch(
            r"\{ path=(.*?) ; argv\[\]=(.*?) ; ignore_errors=no ; [^{}]* \}", start
        )
        expected_arguments = " ".join(
            (
                str(selected),
                "tunnel",
                "run",
                "--token-file",
                str(self._paths.tunnel_token_file).replace("$", "$$"),
            )
        )
        if match is None or match.group(1) != str(selected) or match.group(2) != expected_arguments:
            raise _foreign()

    def _require_private_existing_state(self) -> None:
        for directory in (self._paths.state_dir, self._paths.logs_dir):
            _ = private_directory_available(directory)
        _ = read_private_file(
            self._paths.tunnel_token_file.parent,
            self._paths.tunnel_token_file.name,
            max_bytes=65536,
        )
        for log_file in (self._paths.stdout_log_file, self._paths.stderr_log_file):
            if not log_file.exists() and not log_file.is_symlink():
                continue
            metadata = log_file.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise AppError("Linux connector logs must be owned private regular files (0600).")
        self._require_service_directory()

    def _require_service_directory(self) -> None:
        """Reject redirected or writable ancestry before reading or changing the unit."""

        directory = self._paths.service_dir
        while True:
            if directory.exists() or directory.is_symlink():
                metadata = directory.lstat()
                root_sticky = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid not in {0, os.getuid()}
                    or metadata.st_mode & 0o022
                    and not root_sticky
                ):
                    raise _foreign()
            if directory == directory.parent:
                return
            directory = directory.parent

    @staticmethod
    def _serving(values: dict[str, str]) -> bool:
        return (
            values["ActiveState"] not in {"inactive", "failed"}
            or values["UnitFileState"] not in {"disabled", "", "not-found"}
            or _integer(values, "MainPID") > 0
        )


def _integer(values: dict[str, str], key: str) -> int:
    value = values[key]
    if not value.isdecimal():
        raise AppError("The native service process observation is malformed.")
    return int(value)


def _foreign() -> AppError:
    return AppError(
        "The systemd user unit is not the exact owned connector definition.",
        hints=(
            "Resolve foreign unit files, overrides or ExecStart drift explicitly; "
            + "no takeover is supported.",
        ),
        code="service_ownership_conflict",
    )
