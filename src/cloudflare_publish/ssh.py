"""Bounded native OpenSSH identity probes without login credentials."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from cloudflare_publish.errors import AppError

_ED25519_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
_PROOF_LINE = "debug1: SSH2_MSG_SERVICE_ACCEPT received"
_MAX_LOG_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SshProbeResult:
    """Secret-free transport identity result, not a login or forwarding result."""

    ok: bool
    detail: str


def validate_ssh_host_key(value: str) -> str:
    """Normalize one ordinary Ed25519 public host key, rejecting injected records."""

    error = "SSH host key must be one valid ssh-ed25519 public key."
    if any(character in value for character in ("\r", "\n", "\x00")):
        raise AppError(error)
    parts = value.split(maxsplit=2)
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise AppError(error)
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AppError(error) from exc
    if len(blob) != len(_ED25519_PREFIX) + 32 or not blob.startswith(_ED25519_PREFIX):
        raise AppError(error)
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')}"


class SshProbe:
    """Prove signed key exchange with a pinned host using the native SSH client."""

    def __init__(self, ssh_binary: str | None = None, timeout_seconds: float = 15.0) -> None:
        """Choose a client and a finite deadline for its complete process group."""

        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise AppError("SSH probe timeout must be finite and positive.")
        self._ssh_binary: str = ssh_binary or "ssh"
        self._timeout_seconds: float = timeout_seconds

    def probe(
        self,
        host: str,
        port: int,
        host_key: str,
        host_key_alias: str,
        *,
        cloudflared_binary: str | None = None,
        service_token_client_id: str | None = None,
        service_token_client_secret: str | None = None,
    ) -> SshProbeResult:
        """Verify identity directly or through cloudflared; never attempt a login."""

        try:
            normalized_key = validate_ssh_host_key(host_key)
        except AppError:
            return SshProbeResult(False, "SSH host-key pin is invalid.")
        if (
            not _valid_host(host)
            or not 1 <= port <= 65535
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", host_key_alias) is None
        ):
            return SshProbeResult(False, "SSH probe endpoint or host-key alias is invalid.")
        if (service_token_client_id is None) != (service_token_client_secret is None):
            return SshProbeResult(False, "SSH probe requires both service-token credentials.")
        credentials = (service_token_client_id, service_token_client_secret)
        if any(value is not None and not _valid_credential(value) for value in credentials):
            return SshProbeResult(False, "SSH probe service-token credentials are invalid.")
        if cloudflared_binary is None and service_token_client_id is not None:
            return SshProbeResult(False, "Service tokens require the cloudflared transport.")
        try:
            binary = shutil.which(self._ssh_binary)
            if binary is None:
                return SshProbeResult(False, "OpenSSH client is unavailable.")
            proxy_binary = None
            if cloudflared_binary is not None:
                if not _valid_dns_host(host):
                    return SshProbeResult(False, "Cloudflared requires an exact DNS hostname.")
                proxy_binary = shutil.which(cloudflared_binary)
                if proxy_binary is None:
                    return SshProbeResult(False, "Cloudflared client is unavailable.")
            with tempfile.TemporaryDirectory(prefix="cloudflare-publish-ssh-") as temporary:
                directory = Path(temporary)
                environment = _isolated_environment(directory)
                if service_token_client_id is not None and service_token_client_secret is not None:
                    environment["TUNNEL_SERVICE_TOKEN_ID"] = service_token_client_id
                    environment["TUNNEL_SERVICE_TOKEN_SECRET"] = service_token_client_secret
                known_hosts = directory / "known_hosts"
                _ = known_hosts.write_text(f"{host_key_alias} {normalized_key}\n", encoding="utf-8")
                known_hosts.chmod(0o600)
                trace = directory / "ssh.log"
                trace.touch(mode=0o600)
                command = _probe_command(
                    str(Path(binary).resolve()),
                    host,
                    port,
                    host_key_alias,
                    known_hosts,
                    trace,
                    str(Path(proxy_binary).resolve()) if proxy_binary is not None else None,
                )
                return self._run(command, environment, directory, trace)
        except OSError:
            return SshProbeResult(False, "SSH probe could not use its client or private files.")

    def _run(
        self, command: list[str], environment: dict[str, str], directory: Path, trace: Path
    ) -> SshProbeResult:
        """Bound and reap SSH and its proxy, including on interruption or early exit."""

        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=directory,
                env=environment,
                start_new_session=True,
            )
            try:
                _ = process.wait(timeout=self._timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if process is not None:
                _stop_process_group(process)
        with trace.open("rb") as log_file:
            content = log_file.read(_MAX_LOG_BYTES + 1)
        if (
            len(content) <= _MAX_LOG_BYTES
            and _PROOF_LINE in content.decode("utf-8", errors="replace").splitlines()
        ):
            return SshProbeResult(
                True, "Pinned SSH host identity verified by signed key exchange; login not tested."
            )
        if timed_out:
            return SshProbeResult(False, "SSH identity probe exceeded its connection deadline.")
        return SshProbeResult(False, "SSH did not complete key exchange with the pinned host.")


def _probe_command(
    binary: str,
    host: str,
    port: int,
    alias: str,
    known_hosts: Path,
    trace: Path,
    proxy_binary: str | None,
) -> list[str]:
    """Ignore user configuration, credentials, DNS trust and forwarding defaults."""

    command = [binary, "-F", "/dev/null", "-T", "-N", "-vv", "-E", str(trace)]
    escaped_known_hosts = str(known_hosts).replace("\\", "\\\\").replace('"', '\\"')
    options = [
        "StrictHostKeyChecking=yes",
        f'UserKnownHostsFile="{escaped_known_hosts}"',
        "GlobalKnownHostsFile=/dev/null",
        f"HostKeyAlias={alias}",
        "HostKeyAlgorithms=ssh-ed25519",
        "VerifyHostKeyDNS=no",
        "UpdateHostKeys=no",
        "BatchMode=yes",
        "PreferredAuthentications=none",
        "PubkeyAuthentication=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "IdentityFile=none",
        "IdentityAgent=none",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "PermitLocalCommand=no",
        "ControlMaster=no",
        "ControlPath=none",
        "ProxyJump=none",
    ]
    if proxy_binary is not None:
        proxy = [proxy_binary, "access", "ssh", "--hostname", host, "--loglevel", "error"]
        # OpenSSH adds its own exec before passing the command to the shell.
        # OpenSSH expands percent tokens even inside shell quotes in ProxyCommand.
        options.append(f"ProxyCommand={shlex.join(proxy).replace('%', '%%')}")
    for option in options:
        command.extend(["-o", option])
    command.extend(["-p", str(port), "-l", "cloudflare-publish-probe", host])
    return command


def _isolated_environment(directory: Path) -> dict[str, str]:
    """Exclude ambient credentials and contain cloudflared's login fallback."""

    private_bin = directory / "bin"
    private_bin.mkdir(mode=0o700)
    for launcher in ("open", "xdg-open"):
        blocker = private_bin / launcher
        _ = blocker.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        blocker.chmod(0o700)
    for child in ("home", "config", "cache", "state", "tmp"):
        (directory / child).mkdir(mode=0o700)
    # cloudflared calls `open` / `xdg-open` directly, not the BROWSER variable.
    return {
        "PATH": f"{private_bin}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
        "HOME": str(directory / "home"),
        "XDG_CONFIG_HOME": str(directory / "config"),
        "XDG_CACHE_HOME": str(directory / "cache"),
        "XDG_STATE_HOME": str(directory / "state"),
        "TMPDIR": str(directory / "tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "SSH_ASKPASS_REQUIRE": "never",
    }


def _valid_host(host: str) -> bool:
    """Accept literal IP addresses or a non-option DNS name, never SSH syntax."""

    try:
        _ = ipaddress.ip_address(host)
        return "%" not in host
    except ValueError:
        return _valid_dns_host(host)


def _valid_dns_host(host: str) -> bool:
    """Keep hostnames safe both in argv and cloudflared's shell proxy command."""

    if len(host) > 253:
        return False
    return all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is not None
        for label in host.split(".")
    )


def _valid_credential(value: str) -> bool:
    """Reject empty credentials and HTTP-header/control-character injection."""

    return bool(value) and all(32 <= ord(character) < 127 for character in value)


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill any surviving proxy children even after the SSH parent has exited."""

    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    _ = process.wait()
