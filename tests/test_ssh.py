"""Hermetic host-key validation and native-client probe containment tests."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict, cast

import pytest

from cloudflare_publish.errors import AppError
from cloudflare_publish.ssh import SshProbe, SshProbeResult, validate_ssh_host_key

_KEY_BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
_KEY = "ssh-ed25519 " + base64.b64encode(_KEY_BLOB).decode("ascii")
_PROOF = "debug1: SSH2_MSG_SERVICE_ACCEPT received\n"


class _IsolationCapture(TypedDict):
    args: list[str]
    environment: dict[str, str]
    cwd: str
    known: str
    known_mode: int
    trace_mode: int
    browser_exit: int


class _TokenCapture(TypedDict):
    args: list[str]
    env: dict[str, str]


def _fake_ssh(directory: Path, body: str) -> Path:
    """Write a fake client that has the same private-log argument as OpenSSH."""

    binary = directory / "fake ssh"
    _ = binary.write_text(
        f"#!{sys.executable}\n"
        "import json, os, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "trace = Path(args[args.index('-E') + 1])\n" + body,
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return binary


def _probe(binary: Path, **kwargs: str) -> SshProbeResult:
    """Run one fake identity exchange with a valid public pin."""

    return SshProbe(str(binary)).probe("127.0.0.1", 22, _KEY, "ssh.example.com", **kwargs)


def _assert_stopped(pid: int) -> None:
    """A killed descendant may briefly be a zombie but must not execute."""

    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        result = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)],
            capture_output=True,
            check=False,
            text=True,
        )
        if not result.stdout.strip() or result.stdout.lstrip().startswith("Z"):
            return
        time.sleep(0.01)
    pytest.fail("SSH probe left an executing process behind")


def test_host_key_normalizes_comment_and_spacing() -> None:
    """Only the key's public algorithm and canonical base64 reach state."""

    assert validate_ssh_host_key(f"  {_KEY}  local host comment ") == _KEY


@pytest.mark.parametrize(
    "key",
    [
        "",
        "ssh-ed25519",
        "ssh-rsa AAAA",
        "ssh-ed25519 !!!",
        "ssh-ed25519 " + base64.b64encode(b"ssh-ed25519" + bytes(32)).decode(),
        "ssh-ed25519 " + base64.b64encode(_KEY_BLOB + b"extra").decode(),
        _KEY + "\nother-host " + _KEY,
        _KEY + "\rcomment",
        _KEY + "\x00comment",
        "@cert-authority " + _KEY,
        "from=example.com " + _KEY,
    ],
)
def test_host_key_rejects_wrong_type_wire_format_and_record_injection(key: str) -> None:
    """A pin cannot become a certificate authority or multiple known_hosts records."""

    with pytest.raises(AppError, match="one valid ssh-ed25519 public key"):
        _ = validate_ssh_host_key(key)


def test_probe_accepts_post_kex_proof_in_native_log(tmp_path: Path) -> None:
    """Exit 255 is expected without credentials; signed key exchange is the proof."""

    binary = _fake_ssh(tmp_path, f"trace.write_text({_PROOF!r})\nraise SystemExit(255)\n")
    result = _probe(binary)
    assert result.ok
    assert "login not tested" in result.detail


@pytest.mark.parametrize(
    "body",
    [
        "trace.write_text(\"debug1: Host 'ssh.example.com' is known and matches "
        'the ED25519 host key.\\n")\n',
        f"sys.stderr.write({_PROOF!r})\n",
        f"trace.write_text('banner: ' + {_PROOF!r})\n",
        "trace.write_text('debug1: SSH2_MSG_SERVICE_ACCEPT received extra\\n')\n",
    ],
)
def test_probe_requires_exact_proof_in_ssh_owned_log(tmp_path: Path, body: str) -> None:
    """A key match alone, proxy stderr or a prefixed banner is not signed KEX proof."""

    assert not _probe(_fake_ssh(tmp_path, body)).ok


def test_probe_isolates_configuration_credentials_and_browser_launch(tmp_path: Path) -> None:
    """Native options and an allowlisted environment cannot reuse ambient identity."""

    capture = tmp_path / "capture.json"
    body = (
        "options = [args[i + 1] for i, value in enumerate(args[:-1]) if value == '-o']\n"
        "known = next(value.split('=', 1)[1].strip(chr(34)) for value in options "
        "if value.startswith('UserKnownHostsFile='))\n"
        "launch = subprocess.run(['open', 'https://example.invalid'], check=False)\n"
        f"Path({str(capture)!r}).write_text(json.dumps({{"
        "'args': args, 'environment': dict(os.environ), 'cwd': os.getcwd(), "
        "'known': Path(known).read_text(), 'known_mode': Path(known).stat().st_mode & 0o777, "
        "'trace_mode': trace.stat().st_mode & 0o777, 'browser_exit': launch.returncode}))\n"
        f"trace.write_text({_PROOF!r})\n"
    )
    binary = _fake_ssh(tmp_path, body)
    original = dict(os.environ)
    try:
        os.environ["TUNNEL_SERVICE_TOKEN_ID"] = "ambient-id"
        os.environ["TUNNEL_SERVICE_TOKEN_SECRET"] = "ambient-secret"
        os.environ["SSH_AUTH_SOCK"] = "/ambient/agent.sock"
        os.environ["CF_ACCESS_TOKEN"] = "ambient-token"
        assert _probe(binary).ok
    finally:
        os.environ.clear()
        os.environ.update(original)
    observed = cast(_IsolationCapture, cast(object, json.loads(capture.read_text())))
    args = observed["args"]
    assert args[:2] == ["-F", "/dev/null"]
    assert "StrictHostKeyChecking=yes" in args
    assert "IdentityFile=none" in args
    assert "IdentityAgent=none" in args
    assert "PreferredAuthentications=none" in args
    assert "HostKeyAlgorithms=ssh-ed25519" in args
    assert "ClearAllForwardings=yes" in args
    assert "UpdateHostKeys=no" in args
    assert "VerifyHostKeyDNS=no" in args
    assert observed["known"] == f"ssh.example.com {_KEY}\n"
    assert observed["known_mode"] == observed["trace_mode"] == 0o600
    assert observed["browser_exit"] != 0
    assert Path(observed["environment"]["HOME"]).resolve().parent == Path(observed["cwd"])
    for variable in (
        "TUNNEL_SERVICE_TOKEN_ID",
        "TUNNEL_SERVICE_TOKEN_SECRET",
        "SSH_AUTH_SOCK",
        "CF_ACCESS_TOKEN",
    ):
        assert variable not in observed["environment"]
    assert not Path(observed["cwd"]).exists()


def test_cloudflared_tokens_are_environment_only_and_output_is_sanitized(tmp_path: Path) -> None:
    """Neither process arguments nor returned diagnostics contain service secrets."""

    capture = tmp_path / "capture.json"
    body = (
        f"Path({str(capture)!r}).write_text("
        "json.dumps({'args': args, 'env': dict(os.environ)}))\n"
        "trace.write_text(os.environ['TUNNEL_SERVICE_TOKEN_SECRET'])\n"
        "sys.stderr.write(os.environ['TUNNEL_SERVICE_TOKEN_SECRET'])\n"
    )
    binary = _fake_ssh(tmp_path, body)
    result = SshProbe(str(binary)).probe(
        "ssh.example.com",
        22,
        _KEY,
        "ssh.example.com",
        cloudflared_binary=str(binary),
        service_token_client_id="owned-client-id",
        service_token_client_secret="owned-client-secret",
    )
    observed = cast(_TokenCapture, cast(object, json.loads(capture.read_text())))
    assert not result.ok
    assert "owned-client" not in result.detail
    assert "owned-client" not in " ".join(observed["args"])
    assert observed["env"]["TUNNEL_SERVICE_TOKEN_ID"] == "owned-client-id"
    assert observed["env"]["TUNNEL_SERVICE_TOKEN_SECRET"] == "owned-client-secret"
    proxy = next(value for value in observed["args"] if value.startswith("ProxyCommand="))
    assert "access ssh --hostname ssh.example.com --loglevel error" in proxy


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="Requires the native macOS OpenSSH client")
def test_native_openssh_executes_quoted_proxy_without_duplicate_exec(tmp_path: Path) -> None:
    """The real client and shell must execute the proxy, not `exec exec ...`."""

    capture = tmp_path / "proxy-invocation.json"
    proxy = tmp_path / "proxy 'quoted' %h $ literal"
    _ = proxy.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        f"Path({str(capture)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        "sys.stdout.buffer.write(b'SSH-2.0-controlled-proxy\\r\\n')\n"
        "sys.stdout.buffer.flush()\n",
        encoding="utf-8",
    )
    proxy.chmod(0o700)

    result = SshProbe("/usr/bin/ssh").probe(
        "127.0.0.1",
        22,
        _KEY,
        "ssh.example.com",
        cloudflared_binary=str(proxy),
    )

    # This helper uses no sockets and deliberately cannot complete signed KEX.
    # The marker proves OpenSSH's actual ProxyCommand parser reached the helper.
    assert not result.ok
    assert json.loads(capture.read_text()) == [
        "access",
        "ssh",
        "--hostname",
        "127.0.0.1",
        "--loglevel",
        "error",
    ]


@pytest.mark.parametrize("hang", [True, False])
def test_probe_kills_proxy_descendants_on_timeout_and_parent_exit(
    tmp_path: Path, hang: bool
) -> None:
    """The whole process group ends even when SSH exits before its proxy."""

    capture = tmp_path / "child-pid"
    body = (
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"Path({str(capture)!r}).write_text(str(child.pid))\n"
        + ("time.sleep(60)\n" if hang else f"trace.write_text({_PROOF!r})\n")
    )
    binary = _fake_ssh(tmp_path, body)
    result = SshProbe(str(binary), timeout_seconds=0.5).probe(
        "127.0.0.1", 22, _KEY, "ssh.example.com"
    )
    assert result.ok is not hang
    _assert_stopped(int(capture.read_text()))


def test_probe_reaps_on_interrupt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An interrupted caller does not leave an SSH client or proxy executing."""

    binary = _fake_ssh(tmp_path, "time.sleep(60)\n")
    original_wait = cast(
        Callable[[subprocess.Popen[bytes], float | None], int], subprocess.Popen.wait
    )
    interrupted_pids: list[int] = []

    def interrupted_wait(process: subprocess.Popen[bytes], timeout: float | None = None) -> int:
        if not interrupted_pids:
            interrupted_pids.append(process.pid)
            raise KeyboardInterrupt
        return original_wait(process, timeout)

    monkeypatch.setattr(subprocess.Popen, "wait", interrupted_wait)
    with pytest.raises(KeyboardInterrupt):
        _ = _probe(binary)
    _assert_stopped(interrupted_pids[0])


@pytest.mark.parametrize("host", ["-oProxyCommand=bad", "host;bad", "host\nother", "user@host"])
def test_probe_rejects_non_endpoint_syntax(tmp_path: Path, host: str) -> None:
    """Even a direct adapter caller cannot inject SSH options or proxy shell text."""

    binary = _fake_ssh(tmp_path, f"trace.write_text({_PROOF!r})\n")
    assert not SshProbe(str(binary)).probe(host, 22, _KEY, "ssh.example.com").ok


def test_probe_supports_loopback_ipv6(tmp_path: Path) -> None:
    """A normalized IPv6 origin is a literal SSH endpoint, not bracketed URL syntax."""

    binary = _fake_ssh(tmp_path, f"trace.write_text({_PROOF!r})\n")
    assert SshProbe(str(binary)).probe("::1", 22, _KEY, "ssh.example.com").ok


def test_probe_rejects_partial_credentials_and_missing_binaries(tmp_path: Path) -> None:
    """Incomplete auth and missing clients fail without exposing their inputs."""

    binary = _fake_ssh(tmp_path, f"trace.write_text({_PROOF!r})\n")
    assert (
        not SshProbe(str(binary))
        .probe("ssh.example.com", 22, _KEY, "ssh.example.com", service_token_client_id="id")
        .ok
    )
    assert (
        not SshProbe(str(tmp_path / "missing")).probe("127.0.0.1", 22, _KEY, "ssh.example.com").ok
    )


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("inf"), float("nan")])
def test_probe_rejects_unbounded_or_invalid_timeout(timeout: float) -> None:
    """No caller can accidentally create an unlimited probe."""

    with pytest.raises(AppError):
        _ = SshProbe(timeout_seconds=timeout)
