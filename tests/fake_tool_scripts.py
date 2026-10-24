"""Fake binary script bodies for hermetic CLI tests."""

from __future__ import annotations

import stat
from pathlib import Path


def initial_tool_state() -> str:
    """Return the initial JSON state for fake binaries."""

    return (
        "{\n"
        '  "cloudflared_version": "cloudflared version 2026.3.0",\n'
        '  "launchd_labels": [],\n'
        '  "launchd_pids": {},\n'
        '  "launchd_statuses": {},\n'
        '  "launchctl_fail_bootstrap_once": false,\n'
        '  "launchctl_fail_bootout_once": false,\n'
        '  "launchctl_bootout_linger_checks": 0,\n'
        '  "launchctl_bootout_lingering_label": null,\n'
        '  "launchctl_bootout_lingering_remaining": 0,\n'
        '  "launchctl_kickstart_count": 0,\n'
        '  "brew_calls": 0,\n'
        '  "keychain": {},\n'
        '  "cloudflare": {\n'
        '    "accounts": [{"id": "acc-123", "name": "Example Account"}],\n'
        '    "zones": [{"id": "zone-123", "name": "example.com", '
        '"account": {"id": "acc-123"}, "status": "active", "type": "full"}],\n'
        '    "organization": {"auth_domain": "example.cloudflareaccess.com", '
        '"deny_unmatched_requests": false, '
        '"deny_unmatched_requests_exempted_zone_names": [], '
        '"is_ui_read_only": true},\n'
        '    "fail_tunnel_config_put_once": false,\n'
        '    "tunnels": {},\n'
        '    "tunnel_configurations": {},\n'
        '    "cleaned_tunnel_ids": [],\n'
        '    "dns_records": {},\n'
        '    "access_apps": {},\n'
        '    "access_policies": {},\n'
        '    "service_tokens": {},\n'
        '    "next_ids": {"tunnel": 1, "dns": 1, "app": 1, "policy": 1, "token": 1, "secret": 1}\n'
        "  }\n"
        "}\n"
    )


def write_executable(path: Path, content: str) -> None:
    """Write an executable helper script."""

    _ = path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def cloudflared_script() -> str:
    """Return the fake cloudflared helper script."""

    return """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ.get(
    "CLOUDFLARE_PUBLISH_TEST_STATE",
    str(Path(__file__).resolve().parent.parent / "fake-tool-state.json"),
))
state = json.loads(state_path.read_text(encoding="utf-8"))

if sys.argv[1:] == ["--version"]:
    print(state["cloudflared_version"])
    raise SystemExit(0)

if sys.argv[1:3] == ["access", "ssh"]:
    args = sys.argv[1:]
    hostname = args[args.index("--hostname") + 1]
    calls = state.setdefault("ssh_proxy_calls", [])
    calls.append({
        "hostname": hostname,
        "has_client_id": bool(os.environ.get("TUNNEL_SERVICE_TOKEN_ID")),
        "has_client_secret": bool(os.environ.get("TUNNEL_SERVICE_TOKEN_SECRET")),
    })
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
    cf = state["cloudflare"]
    apps = [app for app in cf["access_apps"].values() if app["domain"] == hostname]
    if len(apps) != 1 or apps[0].get("service_auth_401_redirect") is not True:
        raise SystemExit(1)
    app = apps[0]
    for policy in cf["access_policies"].values():
        if policy["app_id"] != app["id"] or policy["decision"] != "non_identity":
            continue
        for include in policy["include"]:
            token_id = include.get("service_token", {}).get("token_id")
            token = cf["service_tokens"].get(token_id)
            if token is not None and (
                token["client_id"] == os.environ.get("TUNNEL_SERVICE_TOKEN_ID")
                and token["client_secret"] == os.environ.get("TUNNEL_SERVICE_TOKEN_SECRET")
            ):
                raise SystemExit(0)
    raise SystemExit(1)

sys.stderr.write(f"unsupported cloudflared args: {sys.argv[1:]}\\n")
raise SystemExit(1)
"""


def ssh_script() -> str:
    """Return isolated fake SSH that exercises the proxy and writes a private proof trace."""

    return """#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

state_path = Path(__file__).resolve().parent.parent / "fake-tool-state.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]
options = {}
for index, value in enumerate(args[:-1]):
    if value == "-o":
        key, _, value = args[index + 1].partition("=")
        options[key] = value
proxy = options.get("ProxyCommand")
calls = state.setdefault("ssh_probe_calls", [])
calls.append({"transport": "public" if proxy else "origin", "host": args[-1]})
state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
if proxy:
    command = shlex.split(proxy)
    if command[:1] == ["exec"]:
        command = command[1:]
    completed = subprocess.run(command, env=os.environ, check=False)
    if completed.returncode != 0:
        raise SystemExit(255)
known_hosts_path = Path(shlex.split(options["UserKnownHostsFile"])[0])
known_hosts = known_hosts_path.read_text(encoding="utf-8").strip()
expected = state.get("ssh_host_key")
actual = " ".join(known_hosts.split()[1:3])
if expected is not None and actual != expected:
    raise SystemExit(255)
if state.get("ssh_probe_failure") is True:
    raise SystemExit(255)
trace = Path(args[args.index("-E") + 1])
trace.write_text("debug1: SSH2_MSG_SERVICE_ACCEPT received\\n", encoding="utf-8")
raise SystemExit(255)
"""


def launchctl_script() -> str:
    """Return the fake launchctl helper script."""

    return """#!/usr/bin/env python3
import json
import os
import plistlib
import sys
from pathlib import Path

state_path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]
if state.get("record_native_calls"):
    state.setdefault("launchctl_calls", []).append(args)
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")

def save() -> None:
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")

def remove_label(label: str) -> None:
    state["launchd_labels"] = [item for item in state["launchd_labels"] if item != label]
    state.setdefault("launchd_pids", {}).pop(label, None)
    state.setdefault("launchd_statuses", {}).pop(label, None)
    if label == "com.cloudflare-publish.cloudflared":
        for tunnel_id, clients in state["cloudflare"].setdefault("tunnel_connections", {}).items():
            state["cloudflare"]["tunnel_connections"][tunnel_id] = [
                client for client in clients if client["id"] != "local-client"
            ]

def connect_local(label: str) -> None:
    if label != "com.cloudflare-publish.cloudflared":
        return
    cf = state["cloudflare"]
    for tunnel_id in cf["tunnels"]:
        clients = cf.setdefault("tunnel_connections", {}).setdefault(tunnel_id, [])
        clients[:] = [client for client in clients if client["id"] != "local-client"]
        clients.append({
            "id": "local-client",
            "config_version": cf["tunnel_configurations"][tunnel_id].get("version", 0),
            "conns": [{"id": "local-connection", "is_pending_reconnect": False}],
        })

def reported_labels() -> list[str]:
    labels = list(state["launchd_labels"])
    label = state.get("launchctl_bootout_lingering_label")
    remaining = state.get("launchctl_bootout_lingering_remaining", 0)
    if isinstance(label, str) and isinstance(remaining, int) and remaining > 0:
        state["launchctl_bootout_lingering_remaining"] = remaining - 1
        if remaining - 1 == 0:
            remove_label(label)
            state["launchctl_bootout_lingering_label"] = None
        save()
    return labels

if args == ["list"]:
    for label in reported_labels():
        pid = state.get("launchd_pids", {}).get(label, "-")
        status = state.get("launchd_statuses", {}).get(label, 0)
        print(f"{pid}\\t{status}\\t{label}")
    raise SystemExit(0)

if args[:1] == ["print"]:
    label = args[-1].split("/")[-1]
    if label in reported_labels():
        print(f"gui/{os.getuid()}/{label} = {{")
        print("}")
        raise SystemExit(0)
    sys.stderr.write(f'Could not find service "{label}"\\n')
    raise SystemExit(113)

if args[:2] == ["bootstrap", f"gui/{os.getuid()}"]:
    if state.get("launchctl_fail_bootstrap_once") is True:
        state["launchctl_fail_bootstrap_once"] = False
        save()
        sys.stderr.write("bootstrap failed\\n")
        raise SystemExit(1)
    plist_path = Path(args[2])
    with plist_path.open("rb") as handle:
        payload = plistlib.load(handle)
    label = payload["Label"]
    if label in state["launchd_labels"]:
        sys.stderr.write("bootstrap operation already in progress\\n")
        raise SystemExit(1)
    if label not in state["launchd_labels"]:
        state["launchd_labels"].append(label)
    state.setdefault("launchd_pids", {})[label] = 1234
    state.setdefault("launchd_statuses", {})[label] = 0
    connect_local(label)
    save()
    raise SystemExit(0)

if args[:1] == ["bootout"]:
    if state.get("launchctl_fail_bootout_once") is True:
        state["launchctl_fail_bootout_once"] = False
        save()
        sys.stderr.write("bootout failed\\n")
        raise SystemExit(1)
    label = args[-1].split("/")[-1]
    linger_checks = state.get("launchctl_bootout_linger_checks", 0)
    if isinstance(linger_checks, int) and linger_checks > 0:
        state["launchctl_bootout_lingering_label"] = label
        state["launchctl_bootout_lingering_remaining"] = linger_checks
    else:
        remove_label(label)
    save()
    raise SystemExit(0)

if args[:2] == ["kickstart", "-k"]:
    label = args[-1].split("/")[-1]
    state["launchctl_kickstart_count"] = state.get("launchctl_kickstart_count", 0) + 1
    if label not in state["launchd_labels"]:
        state["launchd_labels"].append(label)
    state.setdefault("launchd_pids", {})[label] = 1234
    state.setdefault("launchd_statuses", {})[label] = 0
    connect_local(label)
    save()
    raise SystemExit(0)

sys.stderr.write(f"unsupported launchctl args: {args}\\n")
raise SystemExit(1)
"""


def security_script() -> str:
    """Return the fake macOS Keychain helper script."""

    return """#!/usr/bin/env python3
import json
import os
import shlex
import sys
from pathlib import Path

state_path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]
process_args = list(args)
if state.get("record_native_calls"):
    state.setdefault("security_calls", []).append(process_args)
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
if args == ["-q", "-i"]:
    args = shlex.split(sys.stdin.readline())

def save() -> None:
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")

def key(service: str, account: str) -> str:
    return f"{service}:{account}"

if args[:1] == ["add-generic-password"]:
    account = args[args.index("-a") + 1]
    service = args[args.index("-s") + 1]
    if "-X" in args:
        secret = bytes.fromhex(args[args.index("-X") + 1]).decode("utf-8")
    else:
        # Native security does not consume a non-TTY stdin password for bare -w.
        secret = "" if args[-1] == "-w" else args[args.index("-w") + 1]
    state["keychain"][key(service, account)] = secret
    state["last_security_argv"] = process_args
    save()
    raise SystemExit(0)

if args[:1] == ["find-generic-password"]:
    account = args[args.index("-a") + 1]
    service = args[args.index("-s") + 1]
    secret = state["keychain"].get(key(service, account))
    if secret is None:
        raise SystemExit(44)
    if "-w" in args:
        print(secret)
    raise SystemExit(0)

if args[:1] == ["delete-generic-password"]:
    account = args[args.index("-a") + 1]
    service = args[args.index("-s") + 1]
    if state.get("security_fail_delete_once_account") == key(service, account):
        state.pop("security_fail_delete_once_account")
        save()
        sys.stderr.write("security fake: deletion refused\\n")
        raise SystemExit(51)
    state["keychain"].pop(key(service, account), None)
    save()
    raise SystemExit(0)

sys.stderr.write(f"unsupported security args: {args}\\n")
raise SystemExit(1)
"""


def brew_script() -> str:
    """Return the fake Homebrew helper script."""

    return """#!/usr/bin/env python3
import json
import os
import shutil
import sys
from pathlib import Path

state_path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
bin_dir = Path(os.environ["CLOUDFLARE_PUBLISH_FAKE_BIN_DIR"])
args = sys.argv[1:]

if args == ["install", "cloudflared"]:
    state["brew_calls"] += 1
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")
    shutil.copy2(bin_dir / "cloudflared-source", bin_dir / "cloudflared")
    raise SystemExit(0)

sys.stderr.write(f"unsupported brew args: {args}\\n")
raise SystemExit(1)
"""


def plutil_script() -> str:
    """Return the fake plist validation helper script."""

    return """#!/usr/bin/env python3
raise SystemExit(0)
"""
