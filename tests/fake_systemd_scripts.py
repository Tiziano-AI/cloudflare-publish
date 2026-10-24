"""Bounded native user-service fakes backed by the existing hermetic API state."""

from __future__ import annotations


def systemctl_script() -> str:
    """Model only the exact user-manager commands owned by the Linux adapter."""

    return r"""#!/usr/bin/env python3
import json
import os
import shlex
import sys
from pathlib import Path

state_path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]
state.setdefault("systemctl_calls", []).append(args)
unit = "cloudflare-publish.service"
unit_path = Path.home() / ".config/systemd/user" / unit
connector_id = "00000000-0000-4000-8000-000000000001"

def save():
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

def disconnect():
    cf = state["cloudflare"]
    for tunnel_id, clients in cf.setdefault("tunnel_connections", {}).items():
        cf["tunnel_connections"][tunnel_id] = [
            client for client in clients if client["id"] != connector_id
        ]

def connect():
    # Starting an inactive service captures the executable and token then in use.
    # daemon-reload and enable --now do not change an already-running process.
    generation = state.get("systemd_start_count", 0) + 1
    state["systemd_start_count"] = generation
    state["systemd_pid"] = 1233 + generation
    state["systemd_running_definition"] = state["systemd_loaded_definition"]
    token_path = Path.home() / ".local/state/cloudflare-publish/tunnel-token.txt"
    state["systemd_running_token"] = token_path.read_text(encoding="utf-8").strip()
    state["systemd_enabled"] = True
    state["systemd_active"] = True
    state["native_connector_id"] = connector_id
    cf = state["cloudflare"]
    manifest_path = Path.home() / ".local/state/cloudflare-publish/state.json"
    tunnel_id = json.loads(manifest_path.read_text(encoding="utf-8"))["manager"]["tunnel_id"]
    if tunnel_id in cf["tunnels"]:
        clients = cf.setdefault("tunnel_connections", {}).setdefault(tunnel_id, [])
        clients[:] = [client for client in clients if client["id"] != connector_id]
        clients.append({
            "id": connector_id,
            "config_version": cf["tunnel_configurations"][tunnel_id].get("version", 0),
            "conns": [{"id": "linux-connection", "is_pending_reconnect": False}],
        })

def properties():
    definition = state.get("systemd_loaded_definition")
    loaded = isinstance(definition, str)
    arguments = []
    if loaded:
        line = next(line for line in definition.splitlines() if line.startswith("ExecStart="))
        arguments = shlex.split(line.removeprefix("ExecStart="))
        arguments = [argument.replace("%%", "%") for argument in arguments]
    binary = arguments[0] if arguments else ""
    current = unit_path.read_text(encoding="utf-8") if unit_path.exists() else None
    values = {
        "LoadState": "loaded" if loaded else "not-found",
        "ActiveState": "active" if state.get("systemd_active") else "inactive",
        "MainPID": str(state["systemd_pid"]) if state.get("systemd_active") else "0",
        "ExecMainStatus": "0",
        "FragmentPath": str(unit_path) if loaded else "",
        "DropInPaths": "",
        "UnitFileState": "enabled" if state.get("systemd_enabled") else "disabled",
        "ExecStart": (
            "{ path=" + binary + " ; argv[]=" + " ".join(arguments)
            + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0"
            + " ; code=(null) ; status=0/0 }"
        ) if loaded else "",
        "NeedDaemonReload": "yes" if loaded and current != definition else "no",
    }
    values.update(state.get("systemd_property_overrides", {}))
    return values

save()
if args == ["--version"]:
    print(state.get("systemd_version", "systemd 255"))
    raise SystemExit(0)
if args == ["--user", "show", "--property=Version", "--value"]:
    if state.get("systemd_bus_unavailable"):
        sys.stderr.write("Failed to connect to user bus\n")
        raise SystemExit(1)
    print("255")
    raise SystemExit(0)
if args == ["--user", "show", "cloudflared.service", "--property=LoadState"]:
    print("LoadState=" + state.get("systemd_legacy_load_state", "not-found"))
    raise SystemExit(0)
if len(args) == 4 and args[:3] == ["--user", "show", unit]:
    for key, value in properties().items():
        print(key + "=" + value)
    raise SystemExit(0)
if args == ["--user", "daemon-reload"]:
    if state.get("systemd_fail_reload_once"):
        state["systemd_fail_reload_once"] = False
        save()
        sys.stderr.write("daemon-reload refused\n")
        raise SystemExit(1)
    if unit_path.exists():
        state["systemd_loaded_definition"] = unit_path.read_text(encoding="utf-8")
    else:
        state.pop("systemd_loaded_definition", None)
    save()
    raise SystemExit(0)
if args == ["--user", "enable", "--now", unit]:
    state["systemd_enabled"] = True
    if state.get("systemd_fail_start_once"):
        state["systemd_fail_start_once"] = False
        save()
        sys.stderr.write("start refused\n")
        raise SystemExit(1)
    if not state.get("systemd_active"):
        connect()
    save()
    raise SystemExit(0)
if args == ["--user", "restart", unit]:
    disconnect()
    connect()
    save()
    raise SystemExit(0)
if args == ["--user", "disable", "--now", unit]:
    if state.get("systemd_fail_disable_once"):
        state["systemd_fail_disable_once"] = False
        save()
        sys.stderr.write("disable refused\n")
        raise SystemExit(1)
    if not state.get("systemd_refuse_inactive"):
        state["systemd_enabled"] = False
        state["systemd_active"] = False
        disconnect()
    save()
    raise SystemExit(0)
sys.stderr.write("unsupported systemctl arguments\n")
raise SystemExit(1)
"""


def loginctl_script() -> str:
    """Expose linger readback only; enabling linger is intentionally unsupported."""

    return r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(path.read_text(encoding="utf-8"))
args = sys.argv[1:]
state.setdefault("loginctl_calls", []).append(args)
path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
if args == ["show-user", str(os.getuid()), "--property=Linger", "--value"]:
    print("no" if state.get("systemd_linger_disabled") else "yes")
    raise SystemExit(0)
sys.stderr.write("unsupported loginctl arguments\n")
raise SystemExit(1)
"""


def lsof_script() -> str:
    """Return one loopback listener only for the active fake connector's exact PID."""

    return r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(path.read_text(encoding="utf-8"))
args = sys.argv[1:]
state.setdefault("lsof_calls", []).append(args)
path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
pid = str(state.get("systemd_pid", 0))
expected = ["-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fpn"]
if args == expected and state.get("systemd_active"):
    print("p" + pid + "\nf7\nn127.0.0.1:20241")
    raise SystemExit(0)
raise SystemExit(1)
"""
