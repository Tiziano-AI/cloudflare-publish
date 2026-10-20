#!/usr/bin/env bash
# Read-only local manager diagnostic. Inputs: PATH, `cloudflared`
# version, launchd state, manager plist, manager state JSON, and log directory metadata. An optional
# standalone PATH Python parses allowlisted file contents; otherwise only metadata is reported.
# Output: human-readable diagnostic text on stdout/stderr. Side effects: none.
set -euo pipefail

state_dir="$HOME/Library/Application Support/cloudflare-publish"
state_file="$state_dir/state.json"
launch_agent="$HOME/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist"
log_dir="$HOME/Library/Logs/cloudflare-publish"
printf '== cloudflare-publish CLI ==\n'
if cli_path="$(command -v cloudflare-publish)"; then
  printf '%s\n' "$cli_path"
else
  printf 'not found on PATH; install the CLI explicitly before operating it\n'
fi

printf '\n== cloudflared ==\n'
if command -v cloudflared >/dev/null 2>&1; then
  cloudflared --version | head -n 1
else
  printf 'cloudflared missing\n'
fi

parser=""
# Apple's system command can request developer-tools installation. Do not execute it, including
# through a symlink, and never install an interpreter just for this optional diagnostic.
if python_path="$(command -v python3)" &&
  [[ "$python_path" == /* && "$python_path" != /usr/bin/python3 &&
    ! "$python_path" -ef /usr/bin/python3 ]] &&
  "$python_path" -I -B -c 'import json, plistlib, sys; sys.exit(sys.version_info < (3, 7))' >/dev/null 2>&1; then
  parser="$python_path"
fi
printf '\n== optional file parser ==\n'
if [[ -n "$parser" ]]; then
  printf 'available; allowlisted plist and state summaries enabled\n'
else
  printf 'unavailable; file contents skipped, metadata-only diagnosis remains available\n'
fi

printf '\n== launch agent ==\n'
if [[ -f "$launch_agent" ]]; then
  launchctl list | awk '$3 == "com.cloudflare-publish.cloudflared" {print}' || true
  if [[ -n "$parser" ]]; then
    "$parser" -I -B - "$launch_agent" "$state_dir/tunnel-token.txt" <<'PY'
from __future__ import annotations

import plistlib
import sys
from pathlib import Path
from xml.parsers.expat import ExpatError

try:
    with Path(sys.argv[1]).open("rb") as source:
        agent = plistlib.load(source)
    if not isinstance(agent, dict):
        raise ValueError("not an object")
except (OSError, ValueError, plistlib.InvalidFileException, ExpatError):
    print("launch_agent_parse=invalid; contents withheld")
else:
    arguments = agent.get("ProgramArguments")
    valid_arguments = isinstance(arguments, list) and all(
        isinstance(value, str) for value in arguments
    )
    arguments = arguments if valid_arguments else []
    binary = Path(arguments[0]) if arguments else None
    print(f"launch_agent_label_expected={agent.get('Label') == 'com.cloudflare-publish.cloudflared'}")
    print(f"launch_agent_arguments_valid={valid_arguments}")
    if binary is not None and binary.is_absolute() and binary.name == "cloudflared":
        # A recognizable binary path is useful; arbitrary argv and environment
        # contents are not safe diagnostic output when inspecting drift.
        print(f"launch_agent_binary={str(binary)!r}")
    else:
        print("launch_agent_binary=unrecognized; contents withheld")
    expected_token = sys.argv[2]
    token_file_expected = any(
        argument == "--token-file" and index + 1 < len(arguments)
        and arguments[index + 1] == expected_token
        or argument == f"--token-file={expected_token}"
        for index, argument in enumerate(arguments)
    )
    print(f"launch_agent_token_file_expected={token_file_expected}")
    inline_token = any(value == "--token" or value.startswith("--token=") for value in arguments)
    print(f"launch_agent_inline_token_present={inline_token}")
    print(f"launch_agent_environment_present={bool(agent.get('EnvironmentVariables'))}")
PY
  else
    printf 'launch_agent_parse=skipped; optional standalone Python unavailable; contents withheld\n'
    ls -ld "$launch_agent"
  fi
else
  printf 'launch agent missing: %s\n' "$launch_agent"
fi

printf '\n== manager state ==\n'
if [[ -f "$state_file" ]]; then
  if [[ -n "$parser" ]]; then
    "$parser" -I -B - "$state_file" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit


def mapping(value):
    return value if isinstance(value, dict) else {}


def scalar(value):
    # Invalid manifest types must not dump nested objects or arbitrary fields.
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    if isinstance(value, str):
        return value.encode("unicode_escape").decode("ascii")
    return "invalid; contents withheld"


def origin(value):
    if not isinstance(value, str):
        return "unknown"
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "ssh"} or not parsed.hostname:
            return "invalid; contents withheld"
        if (
            parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
        ):
            return "invalid; contents withheld"
    except ValueError:
        return "invalid; contents withheld"
    return scalar(value)

state_path = Path(sys.argv[1])
try:
    state = json.loads(state_path.read_text())
    if not isinstance(state, dict):
        raise ValueError("not an object")
except (OSError, ValueError):
    print("state_parse=invalid; contents withheld")
    raise SystemExit(0)
manager = mapping(state.get("manager"))
publications = mapping(state.get("publications"))

print(f"state_file: {state_path}")
print(f"schema_version: {scalar(state.get('schema_version'))}")
print(f"updated_at: {scalar(state.get('updated_at'))}")
print(f"manager_present: {bool(manager)}")
for field in ("account_name", "zone_name", "auth_domain", "tunnel_name"):
    print(f"{field}: {scalar(manager.get(field))}")
print(f"publication_count: {len(publications)}")
pending = mapping(state.get("pending"))
print(f"pending_transition_present: {bool(pending)}")
for field in ("kind", "phase", "route"):
    if pending:
        print(f"pending_{field}: {scalar(pending.get(field))}")

for name, publication in publications.items():
    publication = mapping(publication)
    spec = mapping(publication.get("spec"))
    remote_state = mapping(publication.get("state"))
    origin_options = mapping(spec.get("origin_options"))
    kind = spec.get("kind", "http_public")
    hostname = spec.get("hostname")
    verify_path = spec.get("verify_path")
    origin_url = spec.get("origin_url")
    print(
        f"- {scalar(name)}: kind={scalar(kind)} hostname={scalar(hostname)} "
        f"audience={scalar(spec.get('audience'))} origin={origin(origin_url)}"
    )
    if kind == "ssh_public":
        host_key = spec.get("ssh_host_key")
        print(f"  ssh_host_key_pin_configured={isinstance(host_key, str) and bool(host_key)}")
        print("  ssh_verification_scope=pinned signed key exchange (not performed)")
    elif kind == "http_public":
        if isinstance(hostname, str) and isinstance(verify_path, str):
            public_verify_url = f"https://{hostname}{verify_path}"
        else:
            public_verify_url = "unknown"
        if isinstance(origin_url, str) and origin_url.startswith("http://"):
            tls_mode = "not applicable"
        elif origin_options.get("no_tls_verify") is True:
            tls_mode = "disabled"
        else:
            tls_mode = "enabled"
        print(f"  verify_path={scalar(verify_path)}")
        print(f"  public_verify_url={scalar(public_verify_url)}")
        print(f"  origin_host_header={scalar(origin_options.get('http_host_header'))}")
        print(f"  origin_server_name={scalar(origin_options.get('origin_server_name'))}")
        print(f"  origin_tls_verification={tls_mode}")
    else:
        print("  verification_scope=unsupported publication kind")
    for field in ("access_application_id", "access_aud", "dns_record_id", "service_token_client_id"):
        print(f"  {field}={scalar(remote_state.get(field))}")
    policy_ids = remote_state.get("policy_ids")
    if isinstance(policy_ids, list) and all(isinstance(value, str) for value in policy_ids):
        print(f"  policy_ids={scalar(','.join(policy_ids))}")
    else:
        print("  policy_ids=unknown")
PY
  else
    printf 'state_parse=skipped; optional standalone Python unavailable; contents withheld\n'
    ls -ld "$state_file"
  fi
else
  printf 'state file missing: %s\n' "$state_file"
fi

printf '\n== logs ==\n'
if [[ -d "$log_dir" ]]; then
  ls -la "$log_dir"
else
  printf 'log directory missing: %s\n' "$log_dir"
fi
