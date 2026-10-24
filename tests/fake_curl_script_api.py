"""Fake curl generated-script preamble and Cloudflare API branch."""

from __future__ import annotations

FAKE_CURL_API_PART = """#!/usr/bin/env python3
import json
import os
import signal
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

state_path = Path(os.environ["CLOUDFLARE_PUBLISH_TEST_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]

def save() -> None:
    state_path.write_text(json.dumps(state, indent=2) + "\\n", encoding="utf-8")

def next_id(kind: str) -> str:
    value = state["cloudflare"]["next_ids"][kind]
    state["cloudflare"]["next_ids"][kind] += 1
    return f"{kind}-{value}"

def write_response(
    status: int,
    body: object,
    response_headers: dict[str, str] | None = None,
) -> None:
    if (
        parsed.netloc == "api.cloudflare.com"
        and method in {"POST", "PUT", "DELETE"}
        and 200 <= status < 300
    ):
        cloudflare.setdefault("write_history", []).append({
            "method": method,
            "path": path,
            "configurations": json.loads(json.dumps(cloudflare["tunnel_configurations"])),
            "apps": json.loads(json.dumps(cloudflare["access_apps"])),
            "dns": json.loads(json.dumps(cloudflare["dns_records"])),
            "token_ids": list(cloudflare["service_tokens"]),
        })
        save()
        if fault is not None and fault["mode"] in {"after", "kill"}:
            if fault["mode"] == "kill":
                if os.environ.get("CLOUDFLARE_PUBLISH_TEST_ALLOW_KILL") != "1":
                    raise RuntimeError("kill fault requires an isolated CLI subprocess")
                os.kill(os.getppid(), signal.SIGKILL)
            sys.stderr.write("curl fake: response lost after accepted write\\n")
            raise SystemExit(56)
    body_text = body if isinstance(body, str) else json.dumps(body)
    Path(output_file).write_text(body_text, encoding="utf-8")
    if header_file is not None:
        header_lines = [f"HTTP/1.1 {status}\\r\\n"]
        if response_headers is not None:
            for key, value in response_headers.items():
                header_lines.append(f"{key}: {value}\\r\\n")
        header_lines.append("\\r\\n")
        Path(header_file).write_text("".join(header_lines), encoding="utf-8")
    print(status, end="")
    raise SystemExit(0)


def paginated_result(items: list[object], query: dict[str, list[str]]) -> object:
    page = int(query.get("page", ["1"])[0])
    per_page = int(query.get("per_page", [str(len(items) or 1)])[0])
    start = (page - 1) * per_page
    end = start + per_page
    total_pages = max(1, (len(items) + per_page - 1) // per_page)
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": items[start:end],
        "result_info": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "count": len(items[start:end]),
            "total_count": len(items),
        },
    }

method = "GET"
headers = {}
body_text = None
output_file = None
header_file = None
url = None
connect_to = {}
insecure = False
index = 0
while index < len(args):
    value = args[index]
    if value == "--request":
        method = args[index + 1]
        index += 2
        continue
    if value == "--header":
        header = args[index + 1]
        header_lines = (
            Path(header[1:]).read_text(encoding="utf-8").splitlines()
            if header.startswith("@")
            else [header]
        )
        for header_line in header_lines:
            key, _, content = header_line.partition(":")
            headers[key.strip()] = content.strip()
        index += 2
        continue
    if value == "--data":
        body_text = args[index + 1]
        index += 2
        continue
    if value == "--json":
        body_arg = args[index + 1]
        body_text = (
            Path(body_arg[1:]).read_text(encoding="utf-8") if body_arg.startswith("@") else body_arg
        )
        index += 2
        continue
    if value == "--output":
        output_file = args[index + 1]
        index += 2
        continue
    if value == "--dump-header":
        header_file = args[index + 1]
        index += 2
        continue
    if value == "--connect-to":
        source_host, source_port, connect_host, connect_port = args[index + 1].split(":")
        connect_to[(source_host, source_port)] = (connect_host, connect_port)
        index += 2
        continue
    if value == "--insecure":
        insecure = True
        index += 1
        continue
    if value.startswith("http"):
        url = value
        index += 1
        continue
    index += 1

if output_file is None or url is None:
    sys.stderr.write("curl fake expected --output and url\\n")
    raise SystemExit(2)

parsed = urlsplit(url)
payload = {} if body_text is None else json.loads(body_text)

def origin_status_for(
    origin_url: str,
    host_header: str | None,
    tls_host: str | None,
    insecure_tls: bool,
    actual_origin_host: str | None = None,
) -> int:
    origin = urlsplit(origin_url)
    origin_host = actual_origin_host or origin.hostname
    origin_port = origin.port or (443 if origin.scheme == "https" else 80)
    if origin_host == "127.0.0.1" and origin_port == 11434 and host_header != "127.0.0.1":
        return 403
    if origin.scheme == "https" and origin_host == "127.0.0.1" and origin_port == 8443:
        if not insecure_tls and tls_host != "tls.internal":
            return 526
    return 200

def api_success(result: object) -> object:
    return {"success": True, "errors": [], "messages": [], "result": result}

def api_error(message: str, status: int = 400) -> None:
    write_response(
        status,
        {
            "success": False,
            "errors": [{"message": message}],
            "messages": [],
            "result": None,
        },
    )

if parsed.netloc == "api.cloudflare.com":
    path = parsed.path.removeprefix("/client/v4")
    query = parse_qs(parsed.query)
    cloudflare = state["cloudflare"]
    fault = None
    if method in {"POST", "PUT", "DELETE"}:
        cloudflare.setdefault("requests", []).append({"method": method, "path": path})
        for candidate in cloudflare.get("faults", []):
            if candidate.get("consumed") is True:
                continue
            if candidate["method"] != method or candidate["path"] != path:
                continue
            candidate["seen"] = candidate.get("seen", 0) + 1
            if candidate["seen"] == candidate.get("occurrence", 1):
                candidate["consumed"] = True
                fault = candidate
            break
        save()
    if fault is not None and fault["mode"] == "before":
        api_error("forced rejection before write", status=503)

    if path == "/accounts" and method == "GET":
        write_response(200, paginated_result(cloudflare["accounts"], query))

    if path == "/zones" and method == "GET":
        zones = cloudflare["zones"]
        name = query.get("name", [None])[0]
        if name is not None:
            zones = [zone for zone in zones if zone["name"] == name]
        write_response(200, paginated_result(zones, query))

    if path.startswith("/accounts/") and path.endswith("/access/organizations"):
        if method == "GET":
            write_response(200, api_success(cloudflare["organization"]))
        if method == "PUT":
            cloudflare["organization"] = payload
            save()
            write_response(200, api_success(cloudflare["organization"]))

    if path.startswith("/accounts/") and path.endswith("/cfd_tunnel") and method == "GET":
        tunnels = list(cloudflare["tunnels"].values())
        write_response(200, paginated_result(tunnels, query))

    if path.startswith("/accounts/") and path.endswith("/cfd_tunnel") and method == "POST":
        tunnel_id = next_id("tunnel")
        tunnel = {
            "id": tunnel_id,
            "name": payload["name"],
            "created_at": "2026-04-02T00:00:00Z",
            "remote_config": True,
            "status": "healthy",
        }
        cloudflare["tunnels"][tunnel_id] = tunnel
        cloudflare["tunnel_configurations"][tunnel_id] = {"config": {}, "version": 0}
        save()
        write_response(200, api_success(tunnel))

    if "/cfd_tunnel/" in path and path.endswith("/token") and method == "GET":
        tunnel_id = path.split("/cfd_tunnel/")[1].split("/")[0]
        token = cloudflare.get("tunnel_tokens", {}).get(tunnel_id, f"token-{tunnel_id}")
        write_response(200, api_success(token))

    if "/cfd_tunnel/" in path and path.endswith("/connections") and method == "DELETE":
        tunnel_id = path.split("/cfd_tunnel/")[1].split("/")[0]
        cloudflare["cleaned_tunnel_ids"].append(tunnel_id)
        cloudflare.setdefault("tunnel_connections", {})[tunnel_id] = []
        save()
        write_response(200, api_success({"id": tunnel_id}))

    if "/cfd_tunnel/" in path and path.endswith("/connections") and method == "GET":
        tunnel_id = path.split("/cfd_tunnel/")[1].split("/")[0]
        clients = cloudflare.setdefault("tunnel_connections", {}).get(tunnel_id, [])
        if state.get("omit_local_config_version") is True:
            clients = [
                {key: value for key, value in client.items() if key != "config_version"}
                if client["id"] == state.get("native_connector_id") else client
                for client in clients
            ]
        write_response(200, paginated_result(clients, query))

    if "/cfd_tunnel/" in path and path.endswith("/configurations"):
        tunnel_id = path.split("/cfd_tunnel/")[1].split("/")[0]
        if method == "GET":
            record = cloudflare["tunnel_configurations"].get(tunnel_id)
            if record is None:
                api_error("missing tunnel config", status=404)
            result = {
                "account_id": "acc-123",
                "tunnel_id": tunnel_id,
                "source": "cloudflare",
                "config": record["config"],
            }
            if "version" in record:
                result["version"] = record["version"]
            write_response(200, api_success(result))
        if method == "PUT":
            if cloudflare.get("fail_tunnel_config_put_once") is True:
                cloudflare["fail_tunnel_config_put_once"] = False
                save()
                api_error("forced tunnel config failure", status=503)
            prior = cloudflare["tunnel_configurations"].get(tunnel_id, {})
            version = prior.get("version", 0) + 1
            cloudflare["tunnel_configurations"][tunnel_id] = {**payload, "version": version}
            if cloudflare.get("hold_local_config") is not True:
                for client in cloudflare.setdefault("tunnel_connections", {}).get(tunnel_id, []):
                    if client["id"] in {"local-client", state.get("native_connector_id")}:
                        client["config_version"] = version
            save()
            write_response(
                200,
                api_success(
                    {
                        "account_id": "acc-123",
                        "tunnel_id": tunnel_id,
                        "version": version,
                        "config": payload["config"],
                    }
                ),
            )

    if "/cfd_tunnel/" in path and method == "GET":
        tunnel_id = path.split("/cfd_tunnel/")[1].split("/")[0]
        tunnel = cloudflare["tunnels"].get(tunnel_id)
        if tunnel is None:
            tunnel = cloudflare.setdefault("deleted_tunnels", {}).get(tunnel_id)
        if tunnel is None:
            api_error("missing tunnel", status=404)
        write_response(200, api_success(tunnel))

    if "/cfd_tunnel/" in path and method == "DELETE":
        tunnel_id = path.split("/cfd_tunnel/")[1].split("/")[0]
        clients = cloudflare.setdefault("tunnel_connections", {}).get(tunnel_id, [])
        if any(client.get("conns") for client in clients):
            api_error("tunnel has active connections", status=400)
        tunnel = cloudflare["tunnels"].pop(tunnel_id, None)
        if tunnel is not None:
            cloudflare.setdefault("deleted_tunnels", {})[tunnel_id] = {
                **tunnel,
                "deleted_at": "2026-04-02T00:00:01Z",
            }
        cloudflare["tunnel_configurations"].pop(tunnel_id, None)
        save()
        write_response(200, api_success({"id": tunnel_id}))

    if path.startswith("/zones/") and path.endswith("/dns_records") and method == "GET":
        zone_id = path.split("/")[2]
        records = [
            record
            for record in cloudflare["dns_records"].values()
            if record["zone_id"] == zone_id
        ]
        name = query.get("name", [None])[0]
        if name is not None:
            records = [record for record in records if record["name"] == name]
        write_response(200, api_success(records))

    if path.startswith("/zones/") and path.endswith("/dns_records") and method == "POST":
        zone_id = path.split("/")[2]
        record_id = next_id("dns")
        record = {
            "id": record_id,
            "zone_id": zone_id,
            "type": payload["type"],
            "name": payload["name"],
            "content": payload["content"],
            "proxied": payload["proxied"],
        }
        cloudflare["dns_records"][record_id] = record
        save()
        write_response(200, api_success(record))

    if "/dns_records/" in path and method == "PUT":
        record_id = path.rsplit("/", 1)[-1]
        record = cloudflare["dns_records"][record_id]
        record["type"] = payload["type"]
        record["name"] = payload["name"]
        record["content"] = payload["content"]
        record["proxied"] = payload["proxied"]
        save()
        write_response(200, api_success(record))

    if "/dns_records/" in path and method == "DELETE":
        record_id = path.rsplit("/", 1)[-1]
        cloudflare["dns_records"].pop(record_id, None)
        save()
        write_response(200, api_success({"id": record_id}))

    if path.startswith("/accounts/") and path.endswith("/access/apps") and method == "GET":
        write_response(200, api_success(list(cloudflare["access_apps"].values())))

    if path.startswith("/accounts/") and path.endswith("/access/apps") and method == "POST":
        app_id = next_id("app")
        app = {
            "id": app_id,
            "name": payload["name"],
            "type": payload["type"],
            "aud": f"aud-{app_id}",
            "domain": payload["domain"],
            "destinations": payload.get("destinations", []),
            "service_auth_401_redirect": payload.get("service_auth_401_redirect", False),
        }
        cloudflare["access_apps"][app_id] = app
        save()
        write_response(200, api_success(app))

    if "/access/apps/" in path and "/policies" not in path and method == "GET":
        app_id = path.rsplit("/", 1)[-1]
        app = cloudflare["access_apps"].get(app_id)
        if app is None:
            api_error("missing access app", status=404)
        write_response(200, api_success(app))

    if "/access/apps/" in path and "/policies" not in path and method == "PUT":
        app_id = path.rsplit("/", 1)[-1]
        app = cloudflare["access_apps"][app_id]
        app["name"] = payload["name"]
        app["domain"] = payload["domain"]
        app["destinations"] = payload.get("destinations", [])
        app["service_auth_401_redirect"] = payload.get("service_auth_401_redirect", False)
        save()
        write_response(200, api_success(app))

    if "/access/apps/" in path and "/policies" not in path and method == "DELETE":
        app_id = path.rsplit("/", 1)[-1]
        cloudflare["access_apps"].pop(app_id, None)
        cloudflare["access_policies"] = {
            key: value
            for key, value in cloudflare["access_policies"].items()
            if value["app_id"] != app_id
        }
        save()
        write_response(200, api_success({"id": app_id}))

    if path.endswith("/policies") and method == "GET":
        app_id = path.split("/access/apps/")[1].split("/")[0]
        if app_id not in cloudflare["access_apps"]:
            api_error("missing access app", status=404)
        policies = [
            policy
            for policy in cloudflare["access_policies"].values()
            if policy["app_id"] == app_id
        ]
        write_response(200, api_success(policies))

    if path.endswith("/policies") and method == "POST":
        app_id = path.split("/access/apps/")[1].split("/")[0]
        policy_id = next_id("policy")
        policy = {
            "id": policy_id,
            "app_id": app_id,
            "name": payload["name"],
            "decision": payload["decision"],
            "include": payload["include"],
            "precedence": payload["precedence"],
        }
        cloudflare["access_policies"][policy_id] = policy
        save()
        write_response(200, api_success(policy))

    if "/policies/" in path and method == "DELETE":
        policy_id = path.rsplit("/", 1)[-1]
        cloudflare["access_policies"].pop(policy_id, None)
        save()
        write_response(200, api_success({"id": policy_id}))

    if (
        path.startswith("/accounts/")
        and path.endswith("/access/service_tokens")
        and method == "GET"
    ):
        tokens = [
            {key: value for key, value in token.items() if key != "client_secret"}
            for token in cloudflare["service_tokens"].values()
        ]
        write_response(200, paginated_result(tokens, query))

    if (
        path.startswith("/accounts/")
        and path.endswith("/access/service_tokens")
        and method == "POST"
    ):
        token_id = next_id("token")
        secret_version = state["cloudflare"]["next_ids"]["secret"]
        state["cloudflare"]["next_ids"]["secret"] += 1
        token = {
            "id": token_id,
            "name": payload["name"],
            "client_id": f"client-{token_id}",
            "client_secret": f"secret-{secret_version}",
        }
        cloudflare["service_tokens"][token_id] = token
        save()
        write_response(200, api_success(token))

    if path.endswith("/rotate") and method == "POST":
        token_id = path.split("/service_tokens/")[1].split("/")[0]
        token = cloudflare["service_tokens"].get(token_id)
        if token is None:
            api_error("missing service token", status=404)
        secret_version = state["cloudflare"]["next_ids"]["secret"]
        state["cloudflare"]["next_ids"]["secret"] += 1
        token["client_secret"] = f"secret-{secret_version}"
        save()
        write_response(200, api_success(token))

    if "/access/service_tokens/" in path and method == "DELETE":
        token_id = path.rsplit("/", 1)[-1]
        cloudflare["service_tokens"].pop(token_id, None)
        save()
        write_response(200, api_success({"id": token_id}))

    if "/access/service_tokens/" in path and method == "GET":
        token_id = path.rsplit("/", 1)[-1]
        token = cloudflare["service_tokens"].get(token_id)
        if token is None:
            api_error("missing service token", status=404)
        metadata = {key: value for key, value in token.items() if key != "client_secret"}
        write_response(200, api_success(metadata))

    api_error(f"unsupported API path: {method} {path}", status=404)

"""
