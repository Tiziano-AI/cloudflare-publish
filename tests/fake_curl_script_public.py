"""Fake curl generated-script public route branch."""

from __future__ import annotations

FAKE_CURL_PUBLIC_PART = """if parsed.hostname == "127.0.0.1" and parsed.port == 20241:
    if not state.get("systemd_active"):
        write_response(503, "connector inactive")
    cf = state["cloudflare"]
    connector_id = state.get("native_connector_id")
    snapshots = [
        (tunnel_id, client)
        for tunnel_id, clients in cf.get("tunnel_connections", {}).items()
        for client in clients if client["id"] == connector_id
    ]
    if len(snapshots) != 1:
        write_response(503, "connector identity unavailable")
    tunnel_id, client = snapshots[0]
    if parsed.path == "/ready":
        write_response(200, {"status": 200, "readyConnections": 1, "connectorId": connector_id})
    if parsed.path == "/diag/tunnel":
        write_response(200, {
            "tunnelID": tunnel_id, "connectorID": connector_id,
            "connections": [{"isConnected": True}],
        })
    if parsed.path == "/config":
        write_response(200, {
            "version": client["config_version"],
            "config": cf["tunnel_configurations"][tunnel_id]["config"],
        })
    write_response(404, "unknown connector endpoint")

port = parsed.port or (443 if parsed.scheme == "https" else 80)
actual_host = parsed.hostname
if actual_host is not None:
    connect_target = connect_to.get((actual_host, str(port)))
    if connect_target is not None:
        actual_host = connect_target[0]

if actual_host == "127.0.0.1":
    write_response(
        origin_status_for(
            url,
            headers.get("Host") or parsed.hostname,
            parsed.hostname,
            insecure,
            actual_host,
        ),
        "origin ok",
    )

cloudflare = state["cloudflare"]
hostname = parsed.hostname
record = None
for item in cloudflare["dns_records"].values():
    if item["name"] == hostname:
        record = item
        break
if record is None:
    write_response(404, "missing dns")

tunnel_id = record["content"].split(".")[0]
config = cloudflare["tunnel_configurations"].get(tunnel_id, {"config": {"ingress": []}})
# An explicit connector snapshot exercises a connector that has not applied a PUT.
# It models only the required-AUD gate, not JWT cryptography or real edge rollout.
config = cloudflare.get("serving_configurations", {}).get(tunnel_id, config)
route = None
for rule in config["config"]["ingress"]:
    if rule.get("hostname") == hostname:
        route = rule
        break
if route is None:
    write_response(404, "missing route")

app = None
for item in cloudflare["access_apps"].values():
    if item["domain"] == hostname:
        app = item
        break
if app is None:
    if cloudflare["organization"]["deny_unmatched_requests"]:
        write_response(403, "guard")
    if route.get("originRequest", {}).get("access", {}).get("required") is True:
        write_response(403, "connector requires an Access JWT")
    write_response(200, "public")

policies = [
    policy for policy in cloudflare["access_policies"].values() if policy["app_id"] == app["id"]
]
provided_client_id = headers.get("CF-Access-Client-Id")
provided_client_secret = headers.get("CF-Access-Client-Secret")
authenticated = False
for policy in policies:
    if policy["decision"] != "non_identity":
        continue
    for include in policy["include"]:
        token_rule = include.get("service_token")
        if not isinstance(token_rule, dict):
            continue
        token_id = token_rule.get("token_id")
        token = cloudflare["service_tokens"].get(token_id)
        if token is None:
            continue
        if (
            token["client_id"] == provided_client_id
            and token["client_secret"] == provided_client_secret
        ):
            authenticated = True

if authenticated:
    origin_request = route.get("originRequest", {})
    access = origin_request.get("access", {})
    if access.get("required") is True and app.get("aud") not in access.get("audTag", []):
        write_response(403, "connector rejects a different application audience")
    forwarded_host = (
        origin_request.get("httpHostHeader")
        if isinstance(origin_request, dict)
        else None
    )
    origin_server_name = (
        origin_request.get("originServerName")
        if isinstance(origin_request, dict)
        else None
    )
    no_tls_verify = (
        origin_request.get("noTLSVerify") is True
        if isinstance(origin_request, dict)
        else False
    )
    if forwarded_host is None:
        forwarded_host = hostname
    if origin_server_name is None:
        origin_server_name = urlsplit(route["service"]).hostname
    write_response(
        origin_status_for(route["service"], forwarded_host, origin_server_name, no_tls_verify),
        "ok",
    )

has_human_policy = any(policy["decision"] == "allow" for policy in policies)
if has_human_policy or app.get("service_auth_401_redirect") is not True:
    write_response(
        302,
        "login",
        {
            "Location": (
                f"https://{cloudflare['organization']['auth_domain']}"
                f"/cdn-cgi/access/login/{hostname}"
            )
        },
    )
write_response(401, "service auth required")
"""
