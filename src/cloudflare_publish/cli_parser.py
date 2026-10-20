"""Argument parser for the canonical CLI."""

from __future__ import annotations

import argparse
from importlib.metadata import version
from typing import Never, override

from cloudflare_publish.errors import AppError
from cloudflare_publish.service_flow import DEFAULT_LOG_LINES


class CliArgumentParser(argparse.ArgumentParser):
    """Argument parser that returns structured CLI errors instead of exiting on misuse."""

    @override
    def error(self, message: str) -> Never:
        """Raise a structured usage error for the outer renderer."""

        raise AppError(
            _friendly_usage_message(message),
            hints=("Run `cloudflare-publish --help` for the supported command surface.",),
            code="usage_error",
        )


class CliArgs(argparse.Namespace):
    """Typed argparse namespace for the CLI."""

    def __init__(self) -> None:
        """Initialize all parser fields with typed defaults."""

        super().__init__()
        self.command: str | None = None
        self.json: bool = False
        self.api_token: str | None = None
        self.install_deps: bool = False
        self.takeover: bool = False
        self.refresh_only: bool = False
        self.yes: bool = False
        self.account_id: str | None = None
        self.zone_id: str | None = None
        self.zone_name: str | None = None
        self.tunnel_name: str | None = None
        self.tunnel_id: str | None = None
        self.name: str | None = None
        self.hostname: str | None = None
        self.origin_url: str | None = None
        self.audience: str | None = None
        self.allowed_emails: list[str] = []
        self.allowed_email_domains: list[str] = []
        self.verify_path: str | None = None
        self.expect_status: str | None = None
        self.http_host_header: str | None = None
        self.origin_server_name: str | None = None
        self.no_tls_verify: bool = False
        self.ssh_host_key: str | None = None
        self.live: bool = False
        self.discover_command: str | None = None
        self.publish_command: str | None = None
        self.repair_command: str | None = None
        self.operation_id: str | None = None
        self.resource_id: str | None = None
        self.absent: bool = False
        self.recover: bool = False
        self.remove_command: str | None = None
        self.recover_command: str | None = None
        self.tunnel_command: str | None = None
        self.token_command: str | None = None
        self.guard_command: str | None = None
        self.service_command: str | None = None
        self.log_lines: int = DEFAULT_LOG_LINES


def parse_args(argv: list[str] | None) -> CliArgs:
    """Parse CLI arguments into the typed namespace."""

    parser = build_parser()
    return parser.parse_args(argv, namespace=CliArgs())


def command_name(args: CliArgs) -> str:
    """Return a stable command label for JSON envelopes."""

    parts: list[str] = []
    if args.command is not None:
        parts.append(args.command)
    for value in (
        args.discover_command,
        args.publish_command,
        args.repair_command,
        args.service_command,
        args.tunnel_command,
        args.recover_command,
        args.remove_command,
        args.token_command,
        args.guard_command,
    ):
        if value is not None:
            parts.append(value)
    if not parts:
        return "unknown"
    return " ".join(parts)


def build_parser() -> argparse.ArgumentParser:
    """Build the canonical CLI parser."""

    parser = CliArgumentParser(
        prog="cloudflare-publish",
        description=(
            "Publish exact-hostname local HTTP(S) or SSH services "
            "through a managed Cloudflare Tunnel."
        ),
    )
    _ = parser.add_argument(
        "--version", action="version", version=f"%(prog)s {version('cloudflare-publish')}"
    )
    _ = parser.add_argument("--json", action="store_true", help="emit a stable JSON envelope")
    _ = parser.add_argument("--api-token", help="Cloudflare API token for this invocation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    _ = subparsers.add_parser("doctor", help="diagnose install, auth, and manager state")

    discover = subparsers.add_parser("discover", help="typed Cloudflare discovery")
    discover_subparsers = discover.add_subparsers(dest="discover_command", required=True)
    _ = discover_subparsers.add_parser("accounts")
    discover_zones = discover_subparsers.add_parser("zones")
    _ = discover_zones.add_argument("--account-id", required=True)
    _ = discover_zones.add_argument("--name", dest="zone_name")
    discover_zone = discover_subparsers.add_parser("zone")
    _ = discover_zone.add_argument("zone_name")
    _ = discover_zone.add_argument("--account-id", required=True)
    discover_tunnels = discover_subparsers.add_parser("tunnels")
    _ = discover_tunnels.add_argument("--account-id", required=True)
    discover_tunnel = discover_subparsers.add_parser(
        "tunnel", help="read one tunnel's hostname topology without adopting it"
    )
    _ = discover_tunnel.add_argument("tunnel_id", metavar="ID")
    _ = discover_tunnel.add_argument("--account-id", required=True)
    _ = discover_tunnel.add_argument("--zone-id", required=True)
    discover_organization = discover_subparsers.add_parser("organization")
    _ = discover_organization.add_argument("--account-id", required=True)

    setup = subparsers.add_parser("setup", help="bootstrap or refresh the manager")
    _ = setup.add_argument("--install-deps", action="store_true")
    _ = setup.add_argument("--takeover", action="store_true")
    _ = setup.add_argument("--refresh-only", action="store_true")
    _ = setup.add_argument("--api-token")
    _ = setup.add_argument("--account-id")
    _ = setup.add_argument("--zone-id")
    _ = setup.add_argument("--zone", dest="zone_name")
    _ = setup.add_argument("--tunnel-name")
    _ = setup.add_argument("--yes", action="store_true")

    publish = subparsers.add_parser("publish", help="plan or apply one publication")
    publish_subparsers = publish.add_subparsers(dest="publish_command", required=True)
    _add_publish_arguments(publish_subparsers.add_parser("plan"), require_yes=False)
    _add_publish_arguments(publish_subparsers.add_parser("apply"), require_yes=True)

    _ = subparsers.add_parser("ls", help="list managed publications")
    inspect_parser = subparsers.add_parser("inspect", help="inspect one publication")
    _ = inspect_parser.add_argument("name")

    verify = subparsers.add_parser("verify", help="verify local and optional live state")
    _ = verify.add_argument("name", nargs="?")
    _ = verify.add_argument("--live", action="store_true")

    repair = subparsers.add_parser(
        "repair", help="inspect or explicitly resolve an incomplete mutation"
    )
    repair_subparsers = repair.add_subparsers(dest="repair_command", required=True)
    _ = repair_subparsers.add_parser("plan")
    repair_resolve = repair_subparsers.add_parser(
        "resolve", help="verify the exact result of an interrupted resource creation"
    )
    _ = repair_resolve.add_argument("--operation", dest="operation_id", required=True)
    result = repair_resolve.add_mutually_exclusive_group(required=True)
    _ = result.add_argument("--resource-id")
    _ = result.add_argument("--absent", action="store_true")
    _ = repair_resolve.add_argument("--yes", action="store_true")
    repair_retire = repair_subparsers.add_parser(
        "retire-token", help="retire an exact candidate token whose secret was lost"
    )
    _ = repair_retire.add_argument("--operation", dest="operation_id", required=True)
    _ = repair_retire.add_argument("--resource-id", required=True)
    _ = repair_retire.add_argument("--yes", action="store_true")

    service = subparsers.add_parser("service", help="manage local launchd connector lifecycle")
    service_subparsers = service.add_subparsers(dest="service_command", required=True)
    _ = service_subparsers.add_parser("status")
    _ = service_subparsers.add_parser("start")
    _ = service_subparsers.add_parser("stop")
    _ = service_subparsers.add_parser("restart")
    service_logs = service_subparsers.add_parser("logs")
    _ = service_logs.add_argument("--lines", dest="log_lines", type=int, default=DEFAULT_LOG_LINES)

    tunnel = subparsers.add_parser("tunnel", help="recover shared tunnel runtime token")
    tunnel_subparsers = tunnel.add_subparsers(dest="tunnel_command", required=True)
    recover = tunnel_subparsers.add_parser("recover")
    recover_subparsers = recover.add_subparsers(dest="recover_command", required=True)
    _ = recover_subparsers.add_parser("plan")
    recover_apply = recover_subparsers.add_parser("apply")
    _ = recover_apply.add_argument("--yes", action="store_true")

    remove = subparsers.add_parser("rm", help="remove one publication")
    remove_subparsers = remove.add_subparsers(dest="remove_command", required=True)
    remove_plan = remove_subparsers.add_parser("plan")
    _ = remove_plan.add_argument("name")
    remove_apply = remove_subparsers.add_parser("apply")
    _ = remove_apply.add_argument("name")
    _ = remove_apply.add_argument("--yes", action="store_true")

    token = subparsers.add_parser("token", help="manage publication service tokens")
    token_subparsers = token.add_subparsers(dest="token_command", required=True)
    token_rotate = token_subparsers.add_parser("rotate")
    _ = token_rotate.add_argument("name")
    _ = token_rotate.add_argument("--yes", action="store_true")
    _ = token_rotate.add_argument(
        "--recover",
        action="store_true",
        help="explicitly reissue the secret after an interrupted rotation of this exact token",
    )

    guard = subparsers.add_parser("guard", help="manage unmatched-request protection")
    guard_subparsers = guard.add_subparsers(dest="guard_command", required=True)
    _ = guard_subparsers.add_parser("status")
    _ = guard_subparsers.add_parser("plan")
    guard_apply = guard_subparsers.add_parser("apply")
    _ = guard_apply.add_argument("--yes", action="store_true")

    teardown = subparsers.add_parser("teardown", help="remove the whole manager")
    _ = teardown.add_argument("--yes", action="store_true")
    return parser


def _friendly_usage_message(message: str) -> str:
    """Replace internal argparse destination names in usage errors."""

    replacements = {
        "discover_command": "discover subcommand",
        "publish_command": "publish subcommand",
        "repair_command": "repair subcommand",
        "service_command": "service subcommand",
        "tunnel_command": "tunnel subcommand",
        "recover_command": "tunnel recover subcommand",
        "remove_command": "rm subcommand",
        "token_command": "token subcommand",
        "guard_command": "guard subcommand",
    }
    friendly = message
    for internal_name, public_name in replacements.items():
        friendly = friendly.replace(internal_name, public_name)
    return friendly


def _add_publish_arguments(parser: argparse.ArgumentParser, *, require_yes: bool) -> None:
    """Add publication spec arguments to a publish subcommand."""

    _ = parser.add_argument("name")
    _ = parser.add_argument("--hostname", required=True)
    _ = parser.add_argument("--to", dest="origin_url", required=True)
    _ = parser.add_argument(
        "--audience",
        required=True,
        metavar="{human,machine,mixed,public}",
        help=(
            "Access audience, or public only when the origin owns fail-closed "
            "request authentication"
        ),
    )
    _ = parser.add_argument("--allow-email", dest="allowed_emails", action="append", default=[])
    _ = parser.add_argument(
        "--allow-domain",
        dest="allowed_email_domains",
        action="append",
        default=[],
    )
    _ = parser.add_argument("--verify-path")
    _ = parser.add_argument("--expect-status")
    _ = parser.add_argument("--http-host-header")
    _ = parser.add_argument("--origin-server-name")
    _ = parser.add_argument("--no-tls-verify", action="store_true")
    _ = parser.add_argument(
        "--ssh-host-key", help="pinned public ssh-ed25519 host key; required for SSH origins"
    )
    if require_yes:
        _ = parser.add_argument("--yes", action="store_true")
