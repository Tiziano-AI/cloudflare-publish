"""Canonical CLI entrypoint for `cloudflare-publish`."""

from __future__ import annotations

import sys
from pathlib import Path

from cloudflare_publish.cli_output import QuietConsole, write_json_error, write_json_success
from cloudflare_publish.cli_parser import CliArgs, command_name, parse_args
from cloudflare_publish.cli_read_commands import (
    run_discover_command,
    run_doctor_command,
    run_inspect_command,
    run_ls_command,
    run_repair_command,
    run_service_command,
    run_verify_command,
)
from cloudflare_publish.cli_runtime import CliRuntime, build_cli_runtime
from cloudflare_publish.cli_shared import require_value
from cloudflare_publish.cli_write_commands import (
    run_guard_command,
    run_publish_command,
    run_remove_command,
    run_setup_command,
    run_teardown_command,
    run_token_command,
    run_tunnel_command,
)
from cloudflare_publish.console import Console
from cloudflare_publish.errors import AppError
from cloudflare_publish.json_types import JsonObject
from cloudflare_publish.manager_lock import ManagerWriterLock
from cloudflare_publish.state import load_manifest
from cloudflare_publish.transitions import require_no_pending


def entrypoint() -> None:
    """Console-script entrypoint."""

    raise SystemExit(main())


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path | None = None,
    home: Path | None = None,
) -> int:
    """Run the canonical CLI and return a process exit code."""

    name = "parse"
    try:
        args = parse_args(argv)
        name = command_name(args)
        console = QuietConsole() if args.json else Console()
        runtime = build_cli_runtime(repo_root=repo_root, home=home)
        if _mutates_manager(args):
            with ManagerWriterLock(runtime.paths):
                if args.command in {"guard", "tunnel", "service"}:
                    manifest = load_manifest(runtime.paths.state_file)
                    if manifest is not None:
                        require_no_pending(manifest)
                data = _dispatch(args=args, runtime=runtime, console=console)
        else:
            data = _dispatch(args=args, runtime=runtime, console=console)
    except AppError as error:
        if _json_requested(argv):
            write_json_error(command=name, error=error)
        else:
            Console().error(error.message)
            for hint in error.hints:
                Console().note(hint)
        return 2 if error.code == "usage_error" else 1
    except KeyboardInterrupt:
        error = AppError("Interrupted.", code="interrupted")
        if _json_requested(argv):
            write_json_error(command=name, error=error)
        else:
            Console().error(error.message)
        return 1
    if args.json:
        write_json_success(command=name, data=data)
    return 0


def _json_requested(argv: list[str] | None) -> bool:
    """Return whether the raw invocation requested the JSON renderer."""

    values = sys.argv[1:] if argv is None else argv
    return "--json" in values


def _mutates_manager(args: CliArgs) -> bool:
    """Classify effects before workflow reads, not by handler module names."""

    return (
        args.command in {"setup", "teardown"}
        or (args.command == "publish" and args.publish_command == "apply")
        or (args.command == "rm" and args.remove_command == "apply")
        or (args.command == "token" and args.token_command == "rotate")
        or (args.command == "repair" and args.repair_command in {"resolve", "retire-token"})
        or (args.command == "guard" and args.guard_command == "apply")
        or (args.command == "tunnel" and args.recover_command == "apply")
        or (args.command == "service" and args.service_command in {"start", "stop", "restart"})
    )


def _dispatch(*, args: CliArgs, runtime: CliRuntime, console: Console) -> JsonObject:
    """Dispatch one parsed CLI command and return a JSON-ready payload."""

    command = require_value(args.command, message="CLI command is required.")
    if command == "doctor":
        return run_doctor_command(
            args=args,
            runtime=runtime,
            console=console,
            render=not args.json,
        )
    if command == "discover":
        return run_discover_command(
            args=args,
            runtime=runtime,
            console=console,
            render=not args.json,
        )
    if command == "setup":
        return run_setup_command(args=args, runtime=runtime, console=console)
    if command == "publish":
        return run_publish_command(args=args, runtime=runtime, console=console)
    if command == "ls":
        return run_ls_command(paths=runtime.paths, console=console, render=not args.json)
    if command == "inspect":
        return run_inspect_command(
            paths=runtime.paths,
            publication_name=require_value(args.name, message="inspect requires a name."),
            console=console,
            render=not args.json,
        )
    if command == "verify":
        return run_verify_command(args=args, runtime=runtime, console=console)
    if command == "repair":
        return run_repair_command(args=args, runtime=runtime, console=console, render=not args.json)
    if command == "service":
        return run_service_command(args=args, runtime=runtime, console=console)
    if command == "tunnel":
        return run_tunnel_command(args=args, runtime=runtime, console=console)
    if command == "rm":
        return run_remove_command(args=args, runtime=runtime, console=console)
    if command == "token":
        return run_token_command(args=args, runtime=runtime, console=console)
    if command == "guard":
        return run_guard_command(args=args, runtime=runtime, console=console)
    if command == "teardown":
        return run_teardown_command(args=args, runtime=runtime, console=console)
    raise AppError("Unknown command dispatch.")
