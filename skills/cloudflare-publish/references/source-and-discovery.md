# Source And Discovery

## Runtime posture

- The operator path is the PATH-global `cloudflare-publish` command.
- If the CLI is not on `PATH`, report the installed-runtime blocker. The plugin supplies guidance
  only. With authorization for installation, resolve the actual source or native plugin package
  root, then run `uv tool install --reinstall .` there; it contains `pyproject.toml` and the runtime source. Do
  not guess a personal checkout path or run setup as an installation side effect. This blocks
  installed operation, not explanation or work in a resolved source checkout.

The single public development and release source for the CLI and plugin is
[Tiziano-AI/cloudflare-publish](https://github.com/Tiziano-AI/cloudflare-publish).
The `tiziano-ai` marketplace pins reviewed commits from this complete source. Native plugin
installation and CLI installation are separate. A local Claude `--plugin-dir` session does not
establish persistent native installation or migration.

## Source and explanation

Use the source contract and relevant implementation for product-purpose questions and source
changes. No installation, credentials, or manager inspection is needed for those claims. An
unknown source owner must be resolved before editing; a known source checkout need not be
installed to be read or changed.

## First discovery sequence

For installed operation, check whether the CLI is globally installed:

```bash
command -v cloudflare-publish
cloudflare-publish --version
cloudflare-publish --help
```

These commands are offline and read no credentials. They establish selection and the installed
version, not manager readiness. The package inspection script likewise resolves the CLI only from
PATH; it never treats a nearby checkout or a command outside PATH as the installed runtime.

When current install/auth/readiness is the question, use `cloudflare-publish --json doctor`.
It resolves credentials and contacts Cloudflare account discovery when a token is available.
Inspect `data.ready` and `data.checks`; diagnostic completion is not readiness.

For local manager facts, inspect the relevant runtime surfaces even if its checkout is unresolved:

```bash
ls -la "$HOME/Library/Application Support/cloudflare-publish"
ls -la "$HOME/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist"
launchctl list | grep com.cloudflare-publish.cloudflared || true
cloudflared --version
```

## When the command is unresolved

- If local manager state is in scope, continue to inspect its runtime artifacts; these do not
  establish remote parity or public-hostname behavior.
- Do not invent a repository path, install from an assumed checkout, or claim
  the command is operational.

## Discovery without manager state

Use these commands when setup or a current remote-state question needs unresolved account, zone,
organization, or tunnel identifiers. They require an API token and contact Cloudflare, but do not
require local manager state:

```bash
cloudflare-publish --json discover accounts
cloudflare-publish --json discover zone example.com --account-id "$CLOUDFLARE_ACCOUNT_ID"
cloudflare-publish --json discover tunnels --account-id "$CLOUDFLARE_ACCOUNT_ID"
cloudflare-publish --json discover tunnel "$CLOUDFLARE_TUNNEL_ID" \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" --zone-id "$CLOUDFLARE_ZONE_ID"
cloudflare-publish --json discover organization --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

There is no raw Cloudflare API command. Product reads return typed, no-secret payloads.
Exact-tunnel inspection requires the supplied zone to belong to the supplied account and does not
adopt manager ownership. Its coverage statement distinguishes inspected routing resources from
application dependencies or uninspected account topology.

## Canonical runtime surfaces

- state manifest: `~/Library/Application Support/cloudflare-publish/state.json`
- persistent writer lock: `~/Library/Application Support/cloudflare-publish/manager.lock`
- tunnel token file: `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
- launch agent: `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- logs: `~/Library/Logs/cloudflare-publish/`
