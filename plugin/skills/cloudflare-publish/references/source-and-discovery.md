# Source And Discovery

## Runtime posture

- The operator runtime is the separately installed `cloudflare-publish` command: the one on
  `PATH`, or `"$(uv tool dir --bin)/cloudflare-publish"` until `PATH` includes uv's tool
  directory.
- Its one channel is a GitHub release tag, installed with
  `uv tool install git+https://github.com/Tiziano-AI/cloudflare-publish@v0.4.0` for the version
  this skill pins. The [CLI preflight](../SKILL.md#cli-preflight) owns selection, the version
  comparison, and when to install, offer an upgrade, or refuse to downgrade.
- This plugin contains no CLI or runtime source. Never run the CLI from the plugin folder or a
  source checkout, use `uv run` or `uvx` as the operator runtime, or run setup as an installation
  side effect. A missing CLI blocks installed operation, not explanation or work in a resolved
  source checkout.

The single public development and release source for the CLI and plugin is
[Tiziano-AI/cloudflare-publish](https://github.com/Tiziano-AI/cloudflare-publish).
The `tiziano-ai` marketplace pins a release tag's commit and installs only its `plugin/`
directory. Native plugin installation and CLI installation are separate. A local Claude
`--plugin-dir` session does not establish persistent native installation or migration.

## Source and explanation

Use the source contract and relevant implementation for product-purpose questions and source
changes. No installation, credentials, or manager inspection is needed for those claims. An
unknown source owner must be resolved before editing; a known source checkout need not be
installed to be read or changed.

## First discovery sequence

For installed operation, check which CLI is installed and selected:

```bash
command -v cloudflare-publish
type -a cloudflare-publish
cloudflare-publish --version
cloudflare-publish --help
```

If `command -v` finds nothing, check `"$(uv tool dir --bin)/cloudflare-publish"` and call it by
that absolute path; when `uv` itself is not on `PATH`, look for it at
`"${XDG_BIN_HOME:-$HOME/.local/bin}/uv"` first. These commands are offline and read no credentials.
They establish selection and the installed version, not manager readiness; compare the version as
the CLI preflight describes. The package inspection script likewise resolves the CLI from `PATH`,
then from uv's tool directory; it never treats a nearby checkout or the plugin folder as the
installed runtime.

When current install/auth/readiness is the question, use `cloudflare-publish --json doctor`.
It resolves credentials and contacts Cloudflare account discovery when a token is available.
Inspect `data.ready` and `data.checks`; diagnostic completion is not readiness.

For local manager facts, run `scripts/inspect-manager.sh` from this resolved skill package even if
the source checkout is unresolved. It chooses the host's canonical paths and reads only safe native
service metadata, not process arguments/environment or credential files.

Manual macOS surfaces:

```bash
ls -la "$HOME/Library/Application Support/cloudflare-publish"
ls -la "$HOME/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist"
launchctl list | grep com.cloudflare-publish.cloudflared || true
cloudflared --version
```

Manual Linux surfaces:

```bash
ls -ld "$HOME/.local/state/cloudflare-publish" \
  "$HOME/.config/systemd/user/cloudflare-publish.service"
systemctl --user show cloudflare-publish.service \
  --property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID
loginctl show-user "$(id -u)" --property=Linger --value
cloudflared --version
```

Do not dump a unit/plist or use raw service `status`, argv or environment output to diagnose drift:
an untrusted noncanonical service can contain inline credentials. Linux needs systemd 240+, a
working user bus and operator-enabled lingering; the product never repairs these through sudo.

## When the command is unresolved

- If local manager state is in scope, continue to inspect its runtime artifacts; these do not
  establish remote parity or public-hostname behavior.
- Do not invent a repository path, install from a checkout or the plugin folder, or claim the
  command is operational. Installation goes through the CLI preflight.

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

## Canonical macOS runtime surfaces

- state manifest: `~/Library/Application Support/cloudflare-publish/state.json`
- persistent writer lock: `~/Library/Application Support/cloudflare-publish/manager.lock`
- tunnel token file: `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
- launch agent: `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- logs: `~/Library/Logs/cloudflare-publish/`

## Canonical Linux runtime surfaces

- state manifest: `~/.local/state/cloudflare-publish/state.json`
- persistent writer lock: `~/.local/state/cloudflare-publish/manager.lock`
- tunnel token file: `~/.local/state/cloudflare-publish/tunnel-token.txt`
- private secret store: `~/.local/state/cloudflare-publish/credentials/`
- logs: `~/.local/state/cloudflare-publish/logs/`
- user unit: `~/.config/systemd/user/cloudflare-publish.service`

These are host-owned surfaces, not a portable manager bundle. Each independent host/profile must
create a distinct remotely managed tunnel. Installing a release and a hermetic gate do not
establish live Linux acceptance, authorize an endpoint, or configure an origin application.
