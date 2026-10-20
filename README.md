# cloudflare-publish

`cloudflare-publish` is a macOS-only PATH-installable CLI that turns one Mac user profile into one managed
Cloudflare publication host. It owns one shared remotely managed Cloudflare Tunnel, one user launch
agent, one local state manifest, and many exact-hostname HTTP, HTTPS, or native SSH publications.
Protected audiences use Cloudflare Access; a `public` audience deliberately omits Access only when the origin
already enforces fail-closed application authentication.

## What It Is For

Use `cloudflare-publish` when a service is already running on this Mac and you want a stable
Cloudflare hostname for it without deploying the app into Cloudflare compute. It is the productized
"safe front door" from a browser, teammate, automation, provider callback, or agent to one localhost
HTTP, HTTPS, or machine-authenticated SSH origin.

Good fits:

- expose a local model or API server, such as an Ollama-style endpoint, to machine clients through a
  publication-scoped Access service token
- reach this Mac's already configured SSH server through a stable hostname, with Access machine
  authentication and a pinned Ed25519 SSH host key, without inbound router port forwarding
- share a local web app, dashboard, or demo with browser users through Cloudflare Access login
- expose a provider callback or transport endpoint whose origin already validates every request
  with its own application protocol and therefore cannot use Cloudflare Access headers
- connect a native HTTPS or WebSocket client to an origin-authenticated local application when the
  client cannot complete Access login or supply service-token headers
- give a temporary preview, webhook receiver, or diagnostics page a stable HTTPS hostname while it
  continues to run locally
- verify or repair the local tunnel manager after reboot, token drift, launch-agent drift, or remote
  Cloudflare drift
- rotate one publication's machine token or remove one hostname without touching unrelated services

First successful loop:

1. run the local service on `127.0.0.1`
2. check the manager with `cloudflare-publish --json doctor`
3. preview the hostname binding with `cloudflare-publish --json publish plan ...`
4. apply the exact-hostname publication only when ready with `cloudflare-publish publish apply ... --yes`
5. check the declared HTTP response or pinned SSH identity and audience boundary with
   `cloudflare-publish verify NAME --live`

The application's service, data, credentials, and start/stop policy stay with the application.
Follow the publication checks with its actual client or provider workflow when that outcome is
part of the work; a reachable hostname alone does not establish useful application behavior.

Do not use it to deploy application code, host Workers or Pages, create wildcard/path routing,
publish protocols other than HTTP(S) or SSH, manage private networks, or expose something that is
not already running locally.

## Product Boundary

The product manages:

- one macOS user profile
- one Cloudflare account
- one active full Cloudflare-managed DNS zone
- one shared remotely managed tunnel
- many exact-hostname HTTP, HTTPS, or machine-authenticated native SSH origins
- zero or one Access application per publication, according to audience
- zero or one service token per publication

The product does not manage:

- wildcard hostnames
- path-based routing
- private network routes
- general TCP, UDP, RDP, SMB, VPN, or WARP publication
- enabling macOS Remote Login, SSH users/private keys, reverse-tunnel supervisors, or remote servers
- Cloudflare IdP setup
- remote dashboard token rotation
- multiple accounts or multiple zones per manager

## Local Ownership

The manager owns these local paths:

- `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- `~/Library/Application Support/cloudflare-publish/state.json`
- `~/Library/Application Support/cloudflare-publish/manager.lock`
- `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
- `~/Library/Application Support/cloudflare-publish/backups/<timestamp>/`
- `~/Library/Logs/cloudflare-publish/cloudflared.out.log`
- `~/Library/Logs/cloudflare-publish/cloudflared.err.log`

The manager does not treat these legacy paths as canonical state:

- `~/.cloudflared/config.yml`
- `~/.cloudflared/cert.pem`

Takeover only backs up and removes the conflicting legacy launch agent plus those two legacy files.
It does not promise to erase every unrelated leftover in `~/.cloudflared/`.

## Requirements

- macOS
- `uv`
- `cloudflared` `2025.4.0` or later
- native OpenSSH client for SSH verification; an independently configured local SSH server and its
  trusted Ed25519 public host key for SSH publication
- a Cloudflare account with a Zero Trust organization
- an active full DNS zone in that account
- a Cloudflare API token with the required account and zone scopes

Partial (`CNAME`) zones are not supported. This product owns Cloudflare DNS records directly.
The hostname also needs a valid Cloudflare edge certificate. For nested names such as
`app.dev.example.com`, arrange suitable certificate coverage separately; Cloudflare's
[Tunnel API guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/)
calls for an Advanced Certificate for multi-level subdomains. This CLI does not order certificates.

Human-access publications assume the Zero Trust organization already has a usable login method.

## Install The CLI And Plugin

The CLI is standalone; the optional agent plugin teaches Codex and Claude Code how to operate it.
They install separately. The plugin requires a local macOS executor with shell access, not a
browser-only chat or a cloud worker. It includes no Cloudflare account or hosted service.

From an explicitly selected source checkout or this plugin's package root, install the CLI onto
`PATH`:

```bash
uv tool install --reinstall .
```

This changes only the installed Python CLI. It does not
copy a skill into a global directory, install cloudflared, create a background job, read credentials,
or configure Cloudflare. Python 3.12 or later is required; `uv` manages the CLI's isolated environment.

Check the selected CLI from outside the source directory, without credentials or network calls:

```bash
command -v cloudflare-publish
cloudflare-publish --version
cloudflare-publish --help
```

The package contains portable `plugin.json`, Claude Code metadata, and one shared `skills/` tree.
The public development source for both CLI and plugin is
[Tiziano-AI/cloudflare-publish](https://github.com/Tiziano-AI/cloudflare-publish).
The `tiziano-ai` marketplace pins reviewed revisions from that same complete source; there is no
separate plugin-only source repository. Install the guidance through your host's native marketplace:

**Codex:**

```bash
codex plugin marketplace add https://github.com/Tiziano-AI/plugins.git --json
codex plugin add cloudflare-publish@tiziano-ai --json
```

**Claude Code:**

```bash
claude plugin marketplace add https://github.com/Tiziano-AI/plugins.git --scope user --json
claude plugin install cloudflare-publish@tiziano-ai --scope user --json
```

If `tiziano-ai` is already registered, refresh it instead of adding it again:
`codex plugin marketplace upgrade tiziano-ai --json` or
`claude plugin marketplace update tiziano-ai --json`, then install the plugin as above.
Check the installed version and enablement with `codex plugin list --json` or
`claude plugin list --json`. Start a new host session to load newly installed guidance; an existing
session may retain its earlier skill catalog.

For an unpublished local preview only, Claude Code can load an explicitly selected checkout with
`claude --plugin-dir /path/to/cloudflare-publish`; that is not a persistent native installation.
Do not install a second global copy of the same skill alongside the plugin.

Ask the agent to plan a private hostname for a local app. It should first discover the CLI, explain
the account and origin requirements, and stop before any setup or publication that you have not
authorized. Plugin installation itself does not run that workflow.

After installing cloudflared and preparing your own account and API token, check readiness with
`cloudflare-publish --json doctor`. It resolves credentials and may contact Cloudflare; unlike
`--version` and `--help`, it is not an offline installation check.

`doctor` is diagnostic. It exits zero when the diagnostic run completes, even when the returned
JSON reports `"ready": false` because setup, auth, or manager state is missing.

The repo-local development wrapper remains available:

```bash
./bin/cloudflare-publish --help
```

## Upgrade And Removal

Upgrade the CLI explicitly from the selected new source with `uv tool install --reinstall .`; update the
plugin through the host. Neither action changes account identity or reconciles managed resources.
Check `cloudflare-publish --version` and the host's selected plugin version independently.

Removing or disabling the plugin removes its guidance only. The separately installed CLI,
cloudflared connector, launch agent, DNS, tunnel, Access policies, tokens, Keychain entries, manager
state, logs, and takeover backups remain. To remove only the CLI, run:

```bash
uv tool uninstall cloudflare-publish
```

That does **not** stop serving existing publications. For full retirement, keep the CLI available,
inspect the manager and its publications, then deliberately run `cloudflare-publish teardown --yes`
only when removing every managed hostname and the shared tunnel is intended. Afterwards uninstall
the CLI and remove the plugin through the host. Teardown preserves takeover backups and
`manager.lock`; it does not restore the legacy configuration or change unrelated Cloudflare state.

## Common Local Commands

For local development, install dev dependencies from the checkout:

```bash
uv sync --group dev
```

Useful terminal-first checks and lifecycle commands:

- status: `cloudflare-publish --json doctor`
- repair planning: `cloudflare-publish repair plan`
- live verification: `cloudflare-publish verify --live`
- repo gate: `uv run devtools/gate.py`
- connector lifecycle: `service start`, `service stop`, `service restart`, `service logs`
- publication inventory: `ls`
- manager, remote-routing, Access, and origin readiness checks: `verify`
- guard inspection: `guard status`
- high-impact mutations: `setup`, `setup --refresh-only`, `publish apply`, `rm apply`,
  `token rotate`, `tunnel recover apply`, `guard apply`, `teardown --yes`

`verify` and `repair plan` resolve credentials, read Cloudflare, and probe origins. Their HTTP
requests use private temporary curl files; SSH checks also use private temporary known-host material
and native OpenSSH processes without login credentials. They change no managed local or Cloudflare
state, but are neither offline nor strict no-file-write operations. `--live` adds public-hostname probes.

## Cloudflare API Token

The easiest reliable token shape is:

Account permissions:

- `Account Settings: Read`
- `Cloudflare Tunnel: Edit`
- `Access: Service Tokens: Edit`
- `Access: Organizations, Identity Providers, and Groups: Edit`
- `Access: Apps and Policies: Edit`

Zone permissions:

- `Zone: Zone: Read`
- `DNS: Edit`

Resource scope:

- the target account
- the target zone

The organization permission covers the product's organization reads and guard update; an
additional broad `Zero Trust Edit` permission is not required by those documented endpoints.
See the [permission reference](skills/cloudflare-publish/references/cloudflare-api-and-permissions.md)
for the official endpoint contracts.

The CLI resolves the API token in this order:

1. explicit `--api-token` for local emergency or tests
2. process environment `CLOUDFLARE_API_TOKEN`
3. private dotenv file pointed at by `CLOUDFLARE_PUBLISH_DOTENV`, key `CLOUDFLARE_API_TOKEN`
4. macOS Keychain, after a manager state file exists

For initial interactive setup, omit `--api-token` and enter the token at the terminal prompt. For
non-interactive setup, either export `CLOUDFLARE_API_TOKEN` for one command or set
`CLOUDFLARE_PUBLISH_DOTENV` to an absolute path for a strict private dotenv file outside the
repository. The CLI does not read tracked `.env` files. Unset short-lived shell environment after
the command, and keep token values out of chat logs, shared shell transcripts, and reusable docs.

The CLI also accepts these setup environment fallbacks:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_ID`
- `CLOUDFLARE_ZONE`
- `CLOUDFLARE_TUNNEL_NAME`

Explicit flags override the process environment, and the process environment overrides matching
keys in the configured private dotenv file.

## JSON Output

Use `--json` when another tool or Codex thread needs stable output:

```bash
cloudflare-publish --json doctor
cloudflare-publish --json discover accounts
cloudflare-publish --json inspect grafana
cloudflare-publish --json verify grafana --live
```

Successful JSON output uses:

```json
{"ok": true, "command": "inspect", "output_class": "public_diagnostic", "data": {}, "warnings": []}
```

Error JSON output uses:

```json
{"ok": false, "command": "verify", "output_class": "evidence_error", "error": {"code": "verify_failed", "message": "...", "hints": []}, "data": {}, "warnings": []}
```

JSON errors redact credentials. `public_diagnostic` payloads never include secrets.
`evidence_error` payloads preserve safe failing-check evidence on nonzero exits. `credential_handoff`
payloads are the only success payloads that include service-token secrets, and only for
`publish apply` on `machine` or `mixed` publications and `token rotate`.

## Discovery

Discovery commands require an API token but do not require an initialized local manager:

```bash
cloudflare-publish --json discover accounts
cloudflare-publish --json discover zones --account-id "$CLOUDFLARE_ACCOUNT_ID"
cloudflare-publish --json discover zone example.com --account-id "$CLOUDFLARE_ACCOUNT_ID"
cloudflare-publish --json discover tunnels --account-id "$CLOUDFLARE_ACCOUNT_ID"
cloudflare-publish --json discover tunnel "$CLOUDFLARE_TUNNEL_ID" \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" --zone-id "$CLOUDFLARE_ZONE_ID"
cloudflare-publish --json discover organization --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

The CLI has no raw Cloudflare API escape hatch. Discovery returns typed payloads only.

`discover tunnel ID --account-id ACCOUNT --zone-id ZONE` inspects the exact tunnel, not whichever
manager happens to be installed. The zone must belong to the supplied account. Its allowlisted
result summarizes tunnel and zone identity, ingress, matching DNS and Access, and unsupported
topology, including wildcard/path rules, services other than HTTP(S) and SSH, private-network
configuration, global origin options, and unknown configuration fields. It never fetches a tunnel token or dumps raw
configuration. The coverage statement makes the inspection's limits explicit; it is not a complete
dependency audit of application consumers or provider targets. Discovery neither adopts resources
nor authorizes their removal.

An exact-tunnel GET can return a deleted tunnel's tombstone. Discovery preserves `deleted_at` and
reports `deleted_tunnel` instead of treating it as a down locally managed tunnel. It skips obsolete
ingress configuration but still shows selected-zone DNS pointing at that tunnel and Access apps
matching those residual names. Empty ingress here does not prove DNS or connector retirement.

Matching Access applications expose `has_destination_overrides`; policies expose
`has_additional_constraints` for additional `require`/`exclude` rules. These Booleans are presence
metadata only. Override and constraint payloads and their semantics are not inspected
or printed, and findings `access_destination_overrides` and
`unreported_policy_constraints` mark that limitation. Policy selector summaries contain only
`include` rule kinds. A hostname-bearing `http_status` rule is flagged as
`non_http_publication_service`, unlike the supported terminal hostless `http_status:404`.

## Concurrent Writes And Manifest Safety

`setup` (including refresh), `publish apply`, `rm apply`, `token rotate`, `guard apply`,
`tunnel recover apply`, `teardown`, and `service start`, `stop`, and `restart` acquire one local OS
writer lock before their workflow reads or effects. A concurrent writer fails immediately with
`manager_busy`; read-only commands remain available. Let the current operation settle rather than
deleting `manager.lock`, which remains on disk even after teardown and does not by itself indicate
an active writer.

`state.json` is staged with mode `0600` beside the destination and replaced atomically after a
successful write. Failed staging preserves the previous manifest. This protects local writers and
manifest integrity, not dashboard edits or Cloudflare transactions.

### Interrupted changes

An unfinished mutation remains in one `pending` transition in `state.json`: operation identity,
normalized request, phase, effective route, owned candidate resources, and any unknown external
effect. It contains Keychain references, not secrets, and disappears when the operation completes.
A compatible repeat of the original confirmed command resumes the same work. An incompatible
mutation fails with `transition_pending`; reads and plans remain available. Do not delete or edit
`pending` to make the next command run, and do not substitute setup refresh for an interrupted
publication or removal.

Start with:

```bash
cloudflare-publish --json repair plan
```

If a resource-creation response was lost, the CLI refuses to repeat that POST blindly. Use the
operation ID and exact candidate ID reported by the plan, not a guessed resource name:

```bash
cloudflare-publish repair resolve --operation OPERATION_ID --resource-id RESOURCE_ID --yes
```

This validates the resource against the saved intent and records ownership; it does not finish
or forget the enclosing mutation. If no resource was created, the alternative is:

```bash
cloudflare-publish repair resolve --operation OPERATION_ID --absent --yes
```

That command must prove absence through a complete scoped remote list before permitting a retry.
After either resolution, repeat the original command. A remote token ID cannot recover its lost
secret. If the plan identifies an unfinished publication's candidate token with no recoverable
secret, retire only that candidate, then repeat the original publication command:

```bash
cloudflare-publish repair retire-token --operation OPERATION_ID --resource-id RESOURCE_ID --yes
```

The original publication remains owned. For an already completed publication's missing local
secret, use explicit `token rotate NAME --yes`. If the rotation itself has an unknown secret
outcome, use `token rotate NAME --recover --yes`; see [token recovery](#token-guard-remove-and-teardown).

Protected HTTP and SSH ingress validates Access JWTs in `cloudflared` against that application's
AUD and organization as well as using Access at the edge. Authorization-boundary or hostname
changes replace the Access application/AUD; origin-only changes may reuse it. A connector with an
old configuration retains its old origin and matching old protection. Withdrawal is saved before
routing changes, and cleanup waits for the exact target configuration version on every observed
active connector, after the full remote configuration and its version match the intended state.
If Cloudflare's API omits the local connector's version, the CLI can obtain it from that
connector's native loopback diagnostics: it checks the launchd process and listener ownership,
the exact tunnel and connector identities, and the applied version. It does not scan ports,
traverse a proxy or read process arguments, environment, tokens or logs. This fills only an
omitted version for that exact connector, never overrides an API-reported mismatch, and proves
nothing about another replica. Missing, stale or conflicting evidence keeps the transition
pending, rather than declaring cleanup complete or globally disconnecting connectors.

These boundaries do not promise instantaneous revocation of every previously issued JWT or
termination of an established SSH, WebSocket, or application session. Removal retires the route
and owned resources, not application sessions. Full teardown requires confirmed tunnel deletion
before removing Access protection.

## Setup

Interactive bootstrap:

```bash
cloudflare-publish setup --install-deps
```

`--install-deps` uses Homebrew to install `cloudflared`, so Homebrew must already be on `PATH`.

Non-interactive bootstrap:

```bash
cloudflare-publish setup \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --zone example.com
```

Optional tunnel name override:

```bash
cloudflare-publish setup \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --zone example.com \
  --tunnel-name my-mac
```

Takeover bootstrap when conflicting local `cloudflared` ownership already exists:

```bash
cloudflare-publish setup --takeover --yes \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --zone example.com
```

`setup` is also the refresh path for an existing manager. Rerunning it:

- refreshes the tunnel runtime token
- validates the complete remote tunnel configuration before applying owned state
- reinstalls the canonical launch agent

Refresh refuses foreign routes, global options, unsupported fields, or other configuration drift
rather than overwriting them. It can upgrade the exact owned pre-validator configuration to native
per-route Access validation; it is not a general dashboard-drift reset. Refresh cannot change the
manager's account, zone, or tunnel identity.

Refresh only an already-bootstrapped manager:

```bash
cloudflare-publish setup --refresh-only
```

`--refresh-only` refuses to create initial manager state. It is a deliberate terminal repair command,
not a hidden one-click action.

`setup` fails closed when:

- `--refresh-only` is used before local manager state exists
- conflicting local `cloudflared` state exists and `--takeover` is missing
- `cloudflared` is older than `2025.4.0`
- the token cannot see the chosen account or zone
- the chosen zone does not belong to the chosen account
- the chosen zone is not `active` and `full`
- an unfinished incompatible mutation exists
- remote tunnel configuration does not match the owned contract
- an operation-specific tunnel creation marker is already in use

The selected tunnel name is a logical manager name. The created remote name includes the setup
operation ID; do not assume a same logical name is the exact remote object or adopt it manually.
An uncertain creation is resolved through `repair plan` and exact-resource resolution.

## Connector Service Lifecycle

The `service` command group manages only the local `cloudflared` launchd connector. It does not
change Cloudflare remote resources or publication state. `service start` and `service restart`
validate the existing launch-agent plist before invoking launchd: the plist must use the canonical
label, point at the manager token file, and encode a `cloudflared` binary that supports
`--token-file`.

Show local lifecycle state:

```bash
cloudflare-publish service status
```

Start an existing launch agent:

```bash
cloudflare-publish service start
```

Stop the connector without deleting manager state:

```bash
cloudflare-publish service stop
```

Restart a loaded connector:

```bash
cloudflare-publish service restart
```

Print recent connector logs:

```bash
cloudflare-publish service logs
cloudflare-publish service logs --lines 200
```

Use `setup` when the launch-agent plist or tunnel token file is missing or stale. Use `verify` when
the question is whether local state and Cloudflare remote state still match.

## Publish

Machine-only publication:

```bash
cloudflare-publish publish apply grafana \
  --hostname grafana.example.com \
  --to http://127.0.0.1:3000 \
  --audience machine \
  --yes
```

Human publication:

```bash
cloudflare-publish publish apply dashboard \
  --hostname dashboard.example.com \
  --to https://127.0.0.1:8443 \
  --audience human \
  --allow-email you@example.com \
  --yes
```

Mixed publication with origin tuning:

```bash
cloudflare-publish publish apply app \
  --hostname app.example.com \
  --to https://127.0.0.1:9443 \
  --audience mixed \
  --allow-domain example.com \
  --http-host-header app.internal \
  --origin-server-name app.internal \
  --verify-path /healthz \
  --expect-status 200-204 \
  --yes
```

Public transport with fail-closed origin authentication:

```bash
cloudflare-publish publish apply provider-ingress \
  --hostname provider-ingress.example.com \
  --to http://127.0.0.1:4751 \
  --audience public \
  --verify-path / \
  --expect-status 400-499 \
  --yes
```

`public` creates the proxied DNS and tunnel route but no Access application, policy, or service
token. Use it only when the origin itself rejects unsigned or otherwise unauthenticated requests;
the status profile must prove that rejection or another exact origin contract.

For native clients, first establish whether Access login or service-token headers are supported.
If neither is, an origin-authenticated `public` publication needs authorization for the
Internet-reachable hostname and pairing surface, plus unauthenticated rejection at a real sensitive
endpoint locally and through the hostname. A public descriptor or a `200` from SPA fallback proves
neither an authentication bypass nor protection. Preserve the public Host and forwarded HTTPS
scheme when the application derives client URLs; use `--http-host-header` only when the origin
requires it.

Use the application's installed help and live protocol descriptor rather than assuming a source
checkout matches its runtime. Check authenticated HTTPS and, when used, WebSocket traffic through
the hostname using the intended native transport where practical; that proves transport, not actual
device pairing or application use. Application pairing and session credentials stay with their owner
and out of tracked files. The skill's
[native-client recipe](skills/cloudflare-publish/references/operator-recipes.md#native-clients-with-origin-owned-authentication)
also covers temporary credential cleanup and diagnostic User-Agent rejection.

Publication rules:

- `--hostname` must be one exact hostname inside the configured zone
- `--to` uses `http://` or `https://` for web origins, or `ssh://` for native SSH
- `human` and `mixed` require at least one `--allow-email` or `--allow-domain`
- `public` rejects Access allow rules
- `--verify-path` must be a path-only value beginning with `/`; query strings, fragments,
  whitespace, and control characters are rejected
- `--expect-status` must be a closed inclusive range such as `200-399`
- SSH requires `--audience machine` and `--ssh-host-key` with one valid `ssh-ed25519` public key;
  optional key comments are accepted but not stored
- SSH rejects every HTTP verification/origin option and all email/domain allow rules; its HTTP
  verification fields are null. HTTP(S) rejects `--ssh-host-key`

For `machine` and `mixed` publications, `publish apply` prints the current service-token client ID
and client secret after reconciliation. That output is the canonical machine-credential handoff.
It does not implicitly rotate a completed publication's missing local secret: use `token rotate
NAME --yes` explicitly. A credential-handoff failure after publication can report
`credential_handoff_unavailable` with `publication_applied: true`; do not mistake that for rollback.

Preview one publication mutation without changing local or remote state:

```bash
cloudflare-publish --json publish plan grafana \
  --hostname grafana.example.com \
  --to http://127.0.0.1:3000 \
  --audience machine
```

## Publish Native SSH

The SSH server must already be running and authorized for the intended users. This product does
not enable macOS Remote Login or configure SSH login keys. Read the server's public host key
through an already trusted channel, not by trusting a new connection to the published hostname.
For a standard local macOS server, the public key is `/etc/ssh/ssh_host_ed25519_key.pub`.

```bash
SSH_HOST_KEY="$(cat /etc/ssh/ssh_host_ed25519_key.pub)"
cloudflare-publish --json publish plan mac-ssh \
  --hostname mac.example.com \
  --to ssh://127.0.0.1:22 \
  --audience machine \
  --ssh-host-key "$SSH_HOST_KEY"
```

After reviewing the plan, run the same `publish apply` arguments with `--yes`, then:

```bash
cloudflare-publish verify mac-ssh --live
```

This reuses the existing shared tunnel, not a new connector or a public TCP listening port. The
origin scheme selects `ssh_public`. Existing HTTP publications stay in the same manager.
`publish apply` hands off one publication-scoped Access service token; keep its secret in private
machine credential storage, not chat, process arguments, tracked files, or shell history.

The client needs `cloudflared` as an OpenSSH `ProxyCommand`, the Access token in its environment,
the independently copied server host-key pin, and a separately authorized SSH login key. Follow
the [native SSH client recipe](skills/cloudflare-publish/references/operator-recipes.md#publish-native-ssh)
for those boundaries and a reverse-forwarding design for remote machines.

Cloudflare carries the outer transport and remains an account and availability dependency; native
SSH with strict host-key checking keeps the SSH contents encrypted end-to-end between client and
server. This is not a third-party-free connection, VPN, or general UDP tunnel. WebSocket transport
can disconnect: supervise long-lived SSH separately, and keep remote work independent of its
connection. A stable hostname cannot reach a Mac that is asleep, offline, or not serving SSH.

## Inspect And Verify

List managed publications:

```bash
cloudflare-publish ls
```

Inspect one publication:

```bash
cloudflare-publish inspect grafana
```

For HTTP, `inspect` shows the public verification URL, local origin URL, verification profile, audience,
Access allow rules, origin request options, remote resource IDs, and service-token client ID when
one exists. Public publications explicitly retain no Access metadata. It does not print
service-token client secrets. Plain HTTP origins report origin TLS verification as not applicable.
SSH inspection instead shows the pinned public host key and native-SSH verification scope, with
no HTTP response profile or origin TLS assertion.

Run manager, remote-routing, Access, and origin verification:

```bash
cloudflare-publish verify
cloudflare-publish verify grafana
```

Add public-hostname verification:

```bash
cloudflare-publish verify --live
cloudflare-publish verify grafana --live
```

`verify` without `--live` checks:

- local `cloudflared` version supports `--token-file`
- local state file presence
- tunnel token file presence
- canonical launch agent presence and load state
- remote tunnel health and reachability
- Zero Trust organization reachability
- parity of the complete supported tunnel configuration, including per-route Access AUD and
  organization validation on every protected HTTP or SSH route
- per-publication origin probe parity
- DNS record id, target, and proxy parity
- Access app hostname and policy parity for protected publications
- policy parity fails if additional `require`/`exclude` constraints are present, rather than
  treating an include-only match as full policy parity
- absence of Access resources and auth metadata for public publications
- and it keeps reporting checks when one probe fails instead of aborting early

`verify --live` additionally checks the audience-specific endpoint boundary:

- protected publications deny anonymous HTTP requests through Access with either an explicit deny or an
  Access login redirect
- HTTP `machine` and `mixed` publications authenticate with the current service token
- SSH publications complete native signed SSH key exchange through `cloudflared` using the current
  service token and the pinned host key
- `public` publications reach the origin and return the exact configured status class without
  Access headers

It does not perform a full interactive human login flow.

For SSH, origin verification proves native signed key exchange against the pin; `--live` repeats
that proof through the public hostname and Access transport. It uses neither private keys nor SSH
login credentials and proves no authenticated shell, reverse forwarding, or session persistence.
The anonymous HTTP check proves only that Access denies that HTTP request. Managed Access apps
use `service_auth_401_redirect: true`, which requests HTTP 401 on Service Auth denial, despite the
setting's name. Public SSH probing first requires that flag, exact machine-only policy parity, and
anonymous HTTP 401/403; a login redirect fails this SSH preflight rather than invoking a browser.

Human output groups checks under Manager, Routing, Origin, Access, and Public probe headings. JSON
uses `manager`, `routing`, `origin`, `access`, and `public_probe`: each check has `group`,
`publication_name`, and `hostname` (the identity fields are null for manager-wide checks).
`data.checks` remains a flat check array and `data.failures` its aggregate failing-check count.
`data.groups` contains populated groups in order, with `group`, a `checks` array, and a `failures`
count, including in a `verify_failed` error result.

An on-demand application's unavailable origin is still a readiness failure. Verification does not
start that application or claim that it is always available. A configured 404/405 response checks
the declared probe behavior, not authenticated application use, successful email receipt, native
device control, generated-video upload, or model inference.

## Tunnel Recovery

Recover the local connector after a dashboard tunnel-token rotation or a shared-tunnel incident:

```bash
cloudflare-publish tunnel recover plan
cloudflare-publish tunnel recover apply --yes
```

`tunnel recover`:

- fetches the current remote tunnel token
- rewrites the local token file
- reinstalls and restarts the canonical launch agent
- deletes all active connectors for the shared tunnel through the Cloudflare API

This is intentionally high impact. It disconnects every connector on the shared tunnel, including
replicas not managed by this workstation. Run the plan form first and inspect the planned connector
blast radius before using `apply --yes`.

The product does not rotate the remote tunnel token for you. Rotate it in the Cloudflare dashboard
first, then run `tunnel recover`.

## Token, Guard, Remove, And Teardown

Rotate one machine token:

```bash
cloudflare-publish token rotate grafana --yes
```

`token rotate` prints the new client ID and client secret after rotation. Use it to reissue a
machine credential when the local or downstream copy is gone.

If its response or new-secret storage was interrupted, run `repair plan`. Plain rotation refuses
an unknown outcome rather than silently rotating again. Explicitly authorize replacement of that
uncertain secret with:

```bash
cloudflare-publish token rotate grafana --recover --yes
```

`--recover` requires the exact pending rotation; it is not a general retry flag or a way to retrieve
an old secret. Replace downstream credentials deliberately after the handoff. Rotation does not
promise that already issued JWTs or established sessions are immediately revoked.

Show account-level unmatched-request protection:

```bash
cloudflare-publish guard status
```

Enable account-level unmatched-request protection:

```bash
cloudflare-publish guard plan
cloudflare-publish guard apply --yes
```

`guard apply` preserves any existing `deny_unmatched_requests_exempted_zone_names` values. The
product preserves the full current organization payload while enabling the guard bit, so it does
not take ownership of broader organization customization. `guard plan` and `guard apply` fail when
the change would block a managed `public` publication, unless the configured zone is already
exempted. `guard status` remains readable and lists the blocking publication names.

Remove one publication:

```bash
cloudflare-publish rm plan grafana
cloudflare-publish rm apply grafana --yes
```

Removal records withdrawal before changing ingress, observes the target configuration on every
active connector, then deletes the owned DNS, Access resources, and service token. An interrupted
withdrawal stays effective during diagnosis and cannot be resurrected by a generic refresh.
Unknown or stale connector application leaves cleanup pending; repeat the original removal after
the observation is available.

Remove the whole manager:

```bash
cloudflare-publish teardown --yes
```

Teardown records intent, stops and confirms removal of the local connector, and refuses active or
unobservable remote replicas. It deletes and confirms deletion of the exact shared tunnel while
Access remains intact, then removes owned DNS, Access resources, service tokens, and finally local
credentials and manager artifacts. It does not forcibly disconnect other machines' replicas.
A failure retains custody for the same command to resume. Confirmed tunnel deletion is a transport
boundary, not proof that application sessions or workloads have ended.

Takeover backups and `manager.lock` survive; the lock file must not be unlinked while the operation
holds it and remains safe to reuse for a later setup.

`setup`, `setup --refresh-only`, `publish apply`, `token rotate`, `guard apply`, `rm apply`,
`teardown --yes`, `setup --takeover`, and `tunnel recover apply` are all explicit-impact commands.

## Secret Handling

- Cloudflare API token: macOS Keychain
- Access service-token secrets: macOS Keychain
- shared tunnel runtime token: local file with strict permissions for launchd use

Keychain writes send a bounded `security -q -i` command over stdin, using UTF-8 hex password input
and exact readback verification instead of a noninteractive password prompt. The adapter accepts
nonempty printable ASCII credentials, not arbitrary binary passwords. Secret material stays out of
process arguments and write diagnostics. Deletion errors retain cleanup custody rather than
pretending an entry is absent. Curl ignores user curlrc configuration and writes headers and JSON bodies into
strict-permission temporary files, so API bearer tokens and Access service-token secrets are not
exposed through curl argv.

`publish` and `token rotate` print the current machine token material for operator handoff. `inspect`
does not print secrets.

## Troubleshooting

If the API token cannot see any accounts:

```bash
cloudflare-publish --json discover accounts
```

An empty typed `accounts` array usually means the token is missing `Account Settings: Read` or the
account resource scope.

If the token cannot list the zone, confirm it also has `Zone: Zone: Read` in addition to
`DNS: Edit`, and confirm the selected zone is `active` and `full`.

```bash
cloudflare-publish --json discover zones --account-id "$CLOUDFLARE_ACCOUNT_ID" --name "$CLOUDFLARE_ZONE"
```

If the zone response reports `type: "partial"`, the product is blocked because partial (`CNAME`)
setup requires external DNS management instead of Cloudflare-managed DNS records.

If the token can see the zone but setup still fails, probe the Zero Trust organization:

```bash
cloudflare-publish --json discover organization --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

If setup reports an uncertain remote tunnel creation or an operation-marker collision, inspect the
pending operation first, then list exact candidates as needed:

```bash
cloudflare-publish --json repair plan
cloudflare-publish --json discover tunnels --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

Do not delete or adopt a resource from its logical name alone. Use the plan's exact-resource
resolution for a pending creation. Unrelated unmanaged cleanup belongs to a separately authorized
Cloudflare operator task; this CLI has no raw vendor API escape hatch.

If verification reports foreign tunnel-config drift, inspect the reported fields and remote owner.
Ordinary writes, including setup refresh, refuse to overwrite it. If the problem is only a missing
or stale local launch agent or tunnel-token file and no mutation is pending, use `setup` for the
same manager.

If a completed machine publication loses its local service-token secret, run
`cloudflare-publish token rotate NAME --yes` to issue a replacement explicitly. For an unfinished
candidate or interrupted rotation, follow the pending operation's recovery path above instead.

If the shared tunnel token was rotated in the dashboard or a compromised token requires all
connectors to be forced off the edge, plan first and then run the confirmed mutation:

```bash
cloudflare-publish tunnel recover plan
cloudflare-publish tunnel recover apply --yes
```

If `setup --takeover` has already removed the old launch agent and legacy config, do not keep
rerunning takeover blindly. Once the old local conflict is gone, use plain `setup` as the refresh
path.
