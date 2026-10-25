# cloudflare-publish Architecture

`cloudflare-publish` is a macOS and Linux operator tool for publishing local HTTP, HTTPS, and
machine-authenticated native SSH services. One manager per host/user profile owns one distinct remotely
managed Cloudflare Tunnel, one native user service, one state manifest, and one CLI. The agent
plugin teaches the same CLI; it adds no separate runtime or infrastructure owner.

## Host platform contract

macOS retains its existing launchd, Keychain and `~/Library` ownership. Linux supports headless
hosts with systemd user services (systemd 240 or newer), with DGX ARM64 as this extension's
deployment target, not system services, root daemons,
containers without a user manager, or a Mac relay. Each independent host creates its own tunnel;
copying a manager manifest or tunnel credential from another host is not bootstrap. A single
host's publications share only that host's tunnel. HTTP/WSS application traffic goes directly
through Cloudflare to that host; publishing does not move inference or application execution.

Linux owns `~/.local/state/cloudflare-publish/` for its atomic manifest, persistent lock, runtime
token, private credentials and logs, and
`~/.config/systemd/user/cloudflare-publish.service` for its canonical unit. The service uses an
absolute executable, the existing `tunnel run --token-file PATH` argument contract, restart on
failure, restrictive umask and append-only stdout/stderr file destinations. Native `systemctl
--user` owns enable/start/stop/restart and user-manager readback; stop disables automatic startup
and confirms inactivity. Teardown atomically renames only the owned inactive/disabled unit to
`~/.config/systemd/user/.cloudflare-publish.service.retiring`, reloads the user manager, and requires
native not-found/inactive/disabled/PID-zero evidence before deleting that custody file. Failed or
interrupted reload/removal resumes through `teardown --yes`, validating retained bytes and cached
native ownership before retrying. Setup/start refuse incomplete retirement; missing unit bytes
without custody never authorize deletion or adoption of a cached foreign definition.
Reinstallation also stops and disables the old connector before replacing its process. It retains
the exact old definition in `.cloudflare-publish.service.replacing` until reload and native absence
are confirmed, then writes, reloads and starts the new definition. This absence barrier prevents a
new on-disk executable from being confused with an old cached native definition. Interrupted
replacement resumes through the original setup/refresh or tunnel-recovery command; generic service
controls refuse incomplete replacement. Neither daemon-reload nor enabling an active unit counts
as restarting its existing process or loading a refreshed runtime token.
The systemd user manager must already be usable; unattended operation across logout/reboot also
requires the operator to arrange user lingering. Setup diagnoses this before creating remote
resources. It never invokes sudo, enables lingering, installs system packages on Linux, or
changes another service. `--install-deps` remains the explicit Homebrew-only macOS convenience.
Linux refuses legacy takeover: an operator must explicitly resolve conflicting legacy files or
services outside this product rather than letting it adopt system-wide ownership.

The user-service directory and every existing ancestor must be real directories owned by the
current user or root, without group/other write access (root-owned sticky ancestors are exempt
from the write-bit rule). Unsafe ancestry fails with `service_directory_unsafe`, identifying the
directory, four-digit octal mode and reason in both the message and JSON `data`. The host operator
resolves that prerequisite; the CLI never changes existing directory permissions. This is distinct
from a foreign unit, override or executable, which remains `service_ownership_conflict`.
Native observation requires every requested property except that systemd may omit `ExecStart`
for a coherent absent unit: `LoadState=not-found`, `ActiveState=inactive`, zero `MainPID` and
`ExecMainStatus`, empty `FragmentPath`, `DropInPaths` and `UnitFileState`, and
`NeedDaemonReload=no`. Only that exact shape normalizes the omitted property to empty. Loaded,
conflicting or otherwise incomplete observations still fail closed, and disk/custody ownership
checks remain required. Absence is used by first setup and the replacement/retirement barriers.

Linux persistent secrets are printable tokens in one file per opaque account reference under
`~/.local/state/cloudflare-publish/credentials/`. The directory must be owned by the current UID,
mode 0700; files must be owned regular single-link files, mode 0600, opened without following
symlinks. Private atomic replacement and exact readback are required; unsafe existing paths,
failed writes and unconfirmed deletion fail closed without echoing values. This is local POSIX
access control, **not encryption at rest**, a hardware vault or protection from root/the same UID.
No desktop keyring session, cloud secret broker or credential in process arguments is needed.
The existing manifest's `*_keychain_account` fields remain stable opaque account references for
actual macOS state consumers; their store is selected by the host, not by copying Mac secrets.

Shared workflows use the native service and secret-store contracts; OS-specific serialization,
commands and storage stay in their adapters. Unsupported platforms fail before mutation. Local
configuration-application evidence still requires the canonical service PID's exact loopback
listener (using `lsof` on both platforms), readiness, tunnel/client identity and applied config,
with ownership rechecks. Merely enabling a systemd unit is not connector/application evidence.
Hermetic platform tests are not Linux/DGX live acceptance or approval to expose a hostname.

Origin-authenticated `public` remains the route for applications whose web/iPhone clients cannot
supply Cloudflare Access service-token headers or browser login. The application must enforce
its own fail-closed device/session authorization, including HTTPS/WSS and pairing. A public
readiness response does not prove that authorization. Endpoint names, API credentials/grants,
Cloudflare mutations and public source/catalog publication require their separate authority.

## Recoverable mutation contract

One nullable, typed `pending` transition in `state.json` owns an unfinished mutation. It records
the operation identity, normalized secret-free request, phase, intended route projection, candidate
resource ownership, and any external creation whose result is unknown. Persist intent before each
non-repeatable effect and its returned resource identity before proceeding. Repeating the same
request resumes; incompatible mutations fail with `transition_pending`. Reads and plans remain
available. Completed transitions are removed, not accumulated as a history or a separate journal.

Every protected HTTP or SSH ingress rule requires native `cloudflared` Access JWT validation for
its own application AUD and organization. Public routes deliberately have no such requirement.
Authorization-boundary or hostname changes replace the application/AUD; origin-only changes with
unchanged authorization may reuse it. Old connectors retain the old origin and old protection.
Publication withdrawal is saved before pushing routing, so an interrupted removal cannot be
resurrected by setup refresh. Cleanup cannot be called complete without observing the applicable
configuration; unobservable replicas leave the operation pending rather than triggering a global
disconnect. Existing authenticated sessions are not retroactively terminated by a routing or
policy change. JWT validity, edge authorization and established-session termination are separate.

Unknown POST results are never blindly retried. `repair plan` exposes the pending operation and
the exact recovery action. `repair resolve --operation ID --resource-id ID --yes` verifies the
resource against the saved intent before retaining its identity. `--absent` instead requires a
complete scoped resource observation proving no matching creation exists; it is not a forget flag.
Metadata cannot recover a lost service-token secret. For a newly created candidate token,
`repair retire-token --operation ID --resource-id ID --yes` verifies its operation-specific identity,
persists retirement, deletes only its owned token/policy/secret, and confirms absence before allowing
publication to reissue it. An uncertain existing-token rotation instead requires the deliberate
`token rotate NAME --recover --yes`: another rotation of that exact owned token, still fenced if
its response is lost. Only publish and token rotation return credentials.

Teardown persists its intent, stops and confirms local connector removal, refuses active remote
replicas, deletes and confirms deletion of the exact tunnel while Access remains, then retires
owned DNS, Access and tokens. Local credentials/artifacts are removed last. Failures retain custody
and the persistent lock file. Ordinary configuration writes compare the entire managed topology
and supported fields first and refuse foreign drift instead of overwriting it.

## External Facts

- Remotely managed tunnels are the supported API-driven posture for this product; tunnel creation
  sends `config_src: "cloudflare"` and tunnel configuration is managed through Cloudflare.
  - [Create a remotely managed tunnel with the API](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/)
- `cloudflared tunnel run --token-file` is a supported tunnel-run parameter for remotely managed
  tunnels and requires `cloudflared` `2025.4.0` or later in this product.
  - [Tunnel run parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/)
- Tunnel tokens are retrievable by API. Cloudflare recommends rotating compromised tunnel tokens,
  then deleting tunnel connections so old connectors are forced off the edge.
  - [Tunnel tokens and rotation](https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/)
- Listing visible accounts is a separate account-scoped API surface and requires token visibility
  to the account itself.
  - [List accounts](https://developers.cloudflare.com/api/resources/accounts/methods/list/)
- Zone discovery includes the zone owner account, status, and type. A full zone implies
  Cloudflare hosts authoritative DNS, while a partial zone is a CNAME setup and is incompatible
  with this product's managed-DNS contract.
  - [List zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)
- Access self-hosted applications are the canonical protection model for `human`, `machine`, and
  `mixed` hostnames, and the hostname must belong to an active zone in the same Cloudflare account.
  - [Protect a self-hosted application](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)
- Updating the Zero Trust organization is a full-payload `PUT`; Cloudflare warns operators to send
  every field returned by the prior `GET` to avoid overwriting existing configuration.
  - [Update organization settings without dropping fields](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/independent-mfa/)
- Access policies are deny-by-default and support explicit `email`, `email_domain`, and
  `service_token` selectors.
  - [Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- Access application policies include precedence, which defines execution order inside one
  application and therefore belongs to the managed policy contract.
  - [Application policy API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/)
- Service tokens are the machine-auth contract. Their client secret is only displayed when
  generated, and the canonical headers are `CF-Access-Client-Id` and
  `CF-Access-Client-Secret`.
  - [Access service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/)
- Account-level require-protection blocks hostnames without a matching Access application. The
  product represents the setting through `deny_unmatched_requests` and preserves
  `deny_unmatched_requests_exempted_zone_names`.
  - [Require Access protection](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/require-access-protection/)
- Cloudflare account, zone, tunnel, and service-token list APIs are paginated read surfaces. The
  CLI discovery commands consume all pages before returning results.
  - [Accounts](https://developers.cloudflare.com/api/resources/accounts/methods/list/),
    [zones](https://developers.cloudflare.com/api/resources/zones/methods/list/),
    [tunnels](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/methods/list/),
    and [service tokens](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/list/)
- Tunnel ingress rules must include a catch-all rule, and HTTP-origin options such as
  `httpHostHeader`, `originServerName`, and `noTLSVerify` are remotely managed.
  - [Origin parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)
- `httpHostHeader` is the HTTP `Host` header forwarded from `cloudflared` to the local origin.
  Origins that reject the public hostname must set this option explicitly.
  - [HTTP Host header](https://developers.cloudflare.com/tunnel/reference/origin-parameters/)
- A public-hostname SSH route uses an `ssh://` origin and client-side `cloudflared access ssh`.
  Cloudflare carries the transport; native SSH encryption and pinned SSH host keys protect the
  inner connection. This is not direct peer-to-peer networking or removal of Cloudflare as a
  third-party availability dependency. WebSocket transport can disconnect; applications that need
  persistent access must supervise their SSH connection separately.
  - [SSH with client-side cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-cloudflared-authentication/)
  - [Access for non-HTTP applications](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/cloudflared-authentication/)
- In the Access application API, `service_auth_401_redirect: true` requests HTTP 401 when Service
  Auth blocks a request. This is distinct from the organization-wide `strict_service_token_auth`.
  - [Access application API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/)
- Quick Tunnels are dev-only and are not a product path for this repo.
  - [Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)
- Codex scans repository skills from `.agents/skills` under the current directory and up to the
  repository root. User-private skills live under `$HOME/.agents/skills`, and skills with duplicate
  names are not merged.
  - [Where Codex discovers skills](https://developers.openai.com/codex/skills#where-to-save-skills)
- Portable Agent Plugins discover `skills/` at the package root. OpenAI settings belong in
  `plugin.json` under `extensions.com.openai`; Claude Code reads `.claude-plugin/plugin.json` and
  the same `skills/` tree. This skill-only package adds neither hooks nor MCP servers.
  - [Agent plugin structure](https://developers.openai.com/plugins/build/plugins#plugin-structure)
  - [Claude Code plugin layout](https://code.claude.com/docs/en/plugins-reference#standard-layout)
- Codex local environments are app-supported project setup/action files that may be checked into a
  repository, but this public product keeps those local app actions in ignored operator
  overlays instead of tracked public contracts.
  - [Codex local environments](https://developers.openai.com/codex/app/local-environments)

## Source And Distribution Ownership

[Tiziano-AI/cloudflare-publish](https://github.com/Tiziano-AI/cloudflare-publish) is the single public
development source for the CLI and native agent plugin. The `tiziano-ai` marketplace catalogs
reviewed commits from this repository; it is not a second source tree or development engine.
CLI installation and each host's native plugin installation remain separate consumer selections.
Neither source publication nor installation configures Cloudflare or changes existing manager state.

## Product Boundary

`cloudflare-publish` manages:

- one supported host/user profile
- one Cloudflare account
- one active full Cloudflare-managed DNS zone
- one distinct remotely managed tunnel, shared by that host's publications only
- many exact-hostname HTTP, HTTPS, or machine-authenticated native SSH publications
- one local native user-service-managed `cloudflared` connector
- one local state manifest
- one host-native credential store (macOS Keychain namespace or Linux private files)
- one canonical public product skill source at `skills/cloudflare-publish/`, discovered and owned
  by the plugin host rather than copied into a global skill directory by the CLI installer

`cloudflare-publish` does not manage:

- wildcard hostnames
- path-based multiplexing
- private network routes
- general TCP, UDP, RDP, SMB, VPN, or WARP client access
- enabling macOS Remote Login, configuring SSH login users or their private keys, or changing
  `sshd` authorization
- remote reverse-forwarding installation, SSH session supervision, or remote-machine administration
- Cloudflare IdP setup
- remote dashboard token rotation
- multiple accounts or multiple zones per local manager
- unrelated machine-global `cloudflared` state

## Canonical Flow

`bin/cloudflare-publish` → `cloudflare_publish.cli` → workflow modules → adapters (`curl`,
`cloudflared`, native user service, host credential store) → local host state + Cloudflare API

Only one path owns each behavior:

- `setup` owns manager bootstrap, manager refresh, and shared tunnel lifecycle
- `discover` owns typed Cloudflare discovery, including bounded inspection of an explicitly
  selected tunnel; it never returns raw vendor envelopes or adopts discovered resources
- `repair plan` owns read-only repair planning for existing managers
- `repair resolve` owns exact unknown-creation resolution; `repair retire-token` owns exact
  unrecoverable new-candidate token retirement before the original publication resumes
- `publish plan` owns create-or-update previews for one publication
- `publish apply` owns create-or-update of one publication
- `verify` owns manager, routing, origin, Access, and optional public-hostname readiness checks
- `service` owns native local connector status, start, stop, restart, and log visibility
- `tunnel recover plan` owns post-dashboard-rotation and incident repair previews
- `tunnel recover apply` owns post-dashboard-rotation and incident repair for the shared tunnel token
- `rm plan` owns publication retirement previews
- `rm apply` owns publication retirement
- `token rotate` owns Access service-token rotation
- `guard status` owns Zero Trust unmatched-request protection inspection
- `guard plan` owns Zero Trust unmatched-request protection enablement previews
- `guard apply` owns Zero Trust unmatched-request protection enablement
- `teardown` owns full manager retirement

## Local Ownership

On macOS the product owns these local paths:

- `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- `~/Library/Application Support/cloudflare-publish/state.json`
- `~/Library/Application Support/cloudflare-publish/manager.lock`
- `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
- `~/Library/Application Support/cloudflare-publish/backups/<timestamp>/`
- `~/Library/Logs/cloudflare-publish/cloudflared.out.log`
- `~/Library/Logs/cloudflare-publish/cloudflared.err.log`

Linux paths and custody are defined in Host platform contract above; no macOS paths are selected
on Linux. On macOS the product inspects but does not canonically own:

- `~/Library/LaunchAgents/com.cloudflare.cloudflared.plist`
- `~/.cloudflared/config.yml`
- `~/.cloudflared/cert.pem`

Those three legacy surfaces are the generic local takeover boundary. Other leftover files under
`~/.cloudflared/` are not canonical manager state.

Secrets are stored as follows:

- Cloudflare API token: host credential store after setup; optional bootstrap ingress from an operator-owned
  private dotenv file only when `CLOUDFLARE_PUBLISH_DOTENV` points at an absolute path outside the
  repository
- Access service-token secret: host credential store
- tunnel runtime token: local `tunnel-token.txt` with strict permissions because the unattended
  connector must read it

The private dotenv is an explicit operator convenience, not a public setup dependency. The product
does not infer a workstation secret root, does not read master secret pools, and rejects symlinked or
non-`0600` dotenv files so one local workflow cannot accidentally expose unrelated credentials.

The Keychain adapter writes one bounded command to `security -q -i` over stdin, with the password
encoded as UTF-8 hex for `add-generic-password -X`, never as a process argument. Credentials must be
nonempty printable ASCII, the token format this adapter serves. It rejects unsupported inputs
before writing, suppresses write diagnostics that could echo credential material, and requires
exact Keychain readback before reporting success. Supplying a bare `-w`
and piping a password to its prompt is not a supported noninteractive write path. The HTTP adapter
writes curl request headers and JSON bodies to mode-`0600` temporary files and passes those file
paths to curl, so bearer tokens and Access
service-token secrets do not appear in curl argv or command-failure text.

## CLI Contract

The canonical operator surface is the PATH-global `cloudflare-publish` console script. `--version`
reports installed Python distribution metadata without reading credentials or manager state. The
repo-local `bin/cloudflare-publish` wrapper remains the development wrapper for a checked-out
worktree.

The canonical command surface is:

- `cloudflare-publish [--json] [--api-token ...] doctor`
- `cloudflare-publish --version`
- `cloudflare-publish [--json] [--api-token ...] discover accounts`
- `cloudflare-publish [--json] [--api-token ...] discover zones --account-id ... [--name ...]`
- `cloudflare-publish [--json] [--api-token ...] discover zone ZONE --account-id ...`
- `cloudflare-publish [--json] [--api-token ...] discover tunnels --account-id ...`
- `cloudflare-publish [--json] [--api-token ...] discover tunnel ID --account-id ACCOUNT --zone-id ZONE`
- `cloudflare-publish [--json] [--api-token ...] discover organization --account-id ...`
- `cloudflare-publish [--json] setup [--install-deps] [--takeover --yes] [--refresh-only] [--api-token ...] [--account-id ...] [--zone ...] [--zone-id ...] [--tunnel-name ...]`
- `cloudflare-publish [--json] publish plan NAME --hostname ... --to http(s)://... --audience {human,machine,mixed,public} [--allow-email ...] [--allow-domain ...] [--verify-path ...] [--expect-status ...] [--http-host-header ...] [--origin-server-name ...] [--no-tls-verify]`
- `cloudflare-publish [--json] publish apply NAME --hostname ... --to http(s)://... --audience {human,machine,mixed,public} [--allow-email ...] [--allow-domain ...] [--verify-path ...] [--expect-status ...] [--http-host-header ...] [--origin-server-name ...] [--no-tls-verify] --yes`
- `cloudflare-publish [--json] publish plan NAME --hostname ... --to ssh://HOST:PORT --audience machine --ssh-host-key 'ssh-ed25519 BASE64'`
- `cloudflare-publish [--json] publish apply NAME --hostname ... --to ssh://HOST:PORT --audience machine --ssh-host-key 'ssh-ed25519 BASE64' --yes`
- `cloudflare-publish [--json] ls`
- `cloudflare-publish [--json] inspect NAME`
- `cloudflare-publish [--json] verify [NAME] [--live]`
- `cloudflare-publish [--json] repair plan`
- `cloudflare-publish [--json] repair resolve --operation ID (--resource-id ID | --absent) --yes`
- `cloudflare-publish [--json] repair retire-token --operation ID --resource-id ID --yes`
- `cloudflare-publish [--json] service status`
- `cloudflare-publish service start`
- `cloudflare-publish service stop`
- `cloudflare-publish service restart`
- `cloudflare-publish service logs [--lines N]`
- `cloudflare-publish [--json] tunnel recover plan`
- `cloudflare-publish [--json] tunnel recover apply --yes`
- `cloudflare-publish [--json] rm plan NAME`
- `cloudflare-publish [--json] rm apply NAME --yes`
- `cloudflare-publish [--json] token rotate NAME --yes`
- `cloudflare-publish [--json] token rotate NAME --recover --yes`
- `cloudflare-publish [--json] guard status`
- `cloudflare-publish [--json] guard plan`
- `cloudflare-publish [--json] guard apply --yes`
- `cloudflare-publish [--json] teardown --yes`

API-token resolution precedence:

- explicit `--api-token` for local emergency or tests
- process environment `CLOUDFLARE_API_TOKEN`
- private dotenv pointed at by `CLOUDFLARE_PUBLISH_DOTENV`, key `CLOUDFLARE_API_TOKEN`
- host credential store, when a local manager manifest exists

Initial interactive setup also prompts for the API token when no token flag, process environment
value, or configured private-dotenv value is present and stdin is a TTY. The host store remains the
persistent product store after setup. The private dotenv is a local bootstrap and noninteractive
ingress surface, not a replacement for that store. Operator-facing docs prefer the interactive prompt,
an explicit private dotenv, or a short-lived local `CLOUDFLARE_API_TOKEN` shell environment over
token-on-argv examples. The explicit `--api-token` flag remains a supported CLI contract for local
terminal use, tests, and emergency noninteractive operation; agents do not ask users to paste token
values into chat.

Setup also reads these environment fallbacks:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_ID`
- `CLOUDFLARE_ZONE`
- `CLOUDFLARE_TUNNEL_NAME`

For those setup fallbacks, flags take precedence over the process environment, and the process
environment takes precedence over the configured private dotenv. The repo does not use tracked
`.env` files or example env files. Local workstation-specific recipes belong in ignored operator
overlays, not in tracked public docs or gates.

`--json` writes one machine-readable envelope to stdout. Human diagnostics, when present, write to
stderr. Successful JSON envelopes use:

```json
{"ok": true, "command": "inspect", "output_class": "public_diagnostic", "data": {}, "warnings": []}
```

Error JSON envelopes use:

```json
{"ok": false, "command": "verify", "output_class": "evidence_error", "error": {"code": "verify_failed", "message": "...", "hints": []}, "data": {}, "warnings": []}
```

JSON errors redact credentials. `public_diagnostic` payloads never include credential material.
`evidence_error` payloads are safe diagnostic data attached to a nonzero exit. `credential_handoff`
payloads are the only JSON success responses that include service-token client secrets, and they
are emitted only by explicit handoff commands: `publish apply` for `machine` and `mixed`
publications, and `token rotate`.

`inspect NAME` renders the local publication contract without secrets. HTTP publications include
the public verification URL, origin URL, verification profile, Access allow rules, and origin
request options. SSH publications include the origin, pinned public host key, and native-SSH
verification scope, not an HTTP verification URL, HTTP status profile, or TLS-origin claims. Both
kinds include remote resource IDs and service-token client ID when present. The service-token
client secret is only printed by `publish` and `token rotate`. Plain HTTP origins render origin TLS
verification as not applicable.

`doctor` is a diagnostic command. It exits zero when diagnostics complete, even when the reported
state is not ready. `verify` remains the readiness command that exits nonzero on failed checks.
When `verify --json` executes checks and fails, the error envelope preserves `data.checks` and
`data.failures` so automation can see the failing evidence. Both successful and failed verification
results also expose `data.groups`: populated groups in order, with `group`, `checks`, and `failures` for
`manager`, `routing`, `origin`, `access`, and `public_probe`. Each check carries its typed `group`
and `publication_name` and `hostname`; these identity fields are null for manager-scoped checks.
Human output uses the same groups with readable headings. `checks` is a flat check array and
`failures` is its aggregate failing-check count; each group likewise contains a check array and
failing-check count.

`discover tunnel ID --account-id ACCOUNT --zone-id ZONE` inspects the exact remote tunnel and
the supplied zone, requiring that the zone belongs to the supplied account. It does not require a
local manager, rewrite manager ownership, or authorize later writes. Its public diagnostic returns
the supplied `account_id`; an allowlisted zone summary; tunnel identity, status, `deleted_at`, and
configuration source; sanitized ingress summaries; matching zone DNS summaries; matching Access
application summaries (`include` rule kinds, not arbitrary selector payloads); and `unsupported_topology`
code/scope findings, with a coverage statement explaining the bounds of the inspection.
Lists consume all relevant pages. Never expose tunnel tokens, credential-bearing URLs, Access
secrets, arbitrary origin-request options, or raw configuration/provider envelopes. Flag wildcard
and path rules, services other than HTTP(S) and SSH, private-network routing, out-of-zone routes,
global origin options, and unknown configuration fields rather than implying that this manager can adopt them.
An Access summary reports Boolean `has_destination_overrides` on an application and
`has_additional_constraints` on a policy. Present destination overrides and nonempty policy
`require`/`exclude` rules produce `access_destination_overrides` and
`unreported_policy_constraints` findings respectively; no override or constraint values are
exposed or interpreted. A hostname-bearing `http_status` service produces
`non_http_publication_service`; the terminal hostless `http_status:404` remains supported.
Discovery never calls a tunnel-token endpoint. It is not a complete audit of consumers, provider
webhook targets, private-network routes elsewhere in the account, or other configuration outside
the reported surfaces. Coverage explicitly excludes interpretation of destination overrides or
policy `require`/`exclude` semantics.

Cloudflare can retain an exact-tunnel GET after deletion. A nonempty `deleted_at` identifies that
deletion tombstone: discovery emits `deleted_tunnel`, returns no ingress, and does not query its
obsolete configuration or classify it as a locally managed tunnel with missing ingress. Selected-zone
DNS records still referencing its CNAME, and Access applications matching those residual names,
remain visible. Deletion metadata alone does not prove DNS or connector retirement. A down tunnel
without deletion metadata remains distinct from a deleted tunnel; discovery never repairs either.

There is no raw Cloudflare API command. All public reads use typed `discover`, `inspect`, `ls`,
`doctor`, `repair plan`, `verify`, `service status`, or `guard status` contracts.

## Local Operator Overlay Contract

The public repository is self-contained and does not require ignored local agent files, local app
action files, user-private skill mirrors, or workstation secret tooling for its gate. Ignored
operator overlays may record local app actions, personal recovery notes, and private secret
materialization recipes, but tracked public docs, tests, and skill packages stay portable.

Public surfaces route through terminal commands and the canonical gate:

- `uv run devtools/gate.py` for repository validation
- `cloudflare-publish service status` for read-only local connector state
- `cloudflare-publish repair plan` for read-only repair planning
- `cloudflare-publish verify --live` for live publication checks when a real manager is configured

Initial `setup`, `setup --refresh-only`, `publish apply`, `rm apply`, `token rotate`, `tunnel
recover apply`, `guard apply`, and `teardown --yes` remain deliberate terminal commands because
they create or reconcile remote state, are parameterized, perform credential handoff, alter account
policy, or are explicit-impact operations.

The `service` command group owns only local connector process lifecycle and log visibility. It does
not reconcile Cloudflare remote resources, rewrite tunnel configuration, rotate tokens, or mutate
publication state. It fails closed unless the existing native service definition uses the canonical
identity, manager token file, and a `cloudflared` binary with `--token-file` support. On Linux it also
checks the loaded fragment and rejects drop-ins or effective executable drift; it does not start
foreign definitions. Use `setup` for manager refresh and `verify` for remote contract validation.

Launch-agent reinstall paths call `launchctl bootout`, wait boundedly for launchd to unregister the
old job, then call `launchctl bootstrap`. This keeps refresh and recovery from racing launchd cleanup
and surfacing misleading bootstrap errors while the previous connector is still being removed.
Linux reinstall instead validates ownership, disables/stops the old owned unit, retains its exact
definition while reloading and confirming native absence, then atomically writes the canonical
replacement, reloads the user manager, and enables/starts it. A stopped disabled unit can
remain loaded by systemd without being an active or automatically restarting connector.

## Cloudflare Token Contract

The product expects one API token that can:

- list accounts visible to the token
- list zones visible to the token
- fetch the Zero Trust organization
- create, inspect, configure, token-fetch, disconnect connectors for, and delete the shared tunnel
- create, update, and delete DNS records
- create, update, list, and delete Access apps and policies
- create, rotate, and delete service tokens

The documented endpoint permission set is:

- `Account Settings: Read`
- `Cloudflare Tunnel: Edit`
- `Access: Service Tokens: Edit`
- `Access: Organizations, Identity Providers, and Groups: Edit`
- `Access: Apps and Policies: Edit`
- `Zone: Zone: Read`
- `DNS: Edit`

The token must also be resource-scoped to the target account and target zone.
Organization operations use the dedicated organization permission. Broad `Zero Trust Edit` is
not an additional documented requirement; a least-privilege live account cycle remains a separate
qualification from endpoint permission documentation.

Cloudflare list adapters consume every paginated result page for accounts, zones, tunnels, DNS
records, Access applications, and Access policies before making collision or reconciliation
decisions.

## Typed State

The canonical local state file is `state.json`. It persists manager ownership plus per-publication
remote identities.

Every manager-mutating command holds one nonblocking OS advisory writer lock across its complete
workflow, before reading state or performing remote or local effects: `setup` (including refresh),
`publish apply`, `rm apply`, `token rotate`, `guard apply`, `tunnel recover apply`, `teardown`, and
`service start`, `stop`, `restart`, and both confirmed `repair` writes. Contention returns typed
`manager_busy` without beginning
the workflow. The persistent lock file survives teardown and is not itself evidence of an active
writer; never remove it to bypass contention or unlink it while a writer holds its inode. Read-only
commands and plan forms remain unlocked.

Manifest writes stage a mode-`0600` file in the same directory and atomically replace `state.json`
only after the staged write succeeds. A failed stage leaves the previous manifest intact. The
writer lock serializes this product's local mutators, not dashboard or other remote writers; neither
the lock nor atomic local replacement provides remote compare-and-swap, multi-resource transactions,
or rollback of effects already completed in Cloudflare.

```json
{
  "schema_version": 1,
  "manager": {
    "account_id": "account-123",
    "account_name": "Example Account",
    "zone_id": "zone-123",
    "zone_name": "example.com",
    "auth_domain": "example.cloudflareaccess.com",
    "tunnel_name": "cloudflare-publish",
    "tunnel_id": "tunnel-123",
    "api_token_keychain_account": "api-token"
  },
  "publications": {
    "grafana": {
      "spec": {
        "kind": "http_public",
        "name": "grafana",
        "hostname": "grafana.example.com",
        "origin_url": "https://127.0.0.1:3000",
        "audience": "mixed",
        "allowed_emails": ["ops@example.com"],
        "allowed_email_domains": ["example.com"],
        "verify_path": "/login",
        "expect_status": "200-399",
        "ssh_host_key": null,
        "origin_options": {
          "http_host_header": "grafana.internal",
          "origin_server_name": null,
          "no_tls_verify": false
        }
      },
      "state": {
        "dns_record_id": "dns-123",
        "access_application_id": "app-123",
        "access_aud": "aud-123",
        "policy_ids": ["policy-human", "policy-machine"],
        "service_token_id": "token-123",
        "service_token_client_id": "client-id",
        "service_token_keychain_account": "service-token:grafana:operation-uuid",
        "updated_at": "2026-04-12T12:00:00Z"
      }
    }
  },
  "backups": [],
  "updated_at": "2026-04-12T12:00:00Z",
  "pending": null
}
```

Existing HTTP manifests without `ssh_host_key` remain readable as an unset value. New SSH specs
use `kind: "ssh_public"`, `audience: "machine"`, `origin_url: "ssh://127.0.0.1:22"`, a normalized
`ssh_host_key`, null `verify_path` and `expect_status`, empty human allow rules, and empty HTTP
origin options. The origin scheme selects the kind; there is no independent kind flag or parallel
SSH publication store.

Existing manifests without `pending` remain readable as completed state. Pending state stores only
the current unfinished operation, not history. New service tokens use operation-specific credential
accounts so stale credentials from a retired token cannot masquerade as a recovered new secret.
Reused existing tokens retain their real stored reference. Initial setup keeps the configured
logical tunnel name, while its remote resource name carries `:<operation-id>` for exact creation
reconciliation. Completed older managers keep their existing resource identities.

## Publication Contract

Each publication owns:

- exactly one hostname
- zero or one Access application, according to audience
- zero or more Access policies, according to audience
- exactly one proxied DNS record
- exactly one ingress rule in the shared tunnel config
- zero or one service token
- one verification profile

Validation rules:

- `kind` is `http_public` for HTTP(S) origins or `ssh_public` for SSH origins
- `hostname` must be an exact hostname inside the configured zone
- `origin_url` must use `http://`, `https://`, or `ssh://` with no credentials, path, query, or fragment
- SSH requires `--audience machine` and one `--ssh-host-key` containing a valid `ssh-ed25519`
  public host key; an optional comment is accepted but only the type and base64 key are stored
- SSH rejects human allow rules and every HTTP verification or origin option, including explicitly
  supplied `--verify-path`, `--expect-status`, `--http-host-header`, `--origin-server-name`, and
  `--no-tls-verify`; HTTP(S) rejects `--ssh-host-key`
- `human` and `mixed` require at least one email or email-domain allow rule
- `public` rejects email and email-domain allow rules
- HTTP `verify_path` must be a path-only value beginning with `/`; query strings, fragments,
  whitespace, and control characters are rejected
- HTTP `expect_status` must be a closed inclusive range such as `200-399`; both HTTP verification
  fields are null for SSH
- manager bootstrap requires the selected zone to be `active` and `full`

Audience semantics:

SSH supports only `machine`; the remaining modes below apply to HTTP(S).

- `human`: allow policies built from `email` and `email_domain`
- `machine`: service-auth policy plus one service token
- `mixed`: both
- `public`: no Access application, policy, or service token; the origin must own fail-closed request
  authentication and its verification profile must observe the declared origin response

For protected audiences the product creates the Access application before exposing the route. For
`public`, publish preflight rejects unmanaged Access ownership and account require-protection unless
the configured zone is already exempted, then reconciles the hostname with no Access resources.

SSH reuses the existing self-hosted Access application, specific service-token `non_identity`
policy, proxied DNS record, and shared tunnel connector. Access applications retain
`service_auth_401_redirect: true`, which requests HTTP 401 when Service Auth blocks a request;
despite its name, it does not enable a login redirect. Before native public SSH probing, require
that flag, exact machine-only policy parity, and anonymous HTTP 401/403 denial. Neither that HTTP
denial nor a generic HTTP response proves native SSH readiness. The account-wide
`strict_service_token_auth` setting is separate and is not changed or required here. SSH login and
forwarding still require independently authorized OpenSSH credentials and server policy; an Access
service token is not an SSH login key.

The SSH host key must be acquired through an already trusted channel, such as the server's local
`/etc/ssh/ssh_host_ed25519_key.pub`. Never learn or replace the pin from an untrusted public
connection merely to make a probe pass. A legitimate server host-key change requires explicit
publication reconciliation with the independently verified replacement key.

## Organization Contract

The Zero Trust organization surface currently stores only the fields this product needs:

- `auth_domain`
- `deny_unmatched_requests`
- `deny_unmatched_requests_exempted_zone_names`

`guard apply` reads the full current organization payload, flips only
`deny_unmatched_requests`, preserves existing exempted zone names, and writes the full payload
back. The product does not become the canonical owner of broader organization custom pages, MFA
settings, UI lock state, or branding fields. `guard plan` and `guard apply` deny enablement when it
would block a managed `public` publication; `guard status` remains a read-only diagnostic and names
the affected publications.

## Remote Configuration Ownership

The shared tunnel remote configuration is derived only from local manager state. The repo writes
the full canonical ingress list:

- during setup bootstrap
- during setup refresh
- during every publication mutation

The canonical config is:

- one ingress rule per effective managed publication (pending withdrawal removes its target;
  pending candidate routing substitutes its owned candidate)
- one terminal `http_status:404` catch-all rule
- per-rule native Access enforcement for protected HTTP and SSH routes, with the exact team and AUD

Typed comparison preserves rule order, topology and every supported Host/SNI/TLS/Access option.
Unknown fields, private routing and nonempty global options are rejected rather than overwritten.
Only documented benign defaults normalize. Explicit setup refresh can upgrade the exact owned
legacy configuration with only derived per-rule guards missing; publication writes cannot.

### Configuration application barrier

Before accepting connector application, read the current remote configuration and require both
complete semantic equality with the intended configuration and its exact target version. Then
require the target version for every observed active connector on the selected tunnel. A version
reported by the connections API is authoritative for that connector: a conflicting version cannot
be overridden by a local observation.

When the API omits a connector's applied version, native local evidence may fill only that missing
value for the exact canonical native-service-managed connector. Discover a loopback listener owned by
that service PID, without scanning ports or reading process arguments, environment, tokens or
logs. Read the native `/ready`, `/diag/tunnel` and `/config` endpoints directly, without a proxy.
The same listener must identify the exact active API client and selected tunnel and report the
exact applied target version. Recheck the service PID, listener ownership and native identity
across the observation; a process replacement or identity change invalidates it. The local
evidence does not stand in for remote configuration equality or supply evidence for another
replica.

Missing, malformed, stale or conflicting evidence retains pending custody. Every foreign or
otherwise unobservable active replica still blocks completion; ordinary mutations do not
disconnect it to manufacture success. This application observation is a snapshot, not a distributed
lock, future-replica guarantee, token-revocation proof or session-drainage proof.

## Setup Sequence

Initial setup order:

1. ensure local tool availability, including `cloudflared` `2025.4.0` or later, and Linux user-manager/linger prerequisites before remote effects
2. ensure manager directories exist
3. inspect canonical manager state plus conflicting legacy ownership
4. require explicit `--takeover` for backup-safe macOS legacy ownership; refuse Linux takeover/conflicts
5. resolve API token, account, and zone
6. fail closed if the selected zone does not belong to the selected account
7. fail closed unless the selected zone is `active` and `full`
8. fetch the Zero Trust organization
9. fail closed if a same-name remote tunnel already exists
10. persist selected identity and initial pending setup, then store/read back the API credential
11. if takeover is active, persist backup ownership before removing the exact backed-up conflicts
12. persist the operation-specific tunnel creation marker before POST; persist its returned ID
13. initialize the canonical shared remote configuration and retain its returned version
14. fetch the tunnel runtime token, write its private file, install/start the canonical native user service
15. require an active connector and exact-version application by all observed active replicas
16. clear the completed pending setup; any interruption resumes from surviving ownership

Refresh setup order:

1. require an existing manifest
2. refuse account, zone, or tunnel-name changes without teardown
3. load the API token from CLI or the host store
4. fetch the existing tunnel and organization
5. reject any unrelated unfinished operation and unexpected full-configuration drift
6. persist refresh custody and refreshed manager metadata; optionally store the supplied API token
7. upgrade only the exact owned legacy configuration or reapply the exact guarded configuration
8. fetch/rewrite the tunnel token, reinstall/start the canonical native user service
9. require active exact-version connector application, then clear refresh custody

## Verify, Recover, Guard, And Teardown Sequences

Verify order:

1. require an existing manager manifest
2. report whether the local `cloudflared` version supports `--token-file`
3. check local state and native user-service surfaces
4. check remote tunnel health, organization, tunnel config, and publication resources
5. optionally run public-endpoint checks

Tunnel recover order:

1. require an existing manager manifest
2. require local tool availability, including supported `cloudflared`
3. fetch the current tunnel and current tunnel token
4. rewrite the local tunnel token file
5. reinstall and start the canonical native user service
6. delete all remote tunnel connections
7. report that every connector on the shared tunnel is forced off the edge

Guard apply order:

1. fetch the current Zero Trust organization
2. no-op if unmatched-request protection is already enabled
3. update `deny_unmatched_requests` by rewriting the full fetched payload while preserving
   exempted zones and every unrelated field
4. persist the refreshed manager metadata

Teardown order:

1. persist teardown custody; stop the canonical native service and confirm it cannot auto-restart (unloaded on macOS; inactive/disabled on Linux)
2. refuse active or unobservable remote replicas without globally disconnecting them
3. delete and positively observe deletion of the exact tunnel while all Access protection remains
4. retire owned DNS first, then Access and service-token resources, retaining refs across failure
5. persist remote cleanup completion, then remove the API credential, exact owned service definition and local artifacts
6. remove state.json last; preserve takeover backups and the persistent writer-lock file; Linux removes only exact owned token/log artifacts and empty directories, leaving unknown state entries intact

## Verification Contract

`verify` without `--live` checks:

- `cloudflared` version supports `--token-file`
- `state.json` presence
- tunnel token file presence
- canonical native user-service definition presence
- running native user-service state
- remote tunnel health and reachability
- Zero Trust organization reachability
- remote tunnel config parity
- per-publication HTTP origin reachability or SSH signed key-exchange identity against the pinned
  public host key
- per-publication DNS record id, target, and proxy parity
- protected-publication Access app hostname and policy parity, including precedence
- protected-publication policy parity fails on present additional `require`/`exclude` constraints;
  an include-only signature cannot establish parity while those constraints exist
- public-publication absence of Access resources and auth metadata

`verify --live` additionally checks:

- protected publications deny anonymous HTTP requests by either an explicit deny or an Access login
  redirect
- HTTP `machine` and `mixed` publications accept requests with the current service token
- SSH publications complete native OpenSSH signed key exchange through client-side `cloudflared`
  using the current Access service token and the pinned host key; an HTTP response or SSH banner
  alone is insufficient
- `public` publications reach the origin without Access headers and return the configured status
  class
- failed machine-authenticated public probes call out Host-header-sensitive origin failures when
  the publication has no `http_host_header`

`verify --live` does not perform an interactive human login flow and does not claim stronger human
Access-gate coverage than the anonymous-denial check.

SSH origin and public probes use a private temporary `known_hosts` file, strict host-key checking,
and OpenSSH's signed key exchange. They do not load a user's SSH configuration, agent, private
keys, or login credentials and do not establish an authenticated shell or forwarding session.
Successful SSH checks prove encrypted transport to the pinned SSH server, not SSH user login,
reverse forwarding, session persistence, or a remote workload. The existing `origin`, `access`, and
`public_probe` groups express these distinctions; SSH adds no parallel readiness framework.
The client-side `cloudflared` process receives Access credentials through environment variables,
not arguments, runs with `--loglevel error` to prevent debug WebSocket headers from exposing
credentials, uses an isolated temporary home for caches, and has browser launching disabled.

The groups distinguish manager/connector readiness, routing parity, origin reachability, Access
configuration, and public probes. An on-demand application with no reachable origin still fails
readiness; the product does not start it or reinterpret absence as success. A configured 404 or 405
probe establishes the declared HTTP response only, not authenticated application use or a complete
provider callback, native-client, upload, or inference workflow.

`verify` and ordinary `repair plan` resolve credentials, read Cloudflare, and probe local origins
even without `--live`. With pending custody, `repair plan` instead reports that operation and bounded
effect-resolution candidates; it does not run normal readiness against unfinished setup or routing.
HTTP requests use private temporary curl files; SSH probes also create private temporary
host-key material and processes. These commands change no managed local or Cloudflare state, but
are neither offline nor strict no-file-write operations.

Verification is doctor-style: probe failures are rendered as failing checks instead of aborting the
entire run on the first exception.

## Failure And Recovery Rules

Local fail-closed rules:

- if conflicting local `cloudflared` user-service ownership or `.cloudflared` state exists,
  setup stops; only backup-safe macOS legacy takeover is supported with explicit `--takeover`
- manager bootstrap fails if Cloudflare token, account, zone, or tunnel identity are ambiguous in
  non-interactive mode
- setup, tunnel recover, and native-service repair paths fail if `cloudflared` is older than
  `2025.4.0`
- setup refresh fails if the request tries to change account, zone, or tunnel name without teardown

Remote fail-closed rules:

- if state is absent and a same-name tunnel already exists remotely, setup does not silently adopt it
- if the selected zone is not `active` and `full`, setup does not continue because the product owns
  Cloudflare DNS records directly
- if a publication hostname is already owned by another managed publication, publish fails
- if a remote DNS record already exists for a hostname that local state does not own, publish fails
- if a remote Access application already exists for a hostname that the selected publication does
  not own, publish fails
- if account require-protection would block a new `public` publication, publish fails before remote
  mutation

Recovery posture:

- setup refresh repairs tunnel-token and owned native-service drift, and upgrades the exact owned legacy
  config. It rejects unrelated topology/options and unfinished publication/removal/teardown custody
- `repair plan` is the read-only operator entrypoint for deciding whether setup refresh, publish,
  guard, or tunnel recovery is the next deliberate terminal action
- missing secrets on existing tokens require explicit `token rotate NAME --yes`, never an implicit
  rotation during publication. A new candidate's lost secret uses exact retirement/reissue; an
  uncertain rotation uses confirmed `--recover`, not metadata adoption or a blind repeat
- a new publication change preflights reused token credentials before creating pending custody.
  If a reused secret disappears during an unfinished change, routing can finish without rotating
  it. Failed final handoff reports `credential_handoff_unavailable` with `publication_applied: true`
  after pending clears; explicit token rotation is then available
- `publish apply` and `token rotate` are the canonical machine-secret handoff surfaces because they
  print the current client ID and client secret after reconciliation
- tunnel recover is the explicit post-dashboard-rotation and incident path when the product must
  force every connector off the shared tunnel; `tunnel recover plan` precedes `tunnel recover apply
  --yes`
- setup persists manager identity and creation intent before the first remote creation
- publish preflights unmanaged DNS ownership before any Access or service-token mutation
- publish preflights unmanaged Access ownership and public-audience guard compatibility before any
  Access, service-token, DNS, or tunnel mutation
- publish persists candidate ownership and intended routing before changing the shared config;
  canonical publication ownership changes only after the fixed transition completes
- `rm` persists withdrawal, applies and observes reduced routing, then deletes DNS before Access;
  setup refresh cannot recreate an interrupted withdrawal
- takeover backups are preserved across normal teardown cleanup

## Skill Package Contract

The canonical source for the `cloudflare-publish` skill package lives in:

- `skills/cloudflare-publish/`

The package is a portable public product skill. It contains portable product workflows only:
Cloudflare publication commands, recovery boundaries, no-secret inspection, and package review
scenarios. Private workstation configuration belongs to machine configuration and product
diagnostics, not in
this public skill package or a second local-ops skill.

`plugin.json` is the portable package identity and OpenAI listing. `.claude-plugin/plugin.json`
contains matching native metadata. Their name, version, and license agree with `pyproject.toml`.
The host discovers the single `skills/` tree; there is no second generated copy or product-owned
global skill installer. The package needs an executor on the publishing macOS or Linux host;
it does not promise browser-only execution or execute commands on another host by itself.

The CLI and plugin install independently. `make install-local` installs only the Python CLI with
`uv tool install --reinstall .`; it does not write a skill directory, run setup, install cloudflared,
start a native service, or access an account. Plugin installation supplies guidance only. The operator must
explicitly install the CLI and cloudflared and configure their own account, zone, login method, and
token before the first publication. No install hook bootstraps services or credentials.

`devtools/validate_package.py` checks metadata coherence, skill file closure, local Markdown
references, script syntax/modes, icon signatures, and private workstation dependencies. It does not
install a package, qualify either host, or contact Cloudflare. The gate also exercises CLI behavior
with the documented hermetic fake environment.

Disabling or removing the plugin stops host discovery only. `uv tool uninstall cloudflare-publish`
removes the CLI, not the connector, DNS, Access, tunnel, stored credentials, state, logs, or takeover
backups. For full retirement, first inspect existing publications while the CLI is available, then
explicitly authorize `teardown --yes`; only afterwards remove the CLI. Teardown preserves backups
and the persistent manager lock. Keep those with their recovery purpose rather than treating them
as plugin cache. A code upgrade or uninstall never silently retires infrastructure.
