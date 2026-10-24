---
name: cloudflare-publish
description: "Publish, verify, recover, or remove local HTTP(S) or machine-only SSH on macOS or Linux through the exact-hostname Cloudflare Tunnel manager. SSH requires a pinned Ed25519 host key. Also use to explain this product. Not for Workers, Pages, generic Cloudflare architecture, wildcard/path routing, VPN/private networks, DNS-only administration, or services on a different host."
---
# Cloudflare Publish

This manager maps a running local HTTP(S) or machine-authenticated SSH service to one exact hostname
in the operator's own Cloudflare account and active full DNS zone. One distinct remotely managed tunnel
per host/user profile carries that host's publications. Protected audiences use Cloudflare Access; `public` omits Access only
when the origin already enforces fail-closed request authentication.

This plugin supplies guidance, not an account or a running service. It installs no CLI, credentials,
connector, DNS records, or Access policies automatically. Discover the separately installed
`cloudflare-publish` command before operating it; see Source And Discovery for explicit setup.
Disabling or removing the plugin leaves the CLI, connector, publications, and credentials in place.

For interrupted writes, start with `repair plan`. Never erase pending state or blindly repeat a
resource creation whose result is unknown; follow [Interrupted writes](#interrupted-writes).

macOS uses launchd/Keychain. Linux uses systemd 240+ user services and private POSIX credential
files, not a desktop keyring or system daemon. A working user bus and operator-arranged `Linger=yes`
are required before setup; never auto-enable lingering, invoke sudo, install Linux dependencies,
or take over legacy/system services. Each independent host creates its own tunnel: do not copy Mac
state/tokens or turn independent backends into replicas. Read the Linux bootstrap recipe before
headless setup. New public hostnames, token grants, host administration, and source publication are
separate decisions; plugin installation grants none of them.

## Use when

- publishing, updating, verifying, or removing a local web app, API, authenticated callback,
  native-client endpoint, or SSH service through this manager
- inspecting or recovering manager state, rotating publication tokens, or repairing the connector
- explaining the product or changing its source, skill, or terminal-first validation

Do not use it for generic Cloudflare architecture, Workers or Pages deployment, wildcard/path
routing, private-network or VPN access, other protocols, or services that do not run on this publishing host.

## Inputs

- the product question, source change, publication, or recovery goal
- for publication work: the exact hostname, local origin URL, and audience requirement
- for SSH: an already running SSH origin, `machine` audience, and an independently trusted
  `ssh-ed25519` public host key; never accept a public network key scan as the source of trust
- for installed operation: CLI discovery, relevant manager state, and operator constraints

## Outputs

- a product-grounded explanation, source change, or operator action plan matching the request
- the exact local product commands and checks to run
- explicit blockers for the work that depends on a missing checkout, installed CLI, or live state
- a recovery path when the live system is blocked

## Choose the working surface

Product explanation uses the Mental Model and Product Contract; source changes need the resolved
source checkout. Neither depends on an installed or authenticated manager. Missing CLI installation
or credentials do not block that work and are not a reason to install, run `doctor`, or inspect
the live manager.

Installed operation depends on current workstation state. For publication or manager diagnosis,
resolve the PATH-global command with `command -v cloudflare-publish`; use
`cloudflare-publish --json doctor` when install, auth, and Cloudflare readiness matter. `doctor`
resolves credentials and contacts the account API when a token is available. It is not an offline
source probe; inspect `data.ready` and `data.checks`, not just exit zero or `ok: true`.

Local artifact inspection, remote parity, and public-hostname behavior answer different questions.
Use the inspection script for local manager facts; `verify` and `repair plan` already use credentials,
query Cloudflare, and probe origins. `--live` adds public-hostname audience checks. Choose those
reads only when the requested operation or claim depends on them.

To inspect an explicitly selected remote tunnel without adopting it, use
`cloudflare-publish --json discover tunnel ID --account-id ACCOUNT --zone-id ZONE`. Its sanitized
routing, DNS, Access, and unsupported-topology summaries are evidence, not permission to publish,
transfer ownership, or remove discovered resources.

Verification groups manager, routing, origin, Access, and public-probe evidence, with publication
identity where applicable. An unavailable on-demand origin still fails readiness. A matching
404/405 probe does not prove authenticated application use; check the real client or provider
workflow only when that outcome is in scope.

SSH is `--to ssh://HOST:PORT --audience machine --ssh-host-key 'ssh-ed25519 BASE64'`. It rejects
human rules and HTTP verify/origin options. Origin and live probes prove signed native SSH key
exchange against the pin, not SSH user login, forwarding, or persistence; they need no private
keys or login credentials. Cloudflare remains the transport/availability dependency, while pinned
native SSH protects inner contents. It is not a VPN or a third-party-free route.
Public SSH verification first requires exact machine policy parity, the application's
`service_auth_401_redirect: true` (HTTP 401 on Service Auth denial), and anonymous HTTP 401/403.
A login redirect fails SSH preflight instead of opening a browser. Keep client cloudflared at
`--loglevel error` to prevent debug WebSocket logging from exposing Access headers.

## Installed operation

1. Distinguish publication, update, verification, token rotation, and tunnel recovery before
   choosing a command; load the relevant operator recipe and state/recovery guidance.
   For native clients, establish whether they support Access login or service-token headers before
   choosing the audience. Unsupported Access is not permission to publish an unprotected origin:
   `public` needs authorized Internet exposure and proven fail-closed origin authentication. Use
   the native-client recipe for endpoint selection and client-level verification.
   For SSH, load the native SSH recipe: pin the host key from a trusted source, keep the Access
   token separate from SSH login credentials, and preserve strict host-key checking. Do not enable
   Remote Login or install remote SSH supervisors as an implicit part of publication.
2. When auth is missing or noninteractive setup needs credentials, direct the operator to the local
   terminal setup prompt or a short-lived `CLOUDFLARE_API_TOKEN` process environment; never ask for
   token values in chat.
3. Use `service` commands only for local native user-connector lifecycle and logs (launchd on Mac,
   systemd `--user` on Linux). Linux stop disables automatic startup and confirms inactivity.
4. Use `discover` commands before setup when account, zone, organization, or tunnel IDs are
   unknown.
5. Use `plan` before publication removal, guard enablement, tunnel recovery, or uncertain
   publication changes.
6. Choose the smallest operator action that satisfies the goal and respect shared-tunnel blast
   radius.
7. Verify the changed surface: connector lifecycle needs local state; publication or recovery
   success needs the relevant hostname, audience-specific Access posture, and manager checks.

Manager-mutating workflows, including connector lifecycle, hold one local OS writer lock. A
`manager_busy` error means another writer holds it: keep read-only diagnosis available and let that
operation settle; never delete the lock file to force a second writer. The lock and atomic manifest
replacement do not protect against dashboard edits or make Cloudflare changes transactional.
Ordinary writes compare the complete supported tunnel configuration and refuse foreign drift;
setup refresh is not an overwrite/reset command. Withdrawal is persisted before route changes,
and cleanup waits for the exact configuration version on all observed active connectors. Unknown
or stale replica application keeps the operation pending. Refresh does not resurrect a withdrawn
route. Use `setup` for owned local token-file or native service-file repair only when no incompatible
transition is pending.

## Interrupted writes

The canonical manifest owns one pending transition. Repeat its original request to resume; do not
substitute setup refresh, another mutation, or a blind retry of an unknown POST.

`repair resolve --operation ID --resource-id ID --yes` validates the exact saved creation;
`--absent` instead must prove absence before retry. Neither finishes or forgets the enclosing
mutation. Metadata cannot restore a token secret: use
`repair retire-token --operation ID --resource-id ID --yes` only for the pending publication's
lost-secret candidate, then repeat its publication command. A completed publication's missing
secret needs explicit `token rotate NAME --yes`; an unknown rotation needs
`token rotate NAME --recover --yes`. Never silently rotate during publication reconciliation.

Protected HTTP and SSH ingress uses native per-route Access JWT validation. Do not treat routing
or policy changes as proof of retroactive JWT revocation or termination of established SSH/WebSocket
sessions. Teardown retains Access until the exact tunnel is confirmed deleted.

## References

- [Mental Model](references/mental-model.md): load when explaining use cases or deciding whether this
  local publication product is the right boundary.
- [Product Contract](references/product-contract.md): load before changing operator behavior,
  explaining ownership, or comparing product and remote Cloudflare state.
- [Operator Recipes](references/operator-recipes.md): load before Linux bootstrap or when giving concrete setup, publish,
  verify, recovery, token, guard, remove, or teardown commands.
- [State And Recovery](references/state-and-recovery.md): load when manager state, native user service,
  `cloudflared`, logs, drift, or incident recovery is in scope.
- [Source And Discovery](references/source-and-discovery.md): load when the PATH command, checkout,
  install posture, or source-edit boundary is uncertain.
- [Cloudflare API And Permissions](references/cloudflare-api-and-permissions.md): load only when
  token visibility, zone/account/tunnel permissions, or blocked setup/recovery requires vendor/API
  probing beyond the CLI.
- [Inspect Manager](scripts/inspect-manager.sh): run for read-only local manager inspection; it does
  not mutate Cloudflare or local manager state and does not print secret values. It reads command
  discovery, `cloudflared --version`, native service and file/log metadata. An optional standalone
  PATH Python enables allowlisted macOS plist/state parsing or Linux state parsing; without one, it reports skipped parsing
  and retains metadata-only diagnosis. It never invokes Apple's developer-tools Python shim or
  requires installing Python/Xcode. The uv-installed CLI has its own interpreter.

## Evidence for the result

An explanation can establish product scope from its source contract without claiming today's
manager readiness. Package validation checks source structure, not live activation or usefulness.
For installed operations, report the observed publication, audience, recovery, or teardown outcome
and any unresolved checks. When editing the inspection script, validate its shell syntax with
`bash -n scripts/inspect-manager.sh`; running it against a real publishing host is separate local-state evidence.
Hermetic tests are not Linux live acceptance, device pairing, HTTPS/WSS authorization, or local
inference proof. For native web/iPhone clients, do not assume Access headers/login: `public` requires
approved exposure and application-owned fail-closed pairing/session checks, not merely a health 200.
