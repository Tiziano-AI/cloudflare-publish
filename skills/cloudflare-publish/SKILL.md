---
name: cloudflare-publish
description: "Publish, update, verify, recover, or remove local HTTP(S) or machine-authenticated native SSH on this Mac through the managed exact-hostname Cloudflare Tunnel manager. SSH requires a pinned Ed25519 host key. Also use to explain this product. Not for Workers, Pages, generic Cloudflare architecture, wildcard/path routing, VPN/private-network connectors, DNS-only administration, or non-local publication."
---
# Cloudflare Publish

For interrupted writes, use `repair plan` before any retry. The canonical manifest owns one pending
transition: repeat its original request to resume; do not substitute setup refresh, another
mutation, or a blind retry of an unknown POST. `repair resolve --operation ID --resource-id ID
--yes` validates the exact saved creation; `--absent` instead must prove absence before retry.
Neither finishes or forgets the enclosing mutation. Metadata cannot restore a token secret: use
`repair retire-token --operation ID --resource-id ID --yes` only for the pending publication's
lost-secret candidate, then repeat its publication command. A completed publication's missing
secret needs explicit `token rotate NAME --yes`; an unknown rotation needs `token rotate NAME
--recover --yes`. Never erase pending state or silently rotate during publication reconciliation.
Protected HTTP and SSH ingress uses native per-route Access JWT validation.
Never equate routing/policy changes with retroactive token revocation or termination of established
SSH/WebSocket sessions. Teardown retains Access until the exact tunnel is confirmed deleted.

One local HTTP, HTTPS, or machine-authenticated SSH service on this Mac maps to one exact hostname
in the operator's own Cloudflare account and active full DNS zone. One remotely managed tunnel carries all managed
publications. Protected audiences use Cloudflare Access; `public` omits Access only when the origin
already enforces fail-closed request authentication.

This plugin supplies guidance, not an account or a running service. It installs no CLI, credentials,
connector, DNS records, or Access policies automatically. Discover the separately installed
`cloudflare-publish` command before operating it; see Source And Discovery for explicit setup.
Disabling or removing the plugin leaves the CLI, connector, publications, and credentials in place.

## Use when

- the user wants to publish, update, verify, recover, rotate, or remove a local HTTP, HTTPS, or SSH
  service behind the shared Tunnel and Access manager
- the user wants to share a local web demo, private API, or application-authenticated provider
  callback on one exact Cloudflare hostname
- a native HTTPS or WebSocket client needs to reach an already authenticated local application
  through one exact hostname
- the user wants a stable SSH hostname for this Mac without dynamic DNS or inbound port forwarding
- the user asks what this repo/product is for, whether it is useful, or which first-success loop to
  try with a local publication
- the task concerns the real `cloudflare-publish` product state on this Mac
- the task concerns terminal-first local status, repair planning, live verification, or gate
  validation
- operator recovery or verification is needed for the local manager or one managed publication

## Do not use when

- the task is generic Cloudflare development or platform choice unrelated to the local product
- the user wants to deploy code into Workers or Pages rather than expose a running local origin
- the work concerns wildcard routing, path routing, private-network connectors, general VPN/UDP/TCP,
  or publication kinds other than HTTP(S) and SSH
- the request concerns neither this product's purpose/source nor a local manager or publication

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
3. Use `service` commands only for local launchd connector lifecycle and logs.
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
route. Use `setup` for owned local token-file or launch-agent repair only when no incompatible
transition is pending.

## References

- [Mental Model](references/mental-model.md): load when explaining use cases or deciding whether this
  local publication product is the right boundary.
- [Product Contract](references/product-contract.md): load before changing operator behavior,
  explaining ownership, or comparing product and remote Cloudflare state.
- [Operator Recipes](references/operator-recipes.md): load when giving concrete setup, publish,
  verify, recovery, token, guard, remove, or teardown commands.
- [State And Recovery](references/state-and-recovery.md): load when manager state, launchd,
  `cloudflared`, logs, drift, or incident recovery is in scope.
- [Source And Discovery](references/source-and-discovery.md): load when the PATH command, checkout,
  install posture, or source-edit boundary is uncertain.
- [Cloudflare API And Permissions](references/cloudflare-api-and-permissions.md): load only when
  token visibility, zone/account/tunnel permissions, or blocked setup/recovery requires vendor/API
  probing beyond the CLI.
- [Inspect Manager](scripts/inspect-manager.sh): run for read-only local manager inspection; it does
  not mutate Cloudflare or local manager state and does not print secret values. It reads command
  discovery, `cloudflared --version`, launchd state and file/log metadata. An optional standalone
  PATH Python enables allowlisted plist/state parsing; without one, it reports skipped parsing
  and retains metadata-only diagnosis. It never invokes Apple's developer-tools Python shim or
  requires installing Python/Xcode. The uv-installed CLI has its own interpreter.

## Evidence for the result

An explanation can establish product scope from its source contract without claiming today's
manager readiness. Package validation checks source structure, not live activation or usefulness.
For installed operations, report the observed publication, audience, recovery, or teardown outcome
and any unresolved checks. When editing the inspection script, validate its shell syntax with
`bash -n scripts/inspect-manager.sh`; running it against the Mac is separate local-state evidence.
