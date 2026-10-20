# Product Contract

`cloudflare-publish` is the canonical local product for publishing exact hostnames from one macOS
user profile through one shared remotely managed Cloudflare Tunnel. Protected audiences use
Cloudflare Access; `public` deliberately delegates request authentication to a fail-closed origin.

It publishes running local HTTP, HTTPS, or machine-authenticated native SSH services. It does not
deploy application code into Cloudflare compute.

## Product model

- one local origin on this Mac
- one exact hostname in one active full Cloudflare-managed DNS zone
- zero or one Cloudflare Access application plus policies for that hostname
- one shared tunnel carrying traffic from the hostname to the local origin

## Canonical ownership

- operator CLI: PATH-global `cloudflare-publish`
- development wrapper: `bin/cloudflare-publish` from the checked-out product repository
- install posture: the host owns this skill-only plugin; install the CLI separately with
  `uv tool install --reinstall .` from an explicitly resolved source or plugin package root. Installing the
  plugin does not install the CLI, cloudflared, credentials, services, or Cloudflare resources.
  Removing it does not retire those independently owned resources; use deliberate CLI teardown
  before uninstalling the CLI if complete manager retirement is intended.
- local manager state:
  - `~/Library/Application Support/cloudflare-publish/state.json`
  - `~/Library/Application Support/cloudflare-publish/manager.lock`
  - `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
  - `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- local secrets:
  - Cloudflare API token in macOS Keychain after setup
  - optional bootstrap API token ingress from a strict private dotenv only when
    `CLOUDFLARE_PUBLISH_DOTENV` points at an absolute path outside the repository
  - Access service-token secrets in macOS Keychain
- secret process posture:
  - The CLI reads only process environment, the explicitly configured private dotenv, and Keychain.
  - The CLI does not infer workstation secret roots, read master secret pools, or follow private
    dotenv symlinks.
  - Keychain writes send a bounded `security -q -i` command with a hex-encoded token over stdin,
    never argv, and require exact readback before reporting success. Only nonempty printable ASCII
    credentials are supported; a write error never includes the credential-bearing command/output.
  - Curl receives bearer headers, Access service-token headers, and JSON bodies through
    strict-permission temporary files, not argv, and disables user curlrc configuration.

## Product boundary

The product manages:

- one account
- one active full Cloudflare-managed zone
- one shared remotely managed tunnel
- many exact-hostname HTTP, HTTPS, or machine-authenticated SSH publications
- zero or one Access app plus policies per publication
- zero or one service token per publication

The product does not manage:

- application build or deploy steps
- Workers, Pages, D1, or other Cloudflare compute or storage products
- wildcard or path-based routing
- partial (`CNAME`) zones or external DNS providers for published hostnames
- private-network, VPN, general TCP/UDP, or publication kinds other than HTTP(S) and SSH
- enabling Remote Login, creating SSH login users/private keys, or supervising reverse SSH tunnels
- Cloudflare IdP setup
- remote dashboard tunnel-token rotation

## Canonical commands

- `cloudflare-publish --json doctor`
- `cloudflare-publish --json discover accounts`
- `cloudflare-publish --json discover zones`
- `cloudflare-publish --json discover zone`
- `cloudflare-publish --json discover tunnels`
- `cloudflare-publish --json discover tunnel ID --account-id ACCOUNT --zone-id ZONE`
- `cloudflare-publish --json discover organization`
- `cloudflare-publish setup`
- `cloudflare-publish setup --refresh-only`
- `cloudflare-publish repair plan`
- `cloudflare-publish repair resolve --operation ID --resource-id ID --yes`
- `cloudflare-publish repair resolve --operation ID --absent --yes`
- `cloudflare-publish repair retire-token --operation ID --resource-id ID --yes`
- `cloudflare-publish service status`
- `cloudflare-publish service start`
- `cloudflare-publish service stop`
- `cloudflare-publish service restart`
- `cloudflare-publish service logs`
- `cloudflare-publish publish plan`
- `cloudflare-publish publish apply --yes`
- `cloudflare-publish inspect`
- `cloudflare-publish verify`
- `cloudflare-publish tunnel recover plan`
- `cloudflare-publish tunnel recover apply --yes`
- `cloudflare-publish token rotate --yes`
- `cloudflare-publish token rotate NAME --recover --yes`
- `cloudflare-publish guard status`
- `cloudflare-publish guard plan`
- `cloudflare-publish guard apply --yes`
- `cloudflare-publish rm plan`
- `cloudflare-publish rm apply --yes`
- `cloudflare-publish teardown --yes`

Tracked public surfaces are terminal-first and do not require local app actions, ignored operator
notes, user-private skill mirrors, or workstation secret tooling. Local app action recipes can exist
only in ignored operator overlays.

## Recovery law

- Use `service start`, `service stop`, and `service restart` only for local connector lifecycle.
- Use `setup` for owned tunnel-token-file and launch-agent refresh, not as a reset of arbitrary
  remote config drift. It validates the full configuration first; only exact owned or exact
  pre-validator configuration is admitted. Account, zone and tunnel identity cannot change there.
- Use `repair plan` to inspect repair needs without changing managed local or Cloudflare state.
  It uses credentials for Cloudflare reads, probes origins, and uses private temporary curl or SSH
  known-host files.
- Use `setup --refresh-only` only as a deliberate terminal repair command for an existing manager.
- Use `publish apply` for publication-scoped machine-secret handoff. A completed publication's
  missing local secret requires explicit `token rotate NAME --yes`, not implicit publication
  rotation. An unknown rotation requires its exact pending `token rotate NAME --recover --yes`.
- Start interrupted changes with `repair plan`. Repeat the same normalized request to resume;
  never substitute a different mutation, delete pending state, or blindly repeat an uncertain POST.
- Use `repair resolve` only for an exact saved creation effect: either validate a candidate ID or
  prove absence through complete scoped listing. It neither forgets nor finishes the enclosing
  transition. Remote metadata cannot restore a secret; `repair retire-token` can retire only the
  pending publication's exact lost-secret candidate before the original publication is resumed.
- Use `public` only for an origin with its own fail-closed request authentication. It owns no Access
  application, policies, or service token, and `verify --live` must observe its configured origin
  status without Access headers.
- Do not enable account require-protection while a managed public publication would be blocked,
  unless the configured zone is already exempted.
- Use `tunnel recover plan` first after dashboard token rotation or when every connector on the
  shared tunnel must be forced off the edge; use `tunnel recover apply --yes` only after explicit
  approval.

## Discovery law

- For installed operation, prefer the PATH-global `cloudflare-publish` CLI.
- Use `cloudflare-publish --json doctor` for install/auth/readiness diagnosis. It resolves
  credentials and queries the account API when a token is available; it is not an offline probe.
- Use `discover accounts`, `discover zone`, `discover zones`, `discover tunnels`, and
  `discover organization` for pre-setup discovery.
- Use `discover tunnel ID --account-id ACCOUNT --zone-id ZONE` for sanitized inspection of one
  remote tunnel, its ingress, matching DNS and Access, and unsupported topology. It requires the
  zone to belong to the account, consumes relevant pages, and neither adopts ownership nor exposes
  tokens or raw provider configuration.
- A nonempty tunnel `deleted_at` identifies a retained deletion tombstone. Discovery emits
  `deleted_tunnel`, skips obsolete ingress configuration, and retains selected-zone DNS referencing
  its CNAME and Access apps matching those residual names. It does not mistake a deleted tunnel
  for a down locally managed tunnel or establish that DNS and connectors were retired.
- Access discovery reports Boolean `has_destination_overrides` and policy
  `has_additional_constraints`, with `access_destination_overrides` and
  `unreported_policy_constraints` findings when present. Only policy `include` rule kinds are
  summarized; override and `require`/`exclude` values and semantics stay outside coverage.
  Hostname-bearing `http_status` rules are flagged as `non_http_publication_service`; the terminal
  hostless `http_status:404` remains supported.
- Use `inspect NAME` as the no-secret publication-contract view. HTTP shows the public verification
  URL, local origin URL, verification profile, Access allow rules, origin request options, remote
  resource IDs, and service-token client ID when one exists.
- SSH inspection instead shows its pinned public host key and native-SSH verification scope, not
  an HTTP response profile or origin TLS verification.
- It does not print service-token client secrets.
- Product explanation and source edits use the resolved source owner; neither requires an
  installed CLI, credentials, nor live manager discovery.
- A missing PATH command blocks installed CLI operation, not source work. Route a needed
  installation to the product owner; do not install as a prerequisite to reading or editing source.
- An unresolved checkout blocks source edits until the owner is found. Inspect runtime artifacts
  independently only when current manager facts are part of the request.

## Readiness and write safety

Verification carries typed `manager`, `routing`, `origin`, `access`, and `public_probe` groups.
Each check includes `publication_name` and `hostname` (null for manager-wide checks). JSON retains
the flat `checks` array and aggregate `failures` count, plus populated `groups` objects in order,
each containing `group`, a `checks` array, and a `failures` count. Human results use the same evidence
groups. An absent on-demand origin fails readiness. A matched
HTTP response, including a configured 404/405, is not proof of authenticated application use or a
complete workflow. `--live` does not perform human login.
SSH signed-key-exchange checks use OpenSSH and the independently trusted Ed25519 host-key pin;
origin checks connect locally and live checks use `cloudflared` with the current Access token.
They load no private keys or login credentials and prove neither SSH user login nor forwarding.
Anonymous HTTP denial is separate evidence, not proof of an SSH handshake.
Managed Access policy verification fails parity on additional `require`/`exclude` constraints;
matching only the declared `include` signature is insufficient while those constraints exist.

Each complete manager mutation, including `service start`, `stop`, and `restart`, holds a local
nonblocking OS advisory lock before workflow reads or writes. Contention fails with `manager_busy`;
read-only commands stay available. Never remove the persistent lock file to bypass a writer.
The manifest is staged mode `0600` beside its destination, then atomically replaced; failed staging
preserves the prior manifest. Neither protection provides remote transactions or excludes dashboard
writers.

One nullable typed `pending` transition in that manifest owns an unfinished mutation: operation
identity, normalized secret-free request, phase, effective route, candidate ownership, and unknown
external effect. Completion clears it; it is not an operation history. An incompatible mutation
fails with `transition_pending`. New remote creation names include the operation ID so recovery
cannot infer ownership from a logical publication or tunnel name alone.

The complete supported tunnel configuration is compared before ordinary writes, including ordered
ingress, global options, defaults, and unknown fields. Foreign drift is refused. Protected HTTP
and SSH ingress uses native `cloudflared` Access JWT validation for that application's AUD and the
selected organization. Public ingress deliberately does not. Authorization-boundary and hostname
changes replace Access/AUD; origin-only changes may reuse them. Old connector configurations retain
the old origin and its matching old protection.

Removal and authorization-boundary replacement persist route withdrawal before changing ingress.
Cleanup first requires complete remote configuration equality and its exact target version, then
that applied version on every observed active connector. When the API omits only the canonical
local connector's version, the CLI may fill it from its PID-owned native loopback diagnostics,
with exact tunnel/client identity and process/listener/identity rechecks. It never overrides an
API-version conflict or supplies evidence for another replica. No proxy, port scan or process
argument, environment, token or log inspection is used. Unknown, malformed, stale or conflicting
application evidence keeps custody pending, and effective routing prevents generic refresh from
resurrecting a withdrawn route. Ordinary mutation does not disconnect every connector. Application
evidence is a snapshot, not a lock against future replicas.

Teardown stops and confirms local connector removal, refuses active or unobservable replicas, and
confirms exact tunnel deletion before removing Access protection. Owned DNS, Access and tokens
follow; credentials and local manager artifacts are last. Failures retain resumable custody;
takeover backups and the persistent lock survive.

Edge authorization, connector JWT validation, and existing sessions are different boundaries.
Token, route, and policy changes do not promise instantaneous revocation of every issued JWT or
termination of an established SSH, WebSocket, or application session. Confirmed tunnel deletion
establishes a transport boundary, not proof about application sessions or workloads.

## Native SSH contract

`--to ssh://HOST:PORT` selects `ssh_public`; HTTP(S) keeps `http_public`. SSH requires `--audience
machine` and `--ssh-host-key` containing one valid `ssh-ed25519` public host key, obtained through
an already trusted channel. Optional comments are accepted but only type and base64 are stored.
SSH rejects every HTTP verification/origin option and all human allow rules. Its `verify_path`
and `expect_status` are null, its HTTP origin options are empty, and `ssh_host_key` holds the pin.
HTTP specs have no host-key pin, and existing HTTP manifests without that field remain readable.

SSH reuses the shared connector, proxied DNS, self-hosted Access application, and specific-token
`non_identity` policy. The existing `service_auth_401_redirect: true` setting requests HTTP 401
when Service Auth blocks a request; despite its name it does not enable a login redirect. Native
public probing requires that flag, exact policy parity, and anonymous HTTP 401/403. The service
token authorizes transport, not SSH login. Cloudflare carries the outer traffic and remains a dependency; strict SSH host-key
pinning protects the native SSH contents. WebSocket transport may disconnect; separate supervisors
own persistent SSH sessions. A stable hostname does not make a sleeping or offline Mac available.
