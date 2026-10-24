# Operator Recipes

## Audience choices

The product contract defines these audience modes. For an existing publication, inspect its
current audience rather than assuming a mode from an example.

- `human`: browser users authenticate through email or email-domain Access rules. Human checks need
  a manual browser validation after `verify --live`.
- `machine`: machine clients authenticate with a publication-scoped service token. Live
  verification proves anonymous HTTP denial plus service-token HTTP success, or pinned native SSH
  key exchange for an SSH publication. It does not prove SSH user login.
- `mixed`: one hostname serves both browser and machine workflows. Live verification proves
  anonymous denial plus service-token success, and human login still needs a browser check.
- `public`: no Cloudflare Access application, policy, or service token. Use only when the local
  origin authenticates requests fail-closed. Live verification sends no Access headers and requires
  the configured origin status.

SSH supports only `machine`. The other audience modes and HTTP status profiles are HTTP(S)-only.

## Bootstrap a new manager

```bash
cloudflare-publish setup \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --zone example.com
```

Use this when no local manager state exists.
In an interactive terminal, omit `--api-token` and enter the Cloudflare API token at the prompt. In
non-interactive local shells, prefer a short-lived `CLOUDFLARE_API_TOKEN` process environment or set
`CLOUDFLARE_PUBLISH_DOTENV` to an absolute private dotenv path outside the repository. The private
dotenv must be a regular mode-`0600` file with `CLOUDFLARE_API_TOKEN` and optional setup defaults.
Do not ask the user to paste token values into chat, shared shell transcripts, or reusable docs. The
`--api-token` flag remains supported for local terminal use, tests, and emergency non-interactive
operation.

The selected zone must be `active` and `full`. Partial (`CNAME`) zones are blocked because the
product manages Cloudflare DNS records directly.
Only macOS supports `setup --install-deps`; Homebrew must already be on `PATH`.
Linux dependencies are externally installed, never by the product.

### Linux prerequisites and bootstrap inputs

Run as the intended host user. Have Python 3.12+, `uv`, official `cloudflared` 2025.4.0+, `curl`
and `lsof` available before installing the CLI from the exact reviewed source or package root.
Check native prerequisites without reading secrets:

```bash
uname -m
systemctl --version
systemctl --user show --property=Version --value
loginctl show-user "$(id -u)" --property=Linger --value
command -v uv curl cloudflared lsof
cloudflared --version
```

Expect systemd 240+, working user-manager access, and lingering `yes`. Select binaries matching the
reported host architecture. ARM64/DGX is this candidate's deployment target, not an admission lock
or a claim of live hardware qualification.
If missing, the host operator/admin arranges the user manager and `loginctl enable-linger USERNAME`
under host policy; this product never invokes sudo, enables lingering, installs dependencies, or
creates a system service. Setup diagnoses these before creating Cloudflare resources.

Required inputs are the approved account/active full zone and scoped token grant, a distinct logical
tunnel name for this host/profile, exact approved hostname, local origin URL and audience, plus the
application's actual sensitive verification path/status (or trusted Ed25519 pin for SSH). Use local
prompt/private-dotenv secret ingress. Each independent host creates its own remotely managed tunnel;
do not copy Mac state, token files or credentials, or use independent backends as replicas. Then run
the common setup, plan, confirmed apply and `verify --live` sequence. Installing this candidate is
not permission to expose an endpoint, issue a grant, or publish a source/catalog release.

Before claiming live acceptance, the integration owner checks the installed candidate, exact unit
ownership and user-service lifecycle, persistence across authorized logout/reboot, private-store
permissions, exact connector-PID/listener configuration evidence and pending-transition recovery.
For native clients, also run sensitive HTTPS/WSS requests with missing/invalid/revoked application
credentials and authenticated requests through the approved hostname. Check actual pairing/device
use separately; hermetic tests or a health response do not prove it. The origin's own service
lifecycle is independent of the connector and remains with its application owner.

## Take over conflicting local cloudflared ownership (macOS only)

```bash
cloudflare-publish setup --takeover --yes \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --zone example.com
```

Use this only when the workstation still owns the generic launch agent or `~/.cloudflared`
 state. The product backs up and removes only the known conflicting surfaces.
Linux refuses takeover, including legacy/system-wide services. Their owner must resolve conflicts
separately; the product does not adopt them.

## Refresh an existing manager

```bash
cloudflare-publish setup
```

Use this for owned local tunnel-token-file or native user-service drift when no incompatible mutation is
pending. It compares the complete remote configuration before writing; foreign routes, options,
or unsupported fields are refused, not reset. The exact owned pre-validator configuration can be
upgraded to native per-route Access validation. Refresh cannot change the selected account, zone,
or tunnel identity.

Use the refresh-only form when the command must fail instead of bootstrapping a new manager:

```bash
cloudflare-publish setup --refresh-only
```

## Publish or update one hostname

```bash
cloudflare-publish publish apply dashboard \
  --hostname dashboard.example.com \
  --to https://127.0.0.1:8443 \
  --audience mixed \
  --allow-domain example.com \
  --yes
```

Re-running `publish apply` with the same publication name reconciles that owned publication.
Authorization-boundary or hostname changes replace Access/AUD after a persisted, observed
withdrawal; origin-only changes may reuse protection. Existing connectors retain the old origin
with its matching old guard until they observe the new configuration.
For `machine` and `mixed` publications, the command also prints the current service-token client ID
and client secret after reconciliation.
Missing local secrets on completed publications require explicit `token rotate NAME --yes`; a
publication update does not silently rotate them. A failed handoff can follow an already-applied
publication (`credential_handoff_unavailable`, `publication_applied: true`), not rollback.

Preview the same mutation without changing local or remote state:

```bash
cloudflare-publish --json publish plan dashboard \
  --hostname dashboard.example.com \
  --to https://127.0.0.1:8443 \
  --audience mixed \
  --allow-domain example.com
```

## Publish native SSH

The publishing host's SSH server must already run and have independently authorized login users and keys.
Publishing does not enable Remote Login or change `sshd`, user accounts, or `authorized_keys`.
The operator must acquire the Ed25519 public host key through a trusted path, such as reading the
local `/etc/ssh/ssh_host_ed25519_key.pub`. A key discovered over the new public hostname is not an
independent pin.

```bash
SSH_HOST_KEY="$(cat /etc/ssh/ssh_host_ed25519_key.pub)"
cloudflare-publish --json publish plan mac-ssh \
  --hostname mac.example.com \
  --to ssh://127.0.0.1:22 \
  --audience machine \
  --ssh-host-key "$SSH_HOST_KEY"
```

After the authorized plan review, use the same arguments with `publish apply` and `--yes`, then
run `cloudflare-publish verify mac-ssh --live`. The origin scheme selects `ssh_public`; there is
no separate setup, connector, publication store, or kind flag. SSH requires one valid Ed25519
public host key and rejects all human allow rules and HTTP verify/origin options. An optional key
comment is accepted but not stored. HTTP(S) rejects `--ssh-host-key`.

`publish apply` returns a publication-scoped Access service token through its credential handoff.
Move it only to the authorized client's private credential store through an approved secure
channel. Never paste a secret into chat, add it to tracked files or shell history, or expand it
into process arguments. Access machine authentication and SSH login authentication are different:
the client needs both the Access token and a separately authorized SSH login key.

### Native client configuration

Install `cloudflared` and OpenSSH separately on the intended client only when that installation is
authorized. Supply `TUNNEL_SERVICE_TOKEN_ID` and `TUNNEL_SERVICE_TOKEN_SECRET` to the client process
environment from private machine credential storage. Keep those values out of the command line.
Use a private, dedicated known-host file containing the independently transferred pin:

```text
mac.example.com ssh-ed25519 BASE64_OF_THE_VERIFIED_MAC_HOST_KEY
```

The following is an operator-owned SSH configuration template, not a product installation step.
Replace the login user, known-host path, private-key path, and binary path with explicitly selected
client values; do not generate or reuse a login key implicitly.

```sshconfig
Host mac-via-cloudflare
    HostName mac.example.com
    User MAC_LOGIN_USER
    ProxyCommand /absolute/path/to/cloudflared access ssh --hostname %h --loglevel error
    UserKnownHostsFile /absolute/path/to/mac-known-hosts
    GlobalKnownHostsFile /dev/null
    HostKeyAlias mac.example.com
    StrictHostKeyChecking yes
    HostKeyAlgorithms ssh-ed25519
    VerifyHostKeyDNS no
    UpdateHostKeys no
    IdentityFile /absolute/path/to/authorized_mac_login_key
    IdentitiesOnly yes
    IdentityAgent none
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
```

Then use `ssh mac-via-cloudflare` in the credential-bearing environment. Keep cloudflared at
`--loglevel error`: debug-level WebSocket logging can expose Access request headers. The machine
Access policy must remain the exact service-token-only policy; unexpected login redirects are an
authentication failure to investigate, not permission to replace it with a browser or human policy.
The product's verification probe isolates its temporary home/cache and blocks the browser-launcher
paths it could invoke. That containment is not installed by this client configuration. Upstream
cloudflared can invoke `open` or `xdg-open` directly; a `BROWSER` environment setting is not a
reliable way to disable its login fallback. Before using an unattended client, its separately owned
installation must contain fallback through verified launcher blocking/isolation or a verified
supervisor-owned transport route. Do not assume the SSH configuration alone provides that boundary.
Do not turn off `StrictHostKeyChecking` or replace a mismatching pin from a public key scan.

The product's native SSH probe uses no private key and deliberately does not log in. Its successful
signed key exchange proves the pinned server's transport identity, not that this client user can
log in. Test the actual authorized login separately when it is part of the commissioned work.

### Reverse forwarding from remote machines

A separately commissioned remote installation can have each remote machine open SSH toward this
stable Mac hostname and request a distinct loopback-only reverse listener, for example remote
machine 1 with `-R 127.0.0.1:2201:127.0.0.1:22` and machine 2 with port `2202`. The Mac can then use
those local listeners to reach their SSH servers. Both sites make outbound Cloudflare connections;
no new inbound router port is needed. The Mac must still be awake and connected.

Give each remote machine its own restricted login key and an explicitly authorized server-side
forwarding policy, limited to its assigned loopback listener. Deny unrelated shell, agent, X11,
and forwarding capabilities; a generic unrestricted Mac login key is not a tunnel-service design.
The subsequent Mac-to-remote SSH connection must separately pin the remote machine's host key
and authenticate with an independently authorized remote login key.

Install and supervise that remote SSH connection separately, with failure detection and reconnect
behavior that avoids competing duplicate listeners. This release does not install that supervisor,
change the Mac's SSH server, or administer remote machines. Cloudflare's WebSocket transport can
disconnect; reconnect restores access, not an interrupted interactive session or workload. Keep
remote jobs independent of the connection, for example in an authorized `tmux` session.

Cloudflare remains the transport and availability dependency. Strict native SSH host-key pinning
keeps the inner SSH contents encrypted end-to-end; this is not a VPN or a third-party-free route.

## Publish a browser-only hostname

```bash
cloudflare-publish publish apply handbook \
  --hostname handbook.example.com \
  --to https://127.0.0.1:8443 \
  --audience human \
  --allow-domain example.com \
  --yes
```

Use this when only browser users need Access login and no machine token should exist.

## Publish an origin-authenticated provider endpoint

```bash
cloudflare-publish publish apply provider-ingress \
  --hostname provider-ingress.example.com \
  --to http://127.0.0.1:4751 \
  --audience public \
  --verify-path / \
  --expect-status 400-499 \
  --yes
```

Use `public` only when the origin itself rejects unsigned or otherwise invalid requests. Do not add
Access allow rules: provider callbacks cannot supply Cloudflare service-token headers. The manager
owns DNS and tunnel routing only; it does not create storage or Cloudflare compute.

## Native clients with origin-owned authentication

Establish whether the intended native HTTPS or WebSocket client supports Access browser login or
the required service-token headers. If neither is supported, `public` can serve an application that
already owns authentication, but only with authorization for the Internet-reachable hostname and
pairing surface and evidence that sensitive requests fail closed. `public` means no Access, not no
application authentication. Do not add a custom gateway merely to preserve an unsuitable Access
mode.

For independent T3-style Linux backends, each host/profile publishes its own hostname and distinct
tunnel directly to its local backend, never through a Mac proxy or ad-hoc fourth publisher. T3 owns
pairing and device/session authentication. Inspect the installed client's actual HTTPS/WSS auth
contract; an iPhone is not assumed to support Access headers or an Access browser flow. New hostname
selection and Cloudflare credentials/grants require explicit approval independently of this recipe.

- Select a real sensitive endpoint for `--verify-path` and its narrow denial status for
  `--expect-status`. Check unauthenticated denial locally and through the hostname. An intentionally
  public descriptor or a `200` from SPA fallback proves neither an authentication bypass nor
  protection of sensitive endpoints.
- Preserve the public Host and forwarded HTTPS scheme when the application derives client URLs
  from them. Leave `--http-host-header` unset unless the origin demonstrably requires an override.
- Use the origin's installed CLI help and live capability or protocol descriptor when issuing
  pairing credentials or constructing a WebSocket request. A source checkout can differ from the
  installed server; do not hard-code its newer command flags or protocol version.
- Follow `verify NAME --live` with authenticated HTTPS and, when used, WebSocket checks through the
  hostname, using the intended native transport where practical. A successful transport test does
  not prove that a real device paired or that its application workflow works; report those separately.
- A diagnostic User-Agent can receive Cloudflare browser-signature rejection
  ([error 1010](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/))
  while the native client succeeds. Compare with the intended client before changing the route;
  do not relax account-wide WAF or Browser Integrity Check just to make a diagnostic pass.

Pairing and session credentials belong to the application, not this manager. Keep them out of
reusable docs and tracked files; revoke temporary test credentials through the application's own
command. Revoking a bootstrap pairing grant may not revoke the session it already issued.

## Inspect or verify state

```bash
cloudflare-publish --json doctor
cloudflare-publish --json ls
cloudflare-publish --json inspect dashboard
cloudflare-publish --json verify
cloudflare-publish --json verify dashboard --live
```

`inspect NAME` is the no-secret publication-contract view. For HTTP it shows the public verification URL,
local origin URL, verification profile, Access allow rules, origin request options, remote resource
IDs, and service-token client ID when one exists. It does not print service-token client secrets.
Plain HTTP origins report origin TLS verification as not applicable.
SSH instead shows its pinned public host key and native-SSH verification scope, not HTTP status,
path, or origin TLS fields.

`doctor` resolves credentials and, when a token is available, queries account discovery. `verify`
and `repair plan` use credentials for Cloudflare reads and probe origins even without `--live`;
they do not change managed state, but curl and SSH use private temporary files. These are not offline checks.

Successful HTTP `verify --live` checks establish Access denial for protected publications, service-token
success for `machine` and `mixed`, and the exact declared origin status for `public`. It does not
perform interactive human login.
SSH checks instead establish native signed key exchange to the pinned server locally and through
the Access-protected public transport. An anonymous HTTP denial is only HTTP Access-gate evidence;
the app's `service_auth_401_redirect: true` requests HTTP 401 on Service Auth denial despite its
name. Native public probing requires that flag, exact machine-only policy parity, and anonymous
HTTP 401/403. An unexpected login redirect fails SSH preflight; it does not invoke human login.
No SSH login credentials are used, and success proves neither user login nor reverse forwarding.

Checks are grouped as manager, routing, origin, Access, and public probe, with publication name and
hostname for publication-specific evidence. JSON retains a flat `checks` array and aggregate
`failures` count, plus populated `groups` objects with `group`, a `checks` array, and a `failures`
count. An unavailable on-demand origin still
fails readiness: start it through its application owner only when that is requested. A matched
404/405 probe proves neither request authentication nor a successful application/provider workflow.

For browser-facing hostnames, follow `verify --live` with a manual browser check through the
published hostname and confirm the expected Access prompt or login flow.

## Inspect an explicitly selected remote tunnel

```bash
cloudflare-publish --json discover tunnel "$CLOUDFLARE_TUNNEL_ID" \
  --account-id "$CLOUDFLARE_ACCOUNT_ID" --zone-id "$CLOUDFLARE_ZONE_ID"
```

This read does not need a local manager. It requires the zone to belong to the account and returns
allowlisted identity, sanitized ingress, matching DNS/Access, unsupported-topology findings, and
inspection coverage. It never fetches tunnel tokens or dumps raw configuration. Use it to establish
remote publication facts, not as resource adoption or proof that every application dependency has
been found. Unmanaged-resource collision checks in ordinary publication remain unchanged.
`has_destination_overrides` and policy `has_additional_constraints` are presence metadata only;
the corresponding `access_destination_overrides` and `unreported_policy_constraints` findings do
not inspect override or `require`/`exclude` semantics. Only `include` rule kinds are summarized.
Managed policy verification rejects additional `require`/`exclude` constraints rather than
reporting parity from the `include` rules alone. A hostname-bearing `http_status` service is
unsupported (`non_http_publication_service`); the terminal hostless `http_status:404` remains valid.

Cloudflare may retain a deleted tunnel's exact GET. A nonempty `deleted_at` and `deleted_tunnel`
finding identify the tombstone; discovery does not fetch obsolete ingress configuration or a token.
Residual selected-zone DNS pointing at its CNAME and matching Access apps stay visible. Verify DNS
and connector settlement separately; an empty ingress summary is not that proof. A down tunnel
without deletion metadata is not a deletion tombstone. This read does not authorize recreation.

## Local connector lifecycle

Use these commands for local native user-connector control only (launchd on macOS, systemd on Linux):

```bash
cloudflare-publish service status
cloudflare-publish service start
cloudflare-publish service stop
cloudflare-publish service restart
cloudflare-publish service logs
```

`service start` loads or kickstarts the macOS canonical plist, or enables/starts the Linux canonical
user unit. It fails closed when the service identity, token-file argument, or absolute `cloudflared`
binary does not match the manager contract. Linux stop disables automatic startup and confirms
inactivity; teardown removes only the owned unit and reloads the user manager. None of these commands
bootstrap a new manager. Use `setup` when the native service file or tunnel token is
missing, and use `verify` when remote Cloudflare parity matters.

Keep connector lifecycle commands, publication inventory, verification, guard inspection,
and all initial setup, publication-specific, credential-handoff, account-policy-changing, and
explicit-impact flows in the terminal instead of hiding them behind one-click local overlays.

## Tunnel Recovery

Use this after dashboard tunnel-token rotation or a shared-tunnel incident.

```bash
cloudflare-publish tunnel recover plan
cloudflare-publish tunnel recover apply --yes
```

Use this only after the tunnel token changes in the dashboard or when every connector on the shared
tunnel must be disconnected. Run the plan form first and inspect the planned shared-tunnel blast
radius before using `apply --yes`.

Effects:

- fetches the current tunnel token
- rewrites the local token file
- reinstalls and restarts the canonical local user service
- deletes all shared-tunnel connectors through the Cloudflare API

Blast radius:

- every connector on the shared tunnel is forced off the edge, including replicas not managed from
  this workstation

## Rotate one Access service token

```bash
cloudflare-publish token rotate dashboard --yes
```

Use this for publication-scoped machine credentials, not for the shared tunnel runtime token.
`token rotate` prints the new client ID and client secret after rotation.
Use it explicitly when a completed publication's local machine-token secret is gone, and replace
downstream credentials deliberately. If the new-secret outcome is unknown, first run `repair plan`,
then authorize replacement of that uncertain secret with:

```bash
cloudflare-publish token rotate dashboard --recover --yes
```

Plain repetition refuses an unknown outcome. `--recover` requires this exact pending rotation;
neither it nor a resource GET can retrieve an old secret.

## Resume an interrupted change

```bash
cloudflare-publish --json repair plan
```

The manifest owns one pending mutation and its effective route, not a second workflow database.
Repeat the original normalized command and confirmation to resume the same request. An incompatible
mutation is refused; reads and plans stay available. Do not erase `pending`, substitute setup
refresh, or repeat an unknown creation POST.

If the plan reports an unknown creation outcome, inspect its exact candidates. Substitute only
the operation and resource IDs from that plan:

```bash
cloudflare-publish repair resolve --operation OPERATION_ID --resource-id RESOURCE_ID --yes
```

The command validates the resource against the saved intent and records ownership. It resolves
only that effect; repeat the original mutation afterwards. If no resource exists, the alternative
is a complete scoped absence proof, not a manual assertion:

```bash
cloudflare-publish repair resolve --operation OPERATION_ID --absent --yes
```

Resource metadata cannot restore a lost service-token secret. For a pending publication candidate
whose token secret is lost, resolve its exact identity first if required, then retire only that
candidate:

```bash
cloudflare-publish repair retire-token --operation OPERATION_ID --resource-id RESOURCE_ID --yes
```

This validates candidate ownership, records retirement, confirms remote absence, and preserves the
original publication. Repeat the original publication command to create/store a replacement. It
does not cancel the mutation or retire an arbitrary token. Completed publications use ordinary
explicit rotation; interrupted rotations use `--recover`, not candidate retirement.

## Manage unmatched-request protection

```bash
cloudflare-publish --json guard status
cloudflare-publish --json guard plan
cloudflare-publish guard apply --yes
```

`guard apply` preserves existing exempted zone names.
It refuses to enable require-protection when that would block a managed `public` publication;
`guard status` names the affected publications without becoming a mutating denial.

## Remove one publication

```bash
cloudflare-publish rm plan dashboard
cloudflare-publish rm apply dashboard --yes
```

This persists withdrawal, changes ingress, and observes the exact configuration version on every
active connector before deleting the managed DNS record, optional Access resources, and service
token. Unknown/stale replica application keeps cleanup pending. A repeat resumes the same removal;
refresh does not resurrect the withdrawn route. Ordinary removal does not disconnect all connectors.

## Retire the whole manager

```bash
cloudflare-publish teardown --yes
```

This records intent, stops and confirms removal of the local connector, and refuses active or
unobservable remote replicas. It confirms deletion of the exact shared tunnel while Access is
still intact, then removes owned DNS, Access resources, tokens, and finally credentials/local
artifacts. Failures retain custody for the same teardown command to resume. It preserves takeover
backups and the persistent local writer lock and does not forcibly disconnect other machines.

Configuration observation is not session drainage. Route, policy, and token changes do not promise
instantaneous JWT revocation or termination of an already-open SSH/WebSocket/application session.
Confirmed tunnel deletion is a transport boundary, not a claim that application workloads ended.
