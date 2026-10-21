# State And Recovery

## First inspection

For local manager diagnosis, run the [inspection script](../scripts/inspect-manager.sh) from the
resolved skill package directory:

```bash
scripts/inspect-manager.sh
```

The inspection script is read-only. It locates the CLI, prints `cloudflared` version, reads launchd
and file/log metadata. An optional standalone `python3` on PATH enables allowlisted plist and state
summaries, including pending kind/phase. The script skips Apple's `/usr/bin/python3` developer-tools
shim (including symlinks), preflights a separate interpreter, and falls back to metadata-only
diagnosis if parsing is unavailable. No Python or developer-tools installation is required; the
uv-installed CLI can work independently of PATH Python. With parsing, it reports inline-token or
environment presence without printing their
contents, and does not read the tunnel-token file. It does not call Cloudflare write APIs, change
launchd state, mutate local manager files, or print secret values. Do not replace it with a raw
plist dump: a noncanonical plist can contain inline credentials.

Manual local inspection commands:

```bash
command -v cloudflare-publish || true
cloudflared --version
launchctl list | grep com.cloudflare-publish.cloudflared || true
ls -la "$HOME/Library/Application Support/cloudflare-publish"
```

Add `cloudflare-publish --json doctor` when auth/Cloudflare readiness matters; it resolves
credentials and may query the account API. Local artifacts alone cannot prove those facts.
If the CLI is not on `PATH`, local diagnosis can continue through runtime artifacts. Source work
instead needs the source owner, not a working manager; see Source And Discovery.

## Canonical local state

- state manifest: `~/Library/Application Support/cloudflare-publish/state.json`
- persistent writer lock: `~/Library/Application Support/cloudflare-publish/manager.lock`
- tunnel token file: `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
- takeover backups: `~/Library/Application Support/cloudflare-publish/backups/<timestamp>/`
- launch agent: `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- logs:
  - `~/Library/Logs/cloudflare-publish/cloudflared.out.log`
  - `~/Library/Logs/cloudflare-publish/cloudflared.err.log`

## Fail-closed rules

- `setup` stops unless `--takeover` is explicit when the generic launch agent or
  `~/.cloudflared` conflict surfaces exist; the command also requires `--yes`.
- manager bootstrap does not silently adopt a same-name remote tunnel. New remote resources carry
  operation-specific creation markers; logical publication/tunnel names are not enough to prove
  ownership.
- `publish apply` fails when a hostname is already owned by another managed publication or by an
  unmanaged remote DNS record.
- `setup` fails unless the chosen zone is `active` and `full`.
- `setup --refresh-only` fails before platform-tool checks unless local manager state already exists.
- `setup`, `service start`, `service restart`, `tunnel recover apply`, and launch-agent repair paths
  require `cloudflared` `2025.4.0` or later because the product uses `cloudflared tunnel run
  --token-file`.
- `service start` and `service restart` fail unless the existing launch-agent plist uses the
  canonical label, manager token file, and token-file command shape.
- SSH publications require a valid independently trusted Ed25519 host-key pin and machine-only
  audience. A signed-key-exchange mismatch fails readiness; it does not authorize public key scans,
  pin replacement, weaker checking, or enabling Remote Login.
- each complete manager-mutating workflow acquires one nonblocking local OS writer lock, including
  `service start`, `stop`, and `restart`; contention fails with `manager_busy` before workflow
  reads or writes. Read-only commands remain unlocked.
- ordinary mutations compare the complete supported tunnel configuration, not just a filtered
  ingress list. Foreign routes, global options, unsupported fields, or other drift are refused.
- protected HTTP and SSH rules require native per-route Access JWT validation for the app's AUD
  and organization. Public routes deliberately have no validator or Access application.

`manager.lock` survives teardown. Its presence does not establish that an operation is running;
never delete it to bypass contention or replace an inode a writer may still hold. Manifest writes
stage a mode-`0600` file beside `state.json`, then replace atomically; failed staging leaves the prior
manifest intact. These are local protections, not Cloudflare transactions or dashboard exclusion.

## One unfinished mutation

The existing manifest owns one nullable `pending` transition: operation identity, normalized
secret-free request, phase, route projection, candidate ownership, and any unknown external effect.
Completion removes it rather than accumulating a history. Repeating the same normalized request
resumes it; an incompatible mutation fails with `transition_pending`. Reads and plans remain
available. Never delete or hand-edit pending state to bypass custody.

Run `cloudflare-publish --json repair plan` before retrying uncertain work. This uses credentials
for Cloudflare reads and probes origins without managed-state mutation; temporary curl and SSH
known-host files mean it is neither offline nor strict no-file-write.

For an unknown creation outcome, take the operation and resource IDs from that plan:

```bash
cloudflare-publish repair resolve --operation OPERATION_ID --resource-id RESOURCE_ID --yes
```

The resource must match the exact saved marker and intended configuration. Resolution records
ownership and clears only that effect, not the enclosing transition. If no candidate exists, use
the alternative `repair resolve --operation OPERATION_ID --absent --yes`; it must establish absence
through a complete scoped list. Then repeat the original mutation. A blind retry can duplicate a
successful creation whose response was lost.

Service-token metadata cannot recover the secret. If the unresolved publication candidate's
created token has no recoverable secret, resolve its exact identity first if necessary, then use:

```bash
cloudflare-publish repair retire-token --operation OPERATION_ID --resource-id RESOURCE_ID --yes
```

This validates and retires only that operation's candidate token, confirms remote absence, and
leaves the original publication owned. Repeat the original publication command to create and
store its replacement. It is not a general deletion or cancellation command.

For a completed publication with a missing local token secret, explicitly run `token rotate NAME
--yes`; `publish apply` does not silently replace it. If that rotation's new secret has an unknown
outcome, plain repetition refuses with `outcome_unknown`. Inspect the plan, then authorize
`token rotate NAME --recover --yes`. That form requires the exact pending rotation and replaces
the uncertain secret; it does not retrieve the old one.

## Choose the repair owner

- Use `service status` before local connector control; `service start`, `stop`, and `restart`
  operate only launchd, not routing or credential reconciliation.
- Use `setup` or `setup --refresh-only` for owned token-file/launch-agent repair when no incompatible
  mutation is pending. Refresh can upgrade the exact owned pre-validator configuration, but
  refuses foreign configuration drift rather than overwriting it. It cannot change account,
  zone, or tunnel identity.
- Refresh and tunnel recovery reinstall the launch agent only after bounded bootout settlement.
  Do not re-run takeover after the known generic-service conflict has already been removed.
- Use `tunnel recover plan` after dashboard token rotation or shared-tunnel compromise, then the
  separately authorized `tunnel recover apply --yes`; it disconnects every shared-tunnel connector.
- Reconcile a changed SSH host-key pin through deliberate `publish apply` only after independently
  verifying the new public key. Token rotation does not change SSH identity or login keys.
- SSH login, reverse-forwarding policy, and supervision belong to their installation, not this
  publication manager. Keep tracked operations terminal-first; local overlays are not prerequisites.
- Source edits need the resolved source owner, not a functioning live manager.

## Withdrawal and teardown

Publication removal and authorization-boundary replacement persist withdrawal before changing
ingress. The effective route remains withdrawn across an interruption, so refresh cannot resurrect
it. Cleanup requires full remote configuration/version parity and exact-version application by
every observed active connector. An omitted API version may be filled only for the canonical
launchd connector through its owned loopback listener's native readiness, exact tunnel/client
identity and applied version, with process/listener/identity rechecks. This uses no proxy, port
scan or process argument, environment, token or log inspection. A reported API mismatch is never
overridden, and foreign or unobservable replicas still block. Missing, malformed, stale or
conflicting evidence keeps the transition pending. Repeat the original request after restoring
observable application; do not erase custody or disconnect all connectors to force success.

Teardown records intent, stops and confirms the local connector is unregistered, and refuses
active or unobservable remote replicas. Access remains intact until the exact tunnel is confirmed
deleted. Owned DNS, Access resources and tokens are next; credentials and local artifacts are last.
Failed deletion, Keychain cleanup, or observation retains custody for resumption.

An observed configuration version is not session drainage. Edge authorization, JWT validity, and
termination of an already open SSH/WebSocket/application session are separate. Route, policy, or
token changes do not promise immediate revocation of every issued JWT or termination of those
sessions. Confirmed tunnel deletion establishes a transport boundary, not application workload state.

## Backup semantics

Takeover backs up only the known conflict surfaces:

- `~/Library/LaunchAgents/com.cloudflare.cloudflared.plist`
- `~/.cloudflared/config.yml`
- `~/.cloudflared/cert.pem`

The product does not promise to clean every unrelated file under `~/.cloudflared/`.

## Incident reminder

`tunnel recover apply --yes` disconnects every connector on the shared tunnel. Treat it as an
explicit-impact incident command, not a quiet refresh, and run `tunnel recover plan` first.

For SSH clients, keep cloudflared at `--loglevel error` because WebSocket debug logging can expose
Access headers. A credential leak needs publication-scoped token rotation and downstream secret
replacement, not removal of the host-key pin or conversion to a public audience. Cloudflare
WebSocket disconnects can interrupt long-lived SSH; remote supervision owns reconnection and
listener settlement, not `service restart` or shared-tunnel recovery by default.
