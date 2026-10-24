# State And Recovery

## First inspection

For local manager diagnosis, run the [inspection script](../scripts/inspect-manager.sh) from the
resolved skill package directory:

```bash
scripts/inspect-manager.sh
```

The inspection script is read-only. It locates the CLI, prints `cloudflared` version, and reads the
host's native user-service and file/log metadata. On Linux it uses allowlisted `systemctl --user`
properties and reports lingering, never raw `status`, unit contents, process arguments or environment.
An optional standalone `python3` on PATH enables allowlisted macOS plist and common state
summaries, including pending kind/phase. On macOS, the script skips Apple's `/usr/bin/python3`
developer-tools shim (including symlinks); Linux system Python remains eligible. It preflights the
selected interpreter and falls back to metadata-only diagnosis if parsing is unavailable. No Python
or developer-tools installation is required; the
uv-installed CLI can work independently of PATH Python. With parsing, it reports inline-token or
environment presence without printing their contents, and does not read the tunnel-token file.
It does not call Cloudflare write APIs, change
native service state, mutate local manager files, or print secret values. Do not replace it with a raw
plist/unit dump: noncanonical files can contain inline credentials.

Manual macOS inspection commands:

```bash
command -v cloudflare-publish || true
cloudflared --version
launchctl list | grep com.cloudflare-publish.cloudflared || true
ls -la "$HOME/Library/Application Support/cloudflare-publish"
```

Manual Linux inspection commands:

```bash
systemctl --user show cloudflare-publish.service \
  --property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID
loginctl show-user "$(id -u)" --property=Linger --value
ls -ld "$HOME/.local/state/cloudflare-publish" \
  "$HOME/.config/systemd/user/cloudflare-publish.service"
```

Add `cloudflare-publish --json doctor` when auth/Cloudflare readiness matters; it resolves
credentials and may query the account API. Local artifacts alone cannot prove those facts.
If the CLI is not on `PATH`, local diagnosis can continue through runtime artifacts. Source work
instead needs the source owner, not a working manager; see Source And Discovery.

## Canonical local state

macOS:

- state manifest: `~/Library/Application Support/cloudflare-publish/state.json`
- persistent writer lock: `~/Library/Application Support/cloudflare-publish/manager.lock`
- tunnel token file: `~/Library/Application Support/cloudflare-publish/tunnel-token.txt`
- takeover backups: `~/Library/Application Support/cloudflare-publish/backups/<timestamp>/`
- launch agent: `~/Library/LaunchAgents/com.cloudflare-publish.cloudflared.plist`
- logs:
  - `~/Library/Logs/cloudflare-publish/cloudflared.out.log`
  - `~/Library/Logs/cloudflare-publish/cloudflared.err.log`

Linux:

- state manifest, persistent lock and runtime token:
  `~/.local/state/cloudflare-publish/{state.json,manager.lock,tunnel-token.txt}`
- private secret files: `~/.local/state/cloudflare-publish/credentials/`
- native user unit: `~/.config/systemd/user/cloudflare-publish.service`
- logs: `~/.local/state/cloudflare-publish/logs/{cloudflared.out.log,cloudflared.err.log}`

The Linux private store requires current-UID mode-0700 directories and mode-0600 regular single-link
files, no-follow opens, private atomic replacement and exact readback. It is not encryption at rest
or protection from root/the same UID. Never print values or copy another host's credentials/state.
The old `*_keychain_account` manifest names are opaque references to the selected platform store.

## Fail-closed rules

- On macOS, `setup` stops unless `--takeover` is explicit when the generic launch agent or
  `~/.cloudflared` conflict surfaces exist; the command also requires `--yes`.
- Linux rejects legacy/system-wide takeover. A host operator resolves conflicts independently;
  the product never invokes sudo, installs packages/system units, or enables lingering. Setup
  requires systemd 240+, a working user bus and `Linger=yes` before remote creation.
- manager bootstrap does not silently adopt a same-name remote tunnel. New remote resources carry
  operation-specific creation markers; logical publication/tunnel names are not enough to prove
  ownership.
- `publish apply` fails when a hostname is already owned by another managed publication or by an
  unmanaged remote DNS record.
- `setup` fails unless the chosen zone is `active` and `full`.
- `setup --refresh-only` fails before platform-tool checks unless local manager state already exists.
- `setup`, `service start`, `service restart`, `tunnel recover apply`, and native service repair paths
  require `cloudflared` `2025.4.0` or later because the product uses `cloudflared tunnel run
  --token-file`.
- `service start` and `service restart` fail unless the existing native service file uses the
  canonical identity, manager token file, absolute binary and token-file command shape.
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
  operate only the native user service, not routing or credential reconciliation. Linux start
  enables the unit; stop disables it and confirms inactivity. Teardown removes only its owned unit.
- Use `setup` or `setup --refresh-only` for owned token-file/native-service repair when no incompatible
  mutation is pending. Refresh can upgrade the exact owned pre-validator configuration, but
  refuses foreign configuration drift rather than overwriting it. It cannot change account,
  zone, or tunnel identity.
- Refresh and tunnel recovery reinstall the native service only after confirmed stop settlement.
  On macOS, do not re-run takeover after the known generic-service conflict has already been removed.
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
native user connector through its owned loopback listener's native readiness, exact tunnel/client
identity and applied version, with process/listener/identity rechecks. This uses no proxy, port
scan or process argument, environment, token or log inspection. A reported API mismatch is never
overridden, and foreign or unobservable replicas still block. Missing, malformed, stale or
conflicting evidence keeps the transition pending. Repeat the original request after restoring
observable application; do not erase custody or disconnect all connectors to force success.

Teardown records intent, stops and confirms the local connector is unregistered, and refuses
active or unobservable remote replicas. Access remains intact until the exact tunnel is confirmed
deleted. Owned DNS, Access resources and tokens are next; credentials and local artifacts are last.
Failed deletion, platform-secret cleanup, or observation retains custody for resumption.

Linux unit retirement atomically moves the exact owned inactive/disabled definition to
`~/.config/systemd/user/.cloudflare-publish.service.retiring` before reloading the user manager.
That file remains until native not-found/inactive/disabled/PID-zero evidence is confirmed. Resume
`teardown --yes` after interruption; it revalidates retained bytes and any cached definition, and
can finish local cleanup after the API credential is gone. Setup/start refuse incomplete retirement.
Never delete custody, adopt a foreign replacement, or treat a missing canonical file alone as proof
of native removal. Linux cleanup preserves unknown state entries, takeover backups and the
persistent lock; it removes only exact owned token/log artifacts and empty directories.

An observed configuration version is not session drainage. Edge authorization, JWT validity, and
termination of an already open SSH/WebSocket/application session are separate. Route, policy, or
token changes do not promise immediate revocation of every issued JWT or termination of those
sessions. Confirmed tunnel deletion establishes a transport boundary, not application workload state.

## Backup semantics

macOS takeover backs up only the known conflict surfaces:

- `~/Library/LaunchAgents/com.cloudflare.cloudflared.plist`
- `~/.cloudflared/config.yml`
- `~/.cloudflared/cert.pem`

The product does not promise to clean every unrelated file under `~/.cloudflared/`.
Linux does not offer takeover or create these backups.

## Incident reminder

`tunnel recover apply --yes` disconnects every connector on the shared tunnel. Treat it as an
explicit-impact incident command, not a quiet refresh, and run `tunnel recover plan` first.

For SSH clients, keep cloudflared at `--loglevel error` because WebSocket debug logging can expose
Access headers. A credential leak needs publication-scoped token rotation and downstream secret
replacement, not removal of the host-key pin or conversion to a public audience. Cloudflare
WebSocket disconnects can interrupt long-lived SSH; remote supervision owns reconnection and
listener settlement, not `service restart` or shared-tunnel recovery by default.
