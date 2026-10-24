# cloudflare-publish

This repository is the source of `cloudflare-publish`, a macOS and Linux operator CLI that publishes
HTTP, HTTPS, or machine-authenticated native SSH services already running on that host through one
Cloudflare Tunnel, and of the
`cloudflare-publish` agent skill that teaches its operation.

## The product and where it is described

One manager per host/user profile owns one Cloudflare account, one active full (not partial or
CNAME) DNS zone, one distinct remotely managed tunnel, one native user `cloudflared` connector and many
exact-hostname HTTP(S) or SSH publications. HTTP supports the `human`, `machine`, `mixed`, and
origin-authenticated `public` audiences; SSH supports only `machine`, with a mandatory independently
trusted Ed25519 host-key pin. Protected audiences use Cloudflare Access; `public` has no Access at
all. Wildcards, path routing, protocols other than HTTP(S) and SSH,
private-network routes, IdP setup and multi-account or multi-zone management are outside the
contract, and adding any of them starts with a change to `ARCH.md`. Setup stays fail-closed on any
zone that is not `active` and `full`, because the product writes the zone's DNS records directly.
Independent hosts never share a tunnel identity by copying credentials or state. The connector runs
with `--token-file`, so every service path keeps requiring `cloudflared`
`2025.4.0` or later.

- `ARCH.md` owns the product and CLI contract: command ownership, local paths, typed state,
  publication, verification and organization contracts, setup/recover/teardown sequences and the
  fail-closed rules.
- `README.md` owns operator guidance: installation, API-token shape, commands and troubleshooting.
- `CONTRIBUTING.md` lists what the gate runs, the test strategy, the dependency-lock policy, and the
  surfaces to re-check when behavior changes.
- `skills/cloudflare-publish/` is the single native plugin skill source.
- `plugin.json` and `.claude-plugin/plugin.json` own package identity; keep name, version and license
  aligned with `pyproject.toml`.
- Put durable product decisions in their owning contract or manual. Save a continuation note only
  for unfinished work that needs one, and remove it when resolved; do not retain completed-work
  journals or empty handoff placeholders.

macOS manager state lives outside the repository, in
`~/Library/Application Support/cloudflare-publish/` (`state.json`, `tunnel-token.txt`, takeover
`backups/`, persistent `manager.lock`), `~/Library/Logs/cloudflare-publish/` and the launch agent
`com.cloudflare-publish.cloudflared`.

Linux uses `~/.local/state/cloudflare-publish/` for state, persistent lock, token,
`credentials/`, and `logs/`, plus `~/.config/systemd/user/cloudflare-publish.service`.
It requires systemd 240+, a working user bus, and operator-arranged `Linger=yes`. Never invoke sudo,
enable lingering, auto-install Linux dependencies, adopt legacy ownership, or create system services.
The Linux secret store uses current-UID mode-0700 directories and mode-0600 regular single-link files,
no-follow opens, atomic replacement and exact readback. It is not encryption at rest or protection
from root/the same UID. `*_keychain_account` manifest fields are opaque platform-store references.
Linux admission is OS/systemd based; ARM64/DGX is the candidate's deployment target, not live
hardware qualification or an architecture restriction. The operator supplies matching binaries.

## Source layout

- `src/cloudflare_publish/cli_parser.py` owns command syntax. `cli.py` dispatches to
  `cli_read_commands.py` and `cli_write_commands.py`, and focused `*_flow.py` modules own workflow
  behavior. The dispatch filenames do not classify effects: the read module also runs
  `service start`, `stop` and `restart`, and the write module also handles the read-only `publish`,
  `rm`, `guard` and `tunnel recover` plan forms and `guard status`. Judge a command's effect by its
  exact subcommand and workflow.
- `cli_output.py` owns the JSON envelope and its output classes.
- `state.py` owns the typed local manifest. Cloudflare, HTTP, native user-service, and secret-store
  adapters keep vendor/process details behind their contracts; macOS uses launchd/Keychain, while
  Linux uses systemd user services/private files. Keep OS selection out of shared workflows.
- API-token resolution is in `cli_auth.py` and `workflow_support.py`, private-dotenv ingress in
  `local_secrets.py`, and the setup environment fallbacks in `cli_write_commands.py`, resolved
  through `cli_shared.py`.
- Native SSH publication shares the existing lifecycle and connector. Origin and live verification
  prove signed OpenSSH key exchange against the configured host-key pin, without SSH login
  credentials; do not substitute an HTTP response, TCP connect, or banner for that proof. Enabling
  Remote Login, authorizing SSH users/keys, and installing reverse-tunnel supervision are separate
  effects outside publication ownership. Keep `cloudflared access ssh --loglevel error` so debug
  WebSocket logging cannot expose Access headers.
- Every manager-mutating workflow, including connector start/stop/restart, holds one nonblocking OS
  advisory writer lock before workflow reads or effects. Contention is `manager_busy`; reads and
  plan forms stay unlocked. Never unlink the persistent lock, including during teardown. Manifest
  writes stage mode `0600` in the same directory and atomically replace only after a successful
  write. Neither mechanism supplies remote transactions or excludes dashboard writers.

## Working in the source

- Run Python tooling only through `uv`; `uv sync --group dev` installs the Python dev tools.
  Install the official npm-based basedpyright locally with `npm ci --include=dev`, using npm 11 or
  later and Node 24.22.1+ on the 24.x line or 26.12.1+ on the 26.x line. `devEngines` rejects older
  runtimes before install or typecheck; `.npmrc` disables dependency lifecycle scripts and optional
  packages. Do not restore the Python basedpyright package: it selects a separately bundled Node
  runtime instead of the developer's patched Node.
- `uv run devtools/gate.py` is the gate: ruff lint and format check, basedpyright, pytest, the
  wrapper's syntax and `--help`, plugin validation, and shellcheck and shfmt when installed. The
  typecheck invokes the repository-local npm binary, with no download, global fallback or bootstrap.
  A repo or skill change is incomplete until it passes.
- The test suite is hermetic: it runs fake `curl`, `cloudflared`, `ssh`, `launchctl`, `security` and
  `brew` and Linux user-service tools against a fake Cloudflare API in a temporary `HOME`.
  A green gate therefore says
  nothing about live Cloudflare behavior, the installed command or native plugin activation. When
  either is part of the task, check the host's selected plugin and the installed CLI separately.
  The read-only commands
  (`doctor`, `verify`, `repair plan`) make no Cloudflare or managed-state
  writes, so neither they nor the gate show that a live write works; report which of them actually
  ran. Live verification is manual on the publishing host and account:
  `bin/cloudflare-publish verify --live`.
  Linux additionally needs real user-service ownership/readback, logout/reboot persistence,
  secret-permission, connector-listener evidence, and intended-client HTTPS/WSS negative and
  authenticated acceptance. Hermetic tests do not establish any of these live outcomes.
- A contract change starts in `ARCH.md` and stays synchronized, in the same change, across
  `README.md`, `CONTRIBUTING.md`, runtime code, tests and the skill package. A CLI contract change
  updates `ARCH.md`, `README.md` and the skill package before runtime code. `CONTRIBUTING.md`'s
  Required Surface Sync and Change Checklist name the files to re-check.
- Explaining the product or changing its source needs no installed CLI, credentials or manager
  inspection, so do not install or run `doctor` to prepare that work.
  `skills/cloudflare-publish/references/source-and-discovery.md` separates source ownership,
  installed-command discovery and the live evidence a particular claim needs.

## Entry points and installation

- The installed PATH-global `cloudflare-publish` console script is the operator entrypoint.
  `bin/cloudflare-publish` is the development wrapper: it runs `uv run python -m cloudflare_publish`
  from the repository root, so it needs `uv` on `PATH` and runs the working tree, not the installed
  command.
- `make install-local` reinstalls only the CLI with `uv tool install --reinstall .`. Run it only
  when installation is in scope. The host separately owns plugin installation, discovery and
  removal; there is no global skill copier, install hook, timer, watcher or unattended sync.
- `make validate-package` checks the source package offline. After a CLI installation, smoke-test
  from outside the checkout with `command -v cloudflare-publish`, `cloudflare-publish --version`
  and `cloudflare-publish --help`. Add `cloudflare-publish --json doctor` only when auth and manager
  readiness are in scope; it may contact Cloudflare.

## Skill package

- `skills/cloudflare-publish/` is the only skill source. It deliberately lives outside
  `.agents/skills`: Codex loads repository skills from `.agents/skills` as well as user skills from
  `$HOME/.agents/skills` and does not merge packages with the same name, so a copy there would
  expose a duplicate. Do not install a second global skill beside the native plugin.
- The package is a portable skill-only plugin. `devtools/validate_package.py`, which the gate
  runs, checks identity coherence, skill file/link closure, scripts, icons and private workstation
  dependencies. It does not prove host activation or live operations. Review routing changes
  against `devtools/skill-review-scenarios.md`.
- Workstation paths and secret configuration belong to machine configuration, not to the package.
  Removing the plugin or CLI must not implicitly retire infrastructure or erase recovery state;
  README.md's Upgrade And Removal section owns the operator sequence.

## Public development and private operator overlays

The canonical public development repository is
[Tiziano-AI/cloudflare-publish](https://github.com/Tiziano-AI/cloudflare-publish). Develop the CLI and
plugin together here. The `tiziano-ai` marketplace pins reviewed revisions from this same complete
source; there is no private development mirror, snapshot-copy release workflow, or second engine.
Do not import the earlier private development history or operator material into the public
repository. Review the actual outgoing commits before any authorized public push. Source publication,
installed CLI selection, native plugin installation and loaded guidance remain distinct claims;
check the consumer relevant to the work. Do not reintroduce retired command aliases.

Tracked docs, tests, the gate and the skill stay
terminal-first and must not require local app configuration, user-private skill mirrors or
workstation secret tooling. Workstation recipes, private notes and app actions belong in ignored
overlays (`.codex/` and `.claude/` are gitignored); the Codex app's local environment, when present,
lives in `.codex/environments/` and calls `bin/cloudflare-publish`. `ARCH.md`'s Local Operator
Overlay Contract owns this boundary.

## Diagnostics reach Cloudflare

- `cloudflare-publish --json doctor` reports that diagnostics completed, not that the manager is
  ready: exit zero and `ok: true` can accompany `data.ready: false`, so read `data.ready` and
  `data.checks`. It resolves the API token (environment, private dotenv or platform secret store)
  and, when one is found, calls Cloudflare's account API, so it is not an offline source probe.
- `verify` is the readiness command and exits nonzero on failing checks; with `--json` the error
  envelope keeps `data.checks`, `data.failures`, and `data.groups`. Its typed groups are `manager`,
  `routing`, `origin`, `access`, and `public_probe`, and publication-specific checks carry name and
  hostname. `cli_read_commands.py` and `cli_output.py` own these semantics. Unavailable on-demand
  origins fail readiness; matching 404/405 probes do not prove application authentication or use.
- `verify` without `--live` and `repair plan` also read credentials, query Cloudflare and probe
  origins, and every HTTP request writes temporary curl files (`http.py`), GETs included. They
  change no managed state but are neither offline nor filesystem-pure, so do not run them under
  no-network, no-credential-access or strict no-file-write constraints. `--live` adds
  public-hostname audience checks, including requests with the current service token for `machine`
  and `mixed`; it never performs an interactive human login.
- `discover tunnel ID --account-id ACCOUNT --zone-id ZONE` is bounded, typed remote inspection,
  not ownership transfer. Keep outputs allowlisted, credential-free, explicit about unsupported
  topology and coverage, and independent of local-manager identity. It never fetches a tunnel token.

## Writes and secrets

- Run a live Cloudflare write only when the person explicitly asks for that operation, and use the
  `plan` form first where one exists for uncertain publication, removal, guard or recovery work.
- These command forms need explicit authorization and, where shown, the confirmation flag: `setup`,
  `setup --refresh-only`, `setup --takeover --yes`, `publish apply ... --yes`,
  `rm apply NAME --yes`, `token rotate NAME --yes`, `guard apply --yes`,
  `tunnel recover apply --yes`, `repair resolve ... --yes`,
  `repair retire-token ... --yes` and `teardown --yes`. Explicit unknown-rotation recovery is
  `token rotate NAME --recover --yes`; it reissues the same owned token, not a new resource.
- Treat `tunnel recover apply --yes` as shared-tunnel incident recovery: it disconnects every
  connector on the managed tunnel, including unmanaged replicas. Independent hosts must use distinct tunnels.
- `service start`, `service stop` and `service restart` change nothing in Cloudflare, but they load,
  unload or restart the native user connector through which this host serves every publication:
  macOS stop uses `launchctl bootout`; Linux stop disables the unit and confirms inactivity.
  This host stops serving all of them. Run them only when the person asks; `service status` and
  `service logs` only read.
- `--audience public` is only for an origin with its own fail-closed request authentication. It
  deliberately owns no Access application, policy or service token; never use it to make an
  otherwise unauthenticated service public.
- SSH publication requires `--audience machine` and `--ssh-host-key`; never learn the host-key pin
  from the new untrusted public route or disable strict checking to bypass a mismatch. Cloudflare
  is still the outer transport and availability dependency, not a third-party-free route.
- Account-level unmatched-request protection (what the `guard` commands manage: Zero Trust
  `deny_unmatched_requests`, which `ARCH.md` calls require-protection) blocks every hostname without
  a matching Access application, and a `public` publication deliberately has none. Do not enable it
  while a managed `public` publication exists unless the configured zone is already in
  `deny_unmatched_requests_exempted_zone_names`. `guard plan` and `guard apply` refuse that case,
  and `guard status` names the affected publications.
- Service-token secrets leave the product only through `publish apply` for `machine` and `mixed`
  publications and through `token rotate` (the `credential_handoff` output class). `inspect` and
  every other command stay secret-free; keep it that way.
- Keep Cloudflare API tokens and Access service-token secrets out of chat, reusable docs, process
  arguments and tracked dotenv files, and never ask the person to paste one into chat. Persistent
  credentials live in the platform store described above. Bootstrap input comes from the
  interactive setup prompt, a short-lived `CLOUDFLARE_API_TOKEN`, or a private dotenv named by an absolute
  `CLOUDFLARE_PUBLISH_DOTENV` path outside this repository (a regular file with mode `0600`); the
  CLI reads no other dotenv. `--api-token` exists for local emergencies and tests.

## Recovery

- Start uncertain repair work with `cloudflare-publish repair plan`, which changes no managed state.
- Linux unit retirement retains `.cloudflare-publish.service.retiring` beside the unit until native
  reload and absence are confirmed. Resume `teardown --yes`; never delete custody or run setup
  over it. Exact local cleanup preserves unknown entries and the persistent writer lock.
- `setup` refresh repairs tunnel-token-file and native user-service drift. It accepts only the exact
  owned guarded configuration or its exact legacy guard-stripped form; foreign config drift is
  not overwritten. It cannot change the manager's account, zone or tunnel identity.
- Pending intent in `state.json` owns unfinished mutations. Resume only the exact original
  request; resolve unknown creations by exact operation/resource identity or proven scoped absence
  before resuming. Never clear pending custody manually or blindly repeat an uncertain POST.
- Missing secrets on existing machine tokens require explicit `token rotate NAME --yes`, never
  implicit publish rotation. A resumed routing change may complete without credential handoff;
  its error must retain `publication_applied: true`. A newly created candidate token with no stored
  secret remains pending and requires exact `repair retire-token` before publication resumes.
- After a dashboard tunnel-token rotation or a shared-tunnel incident, run `tunnel recover plan`
  before the confirmed apply. Connector `service restart` is not a substitute: `service` commands
  own only the local native user-service process and its logs and reconcile nothing in Cloudflare.
  The product never rotates the remote tunnel token itself; that happens in the dashboard first.
- On macOS, preserve takeover backups under the product's Application Support tree. Takeover touches
  only the legacy `com.cloudflare.cloudflared` launch agent, `~/.cloudflared/config.yml` and
  `~/.cloudflared/cert.pem`; keep it scoped to those. Do not manually adopt same-name tunnels, DNS
  records or Access applications that local state does not own.
