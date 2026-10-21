# Contributing

## Canonical Commands

Run the canonical gate from repository root:

```bash
uv run devtools/gate.py
```

Local app actions, private operator notes, and workstation-specific secret recipes are ignored
operator overlays. Tracked public contracts stay terminal-first and must not require local app
configuration, user-private skill mirrors, or workstation secret tooling.

The gate runs:

- `ruff check .`
- `ruff format --check .`
- `basedpyright` over `src`, `devtools`, and the typed fake-binary test surface
- `pytest`
- `bash -n bin/cloudflare-publish`
- `./bin/cloudflare-publish --help`
- `uv run python devtools/validate_package.py`

Validate the plugin metadata and complete skill tree when the package changes:

```bash
uv run python devtools/validate_package.py
```

Install the accepted CLI explicitly, only when installation is in scope:

```bash
make install-local
```

The host owns plugin installation and removal. Do not add a global skill copier, install hook,
approval bypass, or automatic setup step. To test packaging without changing an installed consumer,
build a wheel with `uv build`, install it into an isolated tool directory, and exercise `--version`,
`--help`, and a local read from outside the checkout with an empty temporary user directory. This
checks the built CLI, not live Cloudflare or native plugin activation.

Check both distribution forms. The wheel owns the CLI runtime; `MANIFEST.in` keeps the source
distribution complete with developer contracts, native plugin manifests, skill assets, lockfile,
gate, tests, `conftest.py`, and fake-binary helpers. Extract the source distribution outside the
checkout, validate its plugin package, and exercise its tests there. Metadata inspection or tests
that accidentally import from the original checkout do not establish distribution closure.

## Dependency Lock Policy

- `uv.lock` is the canonical pinned dependency snapshot.
- `pyproject.toml` dependency ranges are the input policy, not the canonical lock state.
- When dependency reality changes, update `uv.lock` with the matching metadata instead of trying to
  treat pinned `pyproject.toml` specifiers as the source of truth.

## Public Source And Releases

[Tiziano-AI/cloudflare-publish](https://github.com/Tiziano-AI/cloudflare-publish) is the single public
development repository and complete installable plugin source. Make product changes here, not in a
private mirror or a distribution checkout. The separate `tiziano-ai` marketplace is a thin catalog
that pins reviewed source commits; it contains no copied runtime or skill tree.

Keep the MIT license, source, tests, contracts, native plugin manifests, skill assets and lockfile
together. Review the complete outgoing changes and public metadata URLs before publication. Ignoring
operator overlays, environments, credentials, state and build outputs does not make newly tracked
content safe. Do not import the earlier private development history into this public repository.

Keep the version in `pyproject.toml`, `uv.lock`, `plugin.json` and `.claude-plugin/plugin.json`
aligned. After the accepted source commit is public, update the catalog's exact source revision and
use native host operations to refresh installed plugins. CLI installation remains explicit and
separate. Package checks need no Cloudflare account and do not establish native host activation,
current provider behavior, or a first live publication.

## Icon Assets

The cloud-and-local-endpoint drawing in `skills/cloudflare-publish/assets/icon-small.svg` is original
project artwork under the root MIT license, not a Cloudflare logo or a vendor asset. It is the editable
source for `icon-large.png`. Rebuild the PNG locally with librsvg:

```bash
rsvg-convert --width 512 --height 512 \
  skills/cloudflare-publish/assets/icon-small.svg \
  --output skills/cloudflare-publish/assets/icon-large.png
```

librsvg is an optional asset-authoring tool, not a runtime or installation dependency.

## Contract Sources

Before changing operator-facing behavior, refresh from:

1. `README.md`
2. `ARCH.md`
3. `src/cloudflare_publish/cli.py`
4. the focused workflow module for the command being changed

`ARCH.md` is the canonical product contract. `README.md` is the canonical operator guidance.

## Required Surface Sync

When the operator surface, recovery semantics, or validation behavior changes, update the matching
surfaces in the same change:

- `README.md`
- `ARCH.md`
- `CONTRIBUTING.md`
- `skills/cloudflare-publish/`
- `plugin.json` and `.claude-plugin/plugin.json` (identity stays aligned with `pyproject.toml`)

At minimum, re-check:

- `SKILL.md`
- `agents/openai.yaml`
- `references/product-contract.md`
- `references/operator-recipes.md`
- `references/state-and-recovery.md`
- `references/cloudflare-api-and-permissions.md`

## Test Strategy

The default test suite is hermetic. It uses fake binaries and a fake Cloudflare API surface to
exercise:

- setup bootstrap and refresh
- manager ownership rules and takeover backups
- multi-publication routing
- mixed HTTP(S)/SSH routing and unchanged existing HTTP-manifest readability
- machine-only SSH input validation, mandatory valid Ed25519 host-key pins, and rejection of HTTP
  options or human allow rules on SSH publications
- Access app and policy creation
- machine, human, and mixed audience behavior
- tunnel recovery and connector cleanup
- service lifecycle status, start, stop, restart, log, and launch-agent denial paths
- service-token rotation
- same-request resumption and incompatible-mutation refusal through one typed pending transition
- lost creation responses, exact-operation resource resolution, complete scoped absence proof,
  candidate-token retirement, and explicit uncertain-secret rotation recovery
- native per-route Access JWT validation for protected HTTP and SSH, with app-AUD replacement on
  authorization-boundary changes
- complete tunnel-configuration comparison, including ordered ingress, global options, explicit
  benign defaults, unknown fields, and refusal to overwrite foreign drift
- persisted withdrawal and exact configuration-version observation across active replicas before
  cleanup, without route resurrection after interruption or global connector disconnection
- full remote configuration/version parity before application observation, including omitted API
  versions filled only by the canonical launchd PID-owned loopback listener's native readiness,
  tunnel/client identity and applied version; rechecked ownership and identity, API-version
  conflict refusal, and foreign, malformed or unobservable replicas retaining custody
- teardown stopping local transport and confirming exact tunnel deletion before Access cleanup,
  with active/unobservable replicas and failed cleanup retaining custody
- guard status, plan, and apply
- publication removal and full teardown
- portable/native package metadata coherence and complete skill references
- typed fake-binary helpers
- verify contract parity and failure reporting
- machine-secret handoff and secret-loss recovery
- Keychain stdin-command encoding, input bounds, secret-safe failures, and exact readback after
  writes; fake bare-`-w` writes must not pretend to consume a noninteractive password prompt
- Keychain deletion failure preserving unfinished cleanup, and native curlrc isolation
- active/full zone admission rules
- explicit-tunnel discovery allowlists, redaction, scope, pagination, and unsupported-topology reports
- deletion-tombstone metadata without obsolete configuration or token fetches, distinct from a down
  locally managed tunnel, while residual selected-zone DNS and matching Access remain visible
- presence-only Access override/constraint metadata without values or semantics, and rejection of
  additional managed-policy `require`/`exclude` constraints during parity verification
- grouped verification identities and failed on-demand origins without overstating probe evidence
- native SSH signed-key-exchange proof with strict known-host verification, no agent/private keys
  or login credentials, and distinct local-origin, anonymous HTTP denial, and authenticated public
  SSH evidence; a banner or HTTP success cannot stand in for signed SSH key exchange
- secret-safe client transport environment and forced error-level cloudflared logging
- whole-workflow writer exclusion, including service lifecycle, with read-only commands available
- restricted-permission atomic manifest replacement and preservation after failed staging

Live verification is manual and requires a real macOS workstation plus a real Cloudflare account:

```bash
bin/cloudflare-publish verify --live
```

## Change Checklist

Before calling a change done:

- keep docs, tests, and state semantics synchronized
- keep the shared tunnel config contract synchronized with verify expectations
- keep pending intent, candidate ownership, effective route, unknown effects, repair output, and
  resumable commands synchronized; do not add a second recovery store or forget command
- preserve withdrawal before route changes and configuration observation before resource cleanup
- keep native local application evidence bound to the current canonical process, owned loopback
  listener and exact tunnel/client; never let it override a reported API version or excuse an
  unobservable replica
- distinguish edge authorization, connector JWT validation, and established-session termination;
  add acceptance evidence at the boundary a claim actually reaches
- keep human and JSON verification groups synchronized, retaining flat checks and failure counts
- keep SSH proof limited to pinned transport identity, not user login, forwarding, or persistence
- keep SSH client recipes strict, machine-only, and separate from Remote Login and reverse-tunnel
  supervisor installation
- check that discovery neither fetches tunnel tokens nor emits raw vendor or credential payloads
- keep the writer lock around the complete mutation, not just the manifest save
- keep the repo skill package synchronized with the public product contract
- validate `skills/cloudflare-publish/agents/openai.yaml`
- keep `skills/cloudflare-publish/scripts/inspect-manager.sh` executable and shell-valid
- keep skill icons structurally valid
- re-run `uv run python devtools/validate_package.py`
- search for stale or retired terminology when a contract name changes

## Scope Rules

- Do not reintroduce retired-name compatibility aliases.
- Do not add wildcard or path-routing support without first changing `ARCH.md`.
- Do not add protocols beyond HTTP(S) and SSH without first defining the typed contract in `ARCH.md`.
- Do not claim interactive human auth coverage from `verify --live`.
- Do not turn a configured HTTP probe response into proof of authenticated application use.
- Do not describe Cloudflare-carried native SSH as a third-party-free tunnel, VPN, or completed
  remote-machine installation.
- Do not replace host-key pinning with trust-on-first-use or leak Access headers through debug logs.
- Do not add resource adoption, transfer commands, or a second publication lifecycle through discovery.
- Do not describe local locking or atomic manifest writes as remote transactions or dashboard exclusion.
- Do not promise instantaneous JWT revocation or established-session termination from token,
  policy, or route changes.
- Do not repeat an uncertain creation POST, recover a secret from resource metadata, or silently
  rotate a missing completed-publication credential through `publish apply`.
- Do not turn `repair resolve` into arbitrary adoption, cancellation, or forgetting pending work;
  it resolves only the saved exact effect after intent validation.
- Do not add launch-agent paths that rely on `cloudflared` older than `2025.4.0`.
