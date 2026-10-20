# Mental Model

`cloudflare-publish` publishes running local origins. It does not deploy code into Cloudflare
compute.

## Resource model

- one macOS user profile
- one Cloudflare account
- one active full Cloudflare-managed DNS zone
- one shared remotely managed Cloudflare Tunnel
- many exact-hostname HTTP, HTTPS, or machine-authenticated SSH publications
- zero or one Cloudflare Access application plus policies per publication
- zero or one publication-scoped service token per publication

## Publication path

1. a local HTTP, HTTPS, or already configured SSH service runs on this Mac
2. `cloudflare-publish` binds that origin to one exact hostname on the shared tunnel
3. the product creates or updates the Cloudflare DNS record and audience-specific Access resources
   for that hostname
4. clients reach the hostname through Access or the origin's own fail-closed authentication, then
   the shared tunnel reaches the local origin. Protected HTTP and SSH routes also validate the
   matching application's Access JWT in the connector; public routes deliberately do not.

## First success

The first useful win is not "Cloudflare was configured." The win is: a local service still runs on
`127.0.0.1`, but the intended client can reach one exact Cloudflare hostname and the selected
audience contract succeeds. Protected audiences deny anonymous traffic through Access; `public`
reaches an origin that rejects invalid requests through its own protocol.

Typical loops:

- local model or API server -> one machine-only hostname -> service-token client succeeds
- local SSH server -> one machine-only hostname -> native signed SSH key exchange matches the
  independently trusted Ed25519 host-key pin; actual SSH user login is a separate check
- local web demo, dashboard, or docs site -> one browser hostname -> Access login is required
- local app with both browser and API clients -> one mixed hostname -> service token works and human
  login still gets a browser check
- provider callback with request signatures -> one public hostname -> no Access resources and the
  unsigned verification request reaches the origin's denial
- existing publication looks stale -> `doctor`, `inspect`, `verify`, or `repair plan` identifies the
  safest next terminal command
- a completed publication's machine credential is lost -> explicit `token rotate NAME --yes`
  replaces it; publication reconciliation does not silently rotate it

## What this product is not

- not Workers deployment
- not Pages deployment
- not a generic Cloudflare architecture guide
- not wildcard or path-based routing
- not private-network, VPN, general TCP/UDP, or non-HTTP(S)/SSH publication management
- not an SSH server installer or reverse-tunnel supervisor

## Requests that should trigger this skill

- publish a local web demo on one hostname
- expose a local API behind Access
- give this Mac's existing SSH server a stable hostname with machine authentication and host-key pinning
- verify or repair the local manager state
- rotate one publication service token
- recover after tunnel-token drift or connector compromise

## Requests that should not trigger this skill

- choose a Cloudflare hosting stack
- design Workers, Pages, D1, R2, or Vectorize architecture
- publish a service that does not already run locally

## SSH trust and reachability

An SSH hostname follows the Mac's outbound connector rather than its changing public IP. No
inbound port forwarding or dynamic DNS is needed, but the Mac must stay awake and connected.
Cloudflare carries the transport and remains a third party and availability dependency. Strictly
pinned native SSH keeps its inner contents encrypted end-to-end; the Access token authorizes the
outer transport and is not an SSH login key. WebSocket transport can disconnect. Separate remote
installation owns login keys, bounded reverse forwarding, and supervision; none is implied by
publishing this Mac's hostname.

## Interrupted changes

The manifest retains one unfinished mutation, not a second workflow engine or an operation history.
`repair plan` shows what is known, which route is effective, and the safe next action. Repeat the
same request to resume; never blindly repeat an uncertain creation or delete pending state. Saved
withdrawal prevents refresh from recreating a route whose removal is unfinished. Token secret loss
during candidate creation or rotation has a separate explicit recovery path in
[State And Recovery](state-and-recovery.md).

Routing changes, Access policy changes, JWT validity, and existing connections have different
boundaries. Route retirement does not promise immediate JWT revocation or terminate an already
established SSH, WebSocket, or application session.
