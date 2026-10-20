# Cloudflare API And Permissions

Use this reference when setup fails on token visibility, organization access, tunnel creation, or
uncertain remote-resource ownership, or when a dashboard tunnel-token rotation requires product
recovery.

## Official grounding

- remote tunnel setup:
  `https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel-api/`
- run parameters and `--token-file` minimum version:
  `https://developers.cloudflare.com/tunnel/advanced/run-parameters/`
- tunnel token handling and connection cleanup:
  `https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/`
- require Access protection:
  `https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/require-access-protection/`
- Access apps:
  `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/`
- native SSH through client-side cloudflared:
  `https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-cloudflared-authentication/`
- non-HTTP WebSocket transport and disconnect limitations:
  `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/cloudflared-authentication/`
- API token permissions:
  `https://developers.cloudflare.com/fundamentals/api/reference/permissions/`
- [organization GET permissions](https://developers.cloudflare.com/api/resources/zero_trust/subresources/organizations/methods/list/)
- [organization PUT permissions and service-token authentication behavior](https://developers.cloudflare.com/api/python/resources/zero_trust/subresources/organizations/methods/update/)

## Scoped token shape

Account permissions:

- `Account Settings: Read`
- `Cloudflare Tunnel: Edit`
- `Access: Service Tokens: Edit`
- `Access: Organizations, Identity Providers, and Groups: Edit`
- `Access: Apps and Policies: Edit`

Zone permissions:

- `Zone: Zone: Read`
- `DNS: Edit`

Resource scope:

- the target account
- the target zone

The organization GET accepts the Access organization Read or Write permission; its PUT accepts
`Access: Organizations, Identity Providers, and Groups Write` (shown as Edit in the dashboard).
The product's guard update uses that endpoint, not Gateway. These documented endpoints do not
require an additional broad `Zero Trust Edit` grant. Permission labels can differ between the
dashboard and API; preserve the selected account/zone resource scopes rather than broadening them
to make a failed probe pass. Endpoint documentation is the permission contract, not evidence that
a particular token has been tested successfully.

## Probe sequence

Use the product CLI first. The public discovery surface is typed and paginates internally; it does
not expose vendor envelopes. Do not ask the user to paste token values into chat. Prefer the setup
prompt, Keychain-backed manager state, a strict private dotenv pointed at by
`CLOUDFLARE_PUBLISH_DOTENV`, or a short-lived local `CLOUDFLARE_API_TOKEN` environment for
secret-bearing investigation. The product never reads master secret pools or follows private dotenv
symlinks.

### 1. Can the token see the account?

```bash
cloudflare-publish --json discover accounts
```

### 2. Can the token see the zone?

```bash
cloudflare-publish --json discover zone "$CLOUDFLARE_ZONE" \
  --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

The zone must belong to the same Cloudflare account the manager will use for the shared tunnel and
Access application.
The zone must also be `active` and `full`. Partial (`CNAME`) zones require external DNS management
and are not compatible with this product.
For nested hostnames such as `app.dev.example.com`, confirm Cloudflare edge certificate coverage
separately. The Tunnel API guide calls for an Advanced Certificate for multi-level subdomains;
the CLI does not order one or replace an operator's valid custom-certificate arrangement.

### 3. Can the token reach the Zero Trust organization?

```bash
cloudflare-publish --json discover organization --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

### 4. Can the token create a remote tunnel?

This is a remote write probe and is outside the read-only discovery surface. Use `setup` for the
product-owned create path after explicit authorization. If setup remains blocked after typed
discovery, treat raw vendor probing as a separate Cloudflare-operator task with explicit scope and
write authorization.

Do not create throwaway tunnels from this skill package.

### 5. Is an uncertain tunnel creation blocking setup?

```bash
cloudflare-publish --json repair plan
cloudflare-publish --json discover tunnels --account-id "$CLOUDFLARE_ACCOUNT_ID"
```

Initial setup persists its operation before remote creation and names the remote tunnel with the
logical tunnel name plus that operation ID. Publication resources likewise use operation-specific
markers. A logical-name match alone does not establish ownership, and a resource ID cannot recover
a lost secret. If a create response was lost, follow the repair plan's exact-resource resolution
or complete scoped absence proof before repeating the original command; see
[State And Recovery](state-and-recovery.md#one-unfinished-mutation).

For unrelated unmanaged objects, `discover tunnel ID --account-id ACCOUNT --zone-id ZONE` provides
sanitized ingress, matching DNS/Access, and topology/coverage findings, not credentials or all
application dependencies. Do not adopt or delete them as a setup workaround. Any exact-resource
cleanup outside pending recovery belongs to a separately authorized Cloudflare operator task.

## Tunnel token recovery runbook

The product does not rotate remote tunnel tokens for you. For compromised or dashboard-rotated
tokens:

1. rotate the token in the Cloudflare dashboard
2. run `cloudflare-publish tunnel recover plan`
3. inspect the planned shared-tunnel connector blast radius
4. run `cloudflare-publish tunnel recover apply --yes`

`tunnel recover apply` fetches the new token, rewrites the local token file, restarts the local
connector, and deletes all shared-tunnel connectors through the API.

## Version requirement

The product requires `cloudflared` `2025.4.0` or later because it runs the connector with
`cloudflared tunnel run --token-file`.

## Operator rules

- Prefer the CLI first.
- Use these probes when setup or recovery is blocked, or a requested live account/permission
  claim needs confirmation. Product explanation and source work do not require vendor probing.
- Do not ask the user to paste the API token into chat.
- Prefer user-run terminal commands for secret-bearing probes.
- SSH reuses self-hosted Access apps with the specific service-token `non_identity` policy; it
  does not need a separate Access for Infrastructure or browser-rendered SSH product.
- Preserve `service_auth_401_redirect: true`, which requests HTTP 401 on Service Auth denial,
  despite its name. Native public probing first requires that flag, exact machine-only policy
  parity, and anonymous HTTP 401/403. A login redirect fails SSH preflight, rather than invoking a
  browser. The separate account-wide `strict_service_token_auth` setting is not changed by this
  product. Cloudflare documents it as mandatory for organizations created on or after October 5,
  2026: service-token denial returns 401/403 rather than redirecting, and successful requests do
  not return a `CF_Authorization` cookie. Do not use cookie issuance as proof of service-token
  success or try to disable the account setting as a workaround. The app flag and the native
  connector JWT validator remain distinct contracts; use the product's live probe for the actual
  hostname/transport outcome.
- Client service-token values belong in `TUNNEL_SERVICE_TOKEN_ID` and
  `TUNNEL_SERVICE_TOKEN_SECRET` environment variables, not flags. Force cloudflared SSH transport
  logging to error level; debug WebSocket headers can reveal those credentials.
