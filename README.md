# id — OAuth identity processor & redirector

`id` is the single sign-in surface for every application under one parent
domain (`X.TLD`). Applications never talk to Google, Microsoft, or the UISP
bridge themselves — they redirect the browser to `id.X.TLD`, and `id` hands
back a one-time code that resolves to the signed-in identity.

```
 ┌────────────┐  1. no session → 302   ┌────────────┐
 │ echo.X.TLD │ ─────────────────────▶ │  id.X.TLD  │──▶ Google / Microsoft /
 │ aida.X.TLD │                        │            │◀── UISP bridge plugin
 └────────────┘ ◀───────────────────── └────────────┘
       │         2. 302 back with            │
       │            one-time ?code           │ SSO cookie on .X.TLD
       │                                     ▼
       └── 3. POST /api/token ───▶ identity {user, provider, subject}
```

## Flows

**Application login.** An app with no local session sends the browser to

```
GET https://id.X.TLD/authorize?redirect_uri=https://app.X.TLD/auth/callback&state=<opaque>
```

`redirect_uri` must be an https URL whose host is the parent domain or any
subdomain of it — that is the entire client-registration model; every app
under `X.TLD` is trusted, nothing else is. If the browser already carries a
valid `id_sso` cookie (scoped to `.X.TLD`, so one login serves every app),
`id` immediately 302s back with `?code=…&state=…`. Otherwise the login page
is shown and the round trip completes after the user authenticates.

The app then redeems the code server-to-server:

```
POST https://id.X.TLD/api/token
{ "code": "…", "redirect_uri": "https://app.X.TLD/auth/callback", "client_secret": "<ID_CLIENT_SECRET>" }

→ { "user": { "iUserId", "email", "displayName", "superAdmin" },
    "identity": { "provider", "subject" },
    "identities": [ { "provider", "subject", "email" }, … ] }
```

Codes are single-use, expire in 5 minutes, and are bound to the exact
`redirect_uri` they were minted for. `ID_CLIENT_SECRET` comes from the same
NocoDB settings table every app reads.

**Sessions persist forever — until revoked.** There is no expiry. A login
ends only when the user signs out, signs out everywhere, or a Super System
Admin revokes their sessions. Applications are expected to follow the same
model for their own local sessions.

**UISP bridge.** The ISP-portal plugin (see EchoOrchestrator/uisp-plugin)
verifies the subscriber's portal session and redirects to
`/sso/callback?code&sig` with an HMAC-signed one-time payload. `id` verifies
the signature and nonce, records a `uisp` identity (subject = CRM clientId),
and completes the pending app redirect — or `DEFAULT_REDIRECT_URI` when the
user entered straight from the portal.

## Configuration

The `.env` carries **only** bootstrap plumbing: MySQL and NocoDB
coordinates (see `.env.example`). Every application-level setting lives in
the **`oAuthConfig` table** (base `id`) in NocoDB at `nocodb.X.TLD`:

| Key | Purpose |
| --- | --- |
| `PARENT_DOMAIN` | Apex domain (`X.TLD`); drives the cookie scope, redirect allowlist, and default super-admin domain |
| `APP_BASE_URL` | Public base URL of this app, e.g. `https://id.X.TLD` |
| `ID_CLIENT_SECRET` | Shared secret apps present at `/api/token` |
| `SUPERADMIN_DOMAIN` | Override for the super-admin email domain (default `PARENT_DOMAIN`) |
| `DEFAULT_REDIRECT_URI` | Where an unsolicited sign-in (e.g. from the ISP portal) lands |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT` | Microsoft Entra ID OAuth |
| `UISP_SSO_SECRET` / `UISP_PLUGIN_URL` / `UISP_BASE_URL` / `UISP_CRM_APP_KEY_READ` | UISP bridge & CRM |

On first boot `id` creates the base/table and seeds every known key with an
empty value and a description, so the menu of settings is visible without
guessing. **A login method is only offered when all of its required keys are
set** — an unconfigured provider simply does not appear on the login page.

Settings are re-read at most every 30 seconds; changes in NocoDB take
effect without a restart.

### First-run setup wizard

While no OAuth provider is configured, the instance is **unclaimed**: `/`
redirects to `/setup`, a built-in wizard that walks the first admin through
claiming it:

1. It checks the NocoDB settings store first — if `NOCODB_API_TOKEN` (or
   `NOCODB_BASE_URL`) is missing or wrong, the wizard says exactly that:
   those two must be set in the environment before anything can be saved.
2. The admin enters the parent domain (`X.TLD`) and credentials for
   **Google or Microsoft** (the wizard is limited to providers that can
   prove a domain; Microsoft additionally requires a tenant ID — `common`
   cannot prove anything).
3. The credentials are held in a short-lived cookie — *not* saved — while a
   real OAuth round trip runs against them.
4. Only if the sign-in works **and** the verified account is on the claimed
   domain does the wizard persist everything to `oAuthConfig` (also minting
   `ID_CLIENT_SECRET`), make the claimer Super System Admin, and land them
   on `/admin`. A failed or off-domain attempt saves nothing.

The wizard closes permanently the moment any provider is configured; later
changes happen in `/admin` or directly in NocoDB at `nocodb.X.TLD`.

## Super System Admin

A user is a Super System Admin when their **provider-verified** email
domain matches `SUPERADMIN_DOMAIN` (default: `PARENT_DOMAIN`). Only
providers that cryptographically vouch for the domain qualify — Google
(Workspace `hd` / verified address) does; Microsoft with a `common`
authority does not, since any tenant can claim any address. Admins can edit
`oAuthConfig`, inspect users and identities, unlink identities (never a
user's last one), and revoke sessions.

## Adding a provider

Add one `ProviderDescriptor` to `src/providers.ts` (id, label,
`requiredKeys`, `buildAuthUrl`, `fetchUserInfo`, and whether it
`verifiesEmailDomain`). Routes, the login page, config gating, and the
admin UI pick it up automatically; `provider` columns are plain VARCHARs,
so no schema change is needed.

## Storage

Identity data lives in MySQL (`id_db`; canonical schema in
`EchoDatabase/init`, and `ensureSchema()` creates it idempotently at boot):

- `id_tbl_User` — people
- `id_tbl_Identity` — login methods per user (`provider`, `subject`)
- `id_tbl_Session` — revocable, non-expiring SSO sessions
- `id_tbl_AuthCode` — one-time app handoff codes
- `id_tbl_SsoNonce` — UISP bridge replay guard

## Development

```bash
npm install
npm run dev     # tsx watch, port 3200
npm test        # vitest
npm run build   # tsc → dist/
```

The full stack (MySQL, NocoDB, this app, the Echo apps) is composed in
**EchoOrchestrator**.
