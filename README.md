# id — OAuth identity processor & redirector

`id` is the single sign-in surface for every application under one parent
domain (`X.TLD`). Applications never talk to Google, Microsoft, or the UISP
bridge themselves — they redirect the browser to `identity.X.TLD`, and `id` hands
back a one-time code that resolves to the signed-in identity.

```
 ┌────────────┐  1. no session → 302   ┌──────────────────┐
 │ echo.X.TLD │ ─────────────────────▶ │ identity.X.TLD   │──▶ Google / Microsoft /
 │ aida.X.TLD │                        │                  │◀── UISP bridge plugin
 └────────────┘ ◀───────────────────── └──────────────────┘
       │         2. 302 back with            │
       │            one-time ?code           │ SSO cookie on .X.TLD
       │                                     ▼
       └── 3. POST /api/token ───▶ identity {user, provider, subject}
```

## Flows

**Application login.** An app with no local session sends the browser to

```
GET https://identity.X.TLD/authorize?redirect_uri=https://app.X.TLD/auth/callback&state=<opaque>
```

`redirect_uri` must be an https URL whose host is the parent domain or any
subdomain of it — that is the entire client-registration model; every app
under `X.TLD` is trusted, nothing else is. If the browser already carries a
valid `id_sso` cookie (scoped to `.X.TLD`, so one login serves every app),
`id` immediately 302s back with `?code=…&state=…`. Otherwise the login page
is shown and the round trip completes after the user authenticates.

The app then redeems the code server-to-server:

```
POST https://identity.X.TLD/api/token
{ "code": "…", "redirect_uri": "https://app.X.TLD/auth/callback" }

→ { "user": { "iUserId", "email", "displayName", "superAdmin" },
    "identity": { "provider", "subject" },
    "identities": [ { "provider", "subject", "email" }, … ] }
```

Codes are single-use, expire in 5 minutes, and are bound to the exact
`redirect_uri` they were minted for. No application secret is required:
the calling server is admitted by **network trust** (below). The legacy
`ID_CLIENT_SECRET` check still exists behind `ID_APP_AUTH_MODE` for the
rollout window.

`user.superAdmin` is **session-scoped and never stored on the user row**.
Its provenance is pinned by the contract: an existing SSO session's
`bSuperAdmin` is copied into the auth code at `/authorize`, and redemption
returns the consumed code's value; a fresh login computes it once and
writes the same value to both Session and AuthCode. Redemption never
recalculates privilege from the email.

## Network trust (POC: IPv4/CIDR policy)

The server-only endpoints — `POST /api/token`, `POST /api/apps/register`,
`GET /api/events`, and everything under `/api/directory/` — accept a
request only when the caller's resolved IPv4 peer is inside
`ID_TRUSTED_APP_CIDRS` (comma-separated IPv4 CIDRs; `/32` and bare
addresses accepted). Browser authorization stays public.

Resolution rules, applied deterministically:

- The **TCP socket peer** is authoritative. Real IPv6 peers are rejected
  (a kernel-reported `::ffff:a.b.c.d` dual-stack peer is normalised to
  IPv4).
- `X-Forwarded-For` is honoured **only** when the socket peer is inside
  `ID_TRUSTED_PROXY_CIDRS`, and only across trusted hops evaluated
  right-to-left; the first non-proxy hop is the client. Malformed, IPv6,
  or IPv4-mapped entries in the header are rejected outright — a spoofed
  header from an untrusted peer changes nothing.
- Denials are a generic `403 { "error": "Forbidden", "correlationId" }`;
  the log line carrying that correlation id records the resolved peer IP.
- In production, startup **fails** when `ID_APP_AUTH_MODE` needs CIDRs and
  `ID_TRUSTED_APP_CIDRS` is empty, and when any CIDR entry is malformed.

`ID_APP_AUTH_MODE` is the rollout flag: `cidr` (POC default), `secret`
(legacy `ID_CLIENT_SECRET` only), or `dual` (either accepted) for the
migration window. The directory endpoints are CIDR-only in **every** mode —
no client-secret header or body field is ever accepted there.

> **Boundary — read this before reusing the pattern.** CIDR trust
> authenticates a *server/network*, not an individual application. Every
> application egressing from an allowed IP can call the same endpoints.
> That is accepted for the first-party POC on the controlled
> LSAidaOffice01 host, and is **not** suitable for unrelated or
> customer-hosted X.TLD applications.

Enforce the same policy at the edge as well as in the app. NGINX, with
apps at `203.0.113.7` and an internal `10.9.0.0/16`:

```nginx
# Server-only API: allowlist app servers, deny the world.
location ~ ^/api/(token|apps/register|events|directory) {
    allow 203.0.113.7/32;
    allow 10.9.0.0/16;
    deny  all;
    proxy_pass http://id-web:3200;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
# Everything else (authorize, login, account, admin) stays public.
location / {
    proxy_pass http://id-web:3200;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

When NGINX fronts the app like this, put the NGINX host's IP in
`ID_TRUSTED_PROXY_CIDRS` so the app evaluates the forwarded client
address; the application-layer check then re-applies the same allowlist.
Firewall prerequisite: only the reverse proxy (and, on the controlled
host, the app servers) may reach the app port at all — the allowlist is
defence in depth, not the only wall.

For **outbound** event delivery, the receiving application's `/id/events`
endpoint applies the mirror-image policy: allowlist id's egress IPv4/CIDRs
at its ingress. TLS protects the transport; event ids and timestamps drive
idempotency and replay handling. The per-app webhook HMAC is no longer part
of the POC contract — the signature header is still sent when the app holds
a legacy secret, but verifying it is optional.

## The machine-readable contract

The versioned integration contract lives at
[`docs/openapi.json`](docs/openapi.json) (OpenAPI 3.1), with response
fixtures under [`docs/contract/fixtures/`](docs/contract/fixtures/) and a
typed TypeScript client in [`src/contractClient.ts`](src/contractClient.ts)
that compiles with the build. `npm test` validates the fixtures against the
contract and pins the POC invariants (superAdmin provenance, exact redirect
binding, single-use five-minute codes, no secret fields); CI additionally
rejects breaking contract changes on pull requests (`oasdiff`). `X.TLD` in
the contract is the configured `PARENT_DOMAIN` placeholder — `localsplash.ai`
URLs anywhere are deployment examples, never normative.

## Central user directory (CIDR-trusted, server-only)

Lets a trusted application (AidaAdmin) create, locate, and select central
users by `iUserId` without direct MySQL access or duplicate person records:

```
POST /api/directory/users            { email, displayName?, idempotencyKey? }
GET  /api/directory/users/{iUserId}
GET  /api/directory/users?query=&limit=25&cursor=
→ { iUserId, email, displayName, claimed }
```

The ensure is idempotent and concurrency-safe: repeat calls (same email,
or same `idempotencyKey`) return the same `iUserId`. A pre-created user is
`claimed: false` until a **trusted-provider** login with a matching
verified email attaches an identity — the same email-match path every
login uses — after which the person signs in holding the UID that was
handed out here. Untrusted providers can never claim a UID by asserted
email. Responses are deliberately minimal: never identities, sessions,
codes, or OAuth credentials.

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

**Zero-config is the intended path.** A fresh instance is expected at
`identity.X.TLD` and works out of the box: the `.env` carries only
bootstrap plumbing (MySQL and NocoDB coordinates — see `.env.example`), the
settings table is created empty on first boot, and the setup wizard fills
in where this service lives from the URL the first admin actually opens it
on. `identity.X.TLD` is the one assumption the code makes; nothing else
about a deployment is defaulted anywhere in the source.

Every application-level setting lives in the **`oAuthConfig` table** (base
`id`) in NocoDB at `nocodb.X.TLD`:

| Key | Purpose |
| --- | --- |
| `PARENT_DOMAIN` | Apex domain (`X.TLD`) the **apps** are served from; drives the cookie scope and redirect allowlist, and is the default super-admin domain |
| `APP_BASE_URL` | Public base URL of this app, e.g. `https://identity.X.TLD`. Normally left to the wizard — see *Where this service thinks it lives* below |
| `ID_CLIENT_SECRET` | **Legacy (rollout only)** — shared secret apps present at `/api/token` when `ID_APP_AUTH_MODE` is `secret`/`dual`; ignored in the default `cidr` mode |
| `SUPERADMIN_DOMAIN` | Domain(s) the **identity provider vouches for** whose users are Super System Admins — comma-separated list accepted (default: `PARENT_DOMAIN`) |
| `DEFAULT_REDIRECT_URI` | Where an unsolicited sign-in (e.g. from the ISP portal) lands |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT` | Microsoft Entra ID OAuth |
| `UISP_SSO_SECRET` / `UISP_PLUGIN_URL` / `UISP_BASE_URL` / `UISP_CRM_APP_KEY_READ` | UISP bridge & CRM |

On first boot `id` creates the base/table and seeds every known key with an
**empty** value and a description, so the menu of settings is visible
without guessing. Seeded rows stay empty on purpose: a database being
created for the first time is not where a public URL or a domain gets
invented. **A login method is only offered when all of its required keys
are set** — an unconfigured provider simply does not appear on the login
page.

Settings are re-read at most every 30 seconds; changes in NocoDB take
effect without a restart.

### Environment overrides

Any key in the table above may also be set in the **environment**, where it
wins over the stored row. That is the escape hatch for deployments that
manage configuration as environment (a Helm chart, a CI secret) or that
need an instance up before NocoDB exists at all — it is an override, not a
default, and the zero-config path leaves all of it unset.

An overridden key is read-only in `/admin` (tagged `env`, with a `409` on
any attempt to write it) and is never copied into the store, since a copy
would go stale the moment the environment changed. Blank counts as unset,
so an empty variable in a compose file does not shadow the store.

### Where this service thinks it lives

`APP_BASE_URL` is what the OAuth callback URIs are built from, and it is
resolved per request in this order:

1. the environment override, if there is one;
2. the `APP_BASE_URL` row in `oAuthConfig` — what the setup wizard wrote;
3. the URL the browser actually reached this service on (honouring
   `X-Forwarded-Proto` / `X-Forwarded-Host` from a reverse proxy);
4. `https://identity.<PARENT_DOMAIN>` — the naming convention, for the rare
   call with no request to observe.

Leave 1 and 2 unset and the service is simply correct about itself: it is
reachable at exactly the URL that reached it. `PARENT_DOMAIN` follows the
same convention in the wizard — this host minus its own label, so
`identity.wisp.net` proposes `wisp.net`.

### First-run setup wizard

While no OAuth provider is configured, the instance is **unclaimed**: `/`
redirects to `/setup`, a built-in wizard that walks the first admin through
claiming it:

1. It checks the NocoDB settings store first — if `NOCODB_API_TOKEN` (or
   `NOCODB_BASE_URL`) is missing or wrong, the wizard says exactly that:
   those two must be set in the environment before anything can be saved.
2. The wizard fills in this service's public URL from the browser's own
   address bar and the application domain from that host minus its label
   (`identity.wisp.net` → `wisp.net`) — both editable, neither guessed
   server-side, and both fixed and read-only when the environment pins
   them. The admin confirms the application domain (`X.TLD`) and enters
   credentials for **Google or Microsoft** (the wizard is limited to
   providers that can prove a domain; Microsoft additionally requires a
   tenant ID — `common` cannot prove anything). In production the service
   URL must be on the domain being claimed. A Super Admin domain can be given too, but it is
   optional — see below.
3. The credentials are held in a short-lived cookie — *not* saved — while a
   real OAuth round trip runs against them.
4. Only if the sign-in works **and** the verified account is on the Super
   Admin domain does the wizard persist everything to `oAuthConfig` (also
   minting `ID_CLIENT_SECRET`), make the claimer Super System Admin, and
   land them on `/admin`. A failed or off-domain attempt saves nothing.
5. If the sign-in works but the account is on a *different* domain, the
   wizard says which domain the provider actually vouched for and offers it
   as the Super Admin domain. Confirming re-runs the sign-in with that value
   in place — so the grant still rests on a fresh, matching identity, never
   on the suggestion.

The wizard closes permanently the moment any provider is configured; later
changes happen in `/admin` or directly in NocoDB at `nocodb.X.TLD`.

## Super System Admin

A user is a Super System Admin when their **provider-verified** email
domain is one of `SUPERADMIN_DOMAIN` (default: `PARENT_DOMAIN`). Only
providers that cryptographically vouch for the domain qualify — Google
(Workspace `hd` / verified address) does; Microsoft only when the app is
locked to a single tenant, since with a `common` authority any directory
could assert any address. Admins can edit `oAuthConfig`, inspect users and
identities, unlink identities (never a user's last one), and revoke
sessions.

### When the app domain and the identity domain differ

`PARENT_DOMAIN` and `SUPERADMIN_DOMAIN` answer two different questions —
where the apps live, and where the people come from — and they are
routinely not the same string.

The everyday case is a **Google Workspace domain alias**. With apps at
`*.example.ai` and a Workspace whose *primary* domain is `example.com`,
`example.ai` being an alias, every sign-in comes back as
`user@example.com` with `hd=example.com`. Google asserts the primary domain
and never the alias — signing in as `user@example.ai` resolves to the same
account and still yields the primary in the token. There is no runtime
signal that ties the two domains together (the alias list is only readable
through an admin-scoped Directory API call, which an external consent
screen cannot ask for), so the relationship is **declared, not detected**:

```
PARENT_DOMAIN      = example.ai      # cookie scope, redirect allowlist
SUPERADMIN_DOMAIN  = example.com     # what Google actually vouches for
```

The setup wizard reaches this configuration for you — it reports the domain
the provider vouched for and offers it — but it is one line to set by hand
too.

The list form covers a later move from alias to **secondary domain**, where
some users hold genuine `@example.ai` primaries and arrive with
`hd=example.ai`: set `SUPERADMIN_DOMAIN = example.com, example.ai` and both
populations qualify, with no migration.

## Integrating an application

Each app's session is its own — id's session and the app's are separate
rows behind separate cookies. That is what makes the app fast (no round
trip per request), and it is also why an app has to be *told* when a login
is revoked: without that, revoking at id only stops **new** sign-ins while
the person stays logged into every app they already reached.

Apps therefore implement one endpoint. There is no polling and no cron.

### 1. Register on boot

```http
POST /api/apps/register
Content-Type: application/json

{ "name": "EchoWeb",
  "webhook_url": "https://app.X.TLD/id/events" }
```

```json
{ "ok": true, "origin": "https://app.X.TLD", "secret": "…",
  "events": ["ping", "session.revoked", "user.merged", "identity.linked", "identity.unlinked"],
  "signature": { "header": "X-Id-Signature", "required": false } }
```

The call is admitted by network trust (the app server's IP), like every
server-only endpoint. `webhook_url` must be https and under
`PARENT_DOMAIN` — the same rule as a `redirect_uri`. The returned `secret`
is the **legacy** delivery-signing key: deliveries still carry a signature
when the app holds one, but verifying it is optional in the POC — the
receiving endpoint's own IP allowlist plus TLS is the trust story. id
immediately queues a `ping` so a broken endpoint shows up now rather than
at the first real revocation.

### 2. Receive events

```http
POST /id/events
X-Id-Event: session.revoked
X-Id-Event-Id: 1234
X-Id-Timestamp: 1774500000
X-Id-Signature: sha256=<hex>

{ "id": 1234, "type": "session.revoked", "occurredAt": "2026-08-26T06:00:00.000Z",
  "data": { "iUserId": 7, "scope": "all" } }
```

A receiver **must**:

- allowlist id's egress IPv4/CIDRs at its ingress (the POC trust model —
  TLS protects the transport);
- be **idempotent**, deduplicating on the event `id` — failures are
  retried, so the same event id can arrive more than once;
- answer **2xx only once the event is durably handled**. Anything else, or a
  timeout past 10s, counts as a failure.

A receiver **may** additionally verify the legacy `X-Id-Signature` header
(`HMAC-SHA256(secret, "<X-Id-Timestamp>.<rawBody>")` over the **raw** body,
constant-time compare, timestamp within **300s**) — optional in the POC.

Retries back off at 0s, 30s, 2m, 10m, 1h, 6h and are then abandoned and
shown in the dashboard.

| Event | `data` | What the app should do |
| --- | --- | --- |
| `ping` | `{ origin }` | Nothing; answer 2xx |
| `session.revoked` | `{ iUserId, scope: 'all' \| 'one', sessionId? }` | End its own sessions for that id user |
| `user.merged` | `{ fromUserId, toUserId }` | Repoint its local mapping from `fromUserId` to `toUserId`, end sessions for the retired user |
| `identity.linked` / `identity.unlinked` | `{ iUserId, provider, subject }` | Usually nothing; apps that bind on a specific identity (EchoWeb binds an org by UISP `clientId`) may care |

### 3. Catch up at boot

Retries cover a brief outage; an app down longer than the schedule would
still have a hole. Read forward once at startup from the last event id it
processed:

```http
GET /api/events?since=1234
```

(Admitted by network trust, like every server-only call.) Combined with
idempotent handlers, that closes the gap without a timer.

### Reference verification

```ts
import crypto from 'crypto';

function verify(secret: string, rawBody: string, headers: Record<string, string>): boolean {
  const ts = Number(headers['x-id-timestamp']);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false;
  const expected = crypto.createHmac('sha256', secret)
    .update(`${ts}.${rawBody}`).digest('hex');
  const got = (headers['x-id-signature'] ?? '').replace(/^sha256=/, '');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(got, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

### Watching the integrations

`/admin` lists every application and derives a status:

- **listening** — registered, deliveries succeeding
- **registered, unverified** — registered, nothing delivered successfully yet
- **not listening** — registered, deliveries failing; revocations are *not*
  reaching it
- **not integrated** — the app redeems handoff codes but never registered a
  webhook at all

That last one needs no configuration to detect: id records the origin of
every app that redeems a code at `/api/token`, so an app that does login but
skipped the receiver announces itself by working. Each row shows the last
handoff, last delivery, queue depth, last error, and a **Send test event**
button.

## Remapping identities between users

One person can end up as two id users — they came through the ISP bridge
first and later signed in with Google, or a provider that does not vouch
for its addresses could not be auto-linked. `/admin` → **Merge into…** folds
one into the other: login methods move, the retired user's sessions are
revoked, and `user.merged` goes out so every app repoints its own mapping
instead of stranding rows against a user id that no longer exists.

## Adding a provider

Add one `ProviderDescriptor` to `src/providers.ts` (id, label,
`requiredKeys`, `buildAuthUrl`, `fetchUserInfo`, and whether it
`verifiesEmailDomain`). Routes, the login page, config gating, and the
admin UI pick it up automatically; `provider` columns are plain VARCHARs,
so no schema change is needed.

## Storage

Identity data lives in MySQL (`id_db`) — the shared platform identity
database on **LSAidaOffice01** — and **this repository is its sole schema
owner**. There is no external schema source: `EchoDatabase/init` is not
used and must not be. `id_db.id_tbl_User.iUserId` is the platform-wide
person id; tenant, role, extension, and prompt data belong to the
applications (e.g. Aida UID mappings in NocoDB), never as columns here.

- `id_tbl_User` — people
- `id_tbl_Identity` — login methods per user (`provider`, `subject`)
- `id_tbl_Session` — revocable, non-expiring SSO sessions
- `id_tbl_AuthCode` — one-time app handoff codes
- `id_tbl_App` / `id_tbl_Event` / `id_tbl_Delivery` — app registry & events
- `id_tbl_SsoNonce` — UISP bridge replay guard
- `id_tbl_DirectoryKey` — directory-ensure idempotency keys
- `id_tbl_Migration` — applied-migration history

### Migrations

The schema is applied at boot by `src/migrations.ts`: an ordered,
append-only list of named, **additive** migrations, each recorded in
`id_tbl_Migration`. A fresh database gets everything; an existing one gets
only what it has not seen; a second run is a no-op; concurrent boots are
serialised by an advisory lock. The baseline migration is written as
`CREATE TABLE IF NOT EXISTS`, so a database created by an earlier
deployment adopts the history without touching existing rows — existing
users keep their `iUserId` and keep authenticating.

To change the schema, append a new named migration; never edit, rename, or
reorder a released one.

**Local vs production.** `docker-compose.yml` / `.env.example` describe a
disposable local MySQL for development and tests. Production is the shared
`id_db` on LSAidaOffice01 (`DB_HOST` pointing at that MySQL) — treat it as
live data at all times.

**Backup / restore / rollback (production).** Take a consistent dump
before every deploy that includes a new migration:

```bash
mysqldump --single-transaction --routines id_db > id_db-$(date +%F).sql   # backup
mysql id_db < id_db-<date>.sql                                            # restore
```

Because migrations are additive, rolling back the *app* to a previous
version is always safe (older code ignores newer tables/columns). Rolling
back the *schema* means restoring the dump taken before the deploy —
accept the data written in between as lost, which is why the dump comes
first.

## Development

```bash
npm install
npm run dev     # tsx watch, port 3200
npm test        # vitest
npm run build   # tsc → dist/
```

The full stack (MySQL, NocoDB, this app, the Echo apps) is composed in
**EchoOrchestrator**.
