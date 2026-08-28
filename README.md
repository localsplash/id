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
coordinates, plus `AIDA_APP_PRIVATE_KEY` (see `.env.example` and
[docs/service-auth.md](docs/service-auth.md)). Every application-level setting lives in
the **`oAuthConfig` table** in NocoDB at `nocodb.X.TLD`:

| Key | Purpose |
| --- | --- |
| `PARENT_DOMAIN` | Apex domain (`X.TLD`) the **apps** are served from; drives the cookie scope and redirect allowlist, and is the default super-admin domain |
| `APP_BASE_URL` | Public base URL of this app, e.g. `https://id.X.TLD` |
| `ID_CLIENT_SECRET` | Shared secret apps present at `/api/token` |
| `SUPERADMIN_DOMAIN` | Domain(s) the **identity provider vouches for** whose users are Super System Admins — comma-separated list accepted (default: `PARENT_DOMAIN`) |
| `DEFAULT_REDIRECT_URI` | Where an unsolicited sign-in (e.g. from the ISP portal) lands |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT` | Microsoft Entra ID OAuth |
| `UISP_SSO_SECRET` / `UISP_PLUGIN_URL` / `UISP_BASE_URL` / `UISP_CRM_APP_KEY_READ` | UISP bridge & CRM |

That table lives in **`AidaOffice`**, the one base every Aida project shares.
NocoDB link fields resolve only within a base, so sharing one is what lets these
settings relate to the tables the other projects own — AidaControl's tenant
tables, AidaAdmin's `appConfig`. The base no longer says whose data it is; the
table title does, and `oAuthConfig` is this project's.

On first boot `id` creates the base and table and seeds every known key with an
empty value and a description, so the menu of settings is visible without
guessing. Creating the base logs a warning: on a first boot that is expected,
but anywhere else it means `NOCODB_BASE_NAME` is wrong and this service is about
to write settings into a base nothing else reads. **A login method is only offered when all of its required keys are
set** — an unconfigured provider simply does not appear on the login page.

Settings are re-read at most every 30 seconds; changes in NocoDB take
effect without a restart.

## Service-to-service authentication

Other Aida services authenticate to `id` — and `id` to them — with Ed25519
signatures rather than shared secrets. Each application publishes its public
key to `aida_application` in the same shared base, so N services need N
published keys rather than N² pasted secrets, and the registry holds nothing
secret at rest.

The private key is `AIDA_APP_PRIVATE_KEY`, base64 of the PKCS#8 DER on one
line. Generate one with `npm run keygen`. **It is required in production** —
the process refuses to start without it rather than improvising a key that
would leave this service callable by nobody. In development an ephemeral key
is generated with a warning.

**Changing the service key signs nobody out.** A user session is 32 random
bytes in `id_tbl_Session`, checked by row lookup; nothing about it is derived
from or verified against this key. Rotation is an ordinary config change.

`GET /readyz` answers whether peers can actually call this service — separate
from `/healthz`, which only says the process is up. When it is unhappy it
names the failure category and the NocoDB row to open, so an incident starts
with one HTTP call rather than a log dive. `GET /internal/v1/whoami` is the
conformance target for a peer checking its own signing.

The full contract — headers, canonical signing string, verification order,
rotation, and the registry schema — is in
[docs/service-auth.md](docs/service-auth.md). The design settled the algorithm
and key encoding but not the wire format, so this service defines it and is
its first implementation; a peer that follows that page will interoperate.

### First-run setup wizard

While no OAuth provider is configured, the instance is **unclaimed**: `/`
redirects to `/setup`, a built-in wizard that walks the first admin through
claiming it:

1. It checks the NocoDB settings store first — if `NOCODB_API_TOKEN` (or
   `NOCODB_BASE_URL`) is missing or wrong, the wizard says exactly that:
   those two must be set in the environment before anything can be saved.
2. The admin enters the application domain (`X.TLD`) and credentials for
   **Google or Microsoft** (the wizard is limited to providers that can
   prove a domain; Microsoft additionally requires a tenant ID — `common`
   cannot prove anything). A Super Admin domain can be given too, but it is
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

{ "client_secret": "<ID_CLIENT_SECRET>",
  "name": "EchoWeb",
  "webhook_url": "https://app.X.TLD/id/events" }
```

```json
{ "ok": true, "origin": "https://app.X.TLD", "secret": "…",
  "events": ["ping", "session.revoked", "user.merged", "identity.linked", "identity.unlinked"] }
```

`webhook_url` must be https and under `PARENT_DOMAIN` — the same rule as a
`redirect_uri`. The returned `secret` signs deliveries to this app; it is
minted once and returned on every registration, so hold it in memory rather
than configuring it. id immediately queues a `ping` so a broken endpoint
shows up now rather than at the first real revocation.

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

- verify `X-Id-Signature` as `HMAC-SHA256(secret, "<X-Id-Timestamp>.<rawBody>")`
  against the **raw** body — not a re-serialised object;
- compare in constant time;
- reject a timestamp more than **300s** from now (the timestamp is inside
  the MAC, so this is what stops a captured delivery being replayed);
- be **idempotent** — failures are retried, so the same event id can arrive
  more than once;
- answer **2xx only once the event is durably handled**. Anything else, or a
  timeout past 10s, counts as a failure.

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
X-Id-Client-Secret: <ID_CLIENT_SECRET>
```

Combined with idempotent handlers, that closes the gap without a timer.

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
