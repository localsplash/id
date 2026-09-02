import { z } from 'zod';

/**
 * Environment configuration — deliberately minimal.
 *
 * The .env carries only what is needed to reach the two stores (MySQL for
 * identity data, NocoDB for settings). Every application-level setting —
 * OAuth client credentials, UISP integration, public URLs — lives in the
 * NocoDB `oAuthConfig` table (see settings.ts) so it can be changed at
 * runtime without redeploying, and so every app under the parent domain
 * reads the same values.
 *
 * Those settings are not listed in the schema below, but any of them may
 * still be set in the environment: `settingOverridesFromEnv()` in
 * settings.ts reads every KNOWN_SETTINGS key straight from process.env and
 * gives it precedence over the store. That is an override for deployments
 * that pin configuration, not a default — nothing here invents a value for
 * a setting the deployment has not stated.
 *
 * APP_BASE_URL in particular needs no answer here or in the store: left
 * unset, the public base URL is the URL the browser actually reached this
 * service on (app.ts), and the setup wizard persists exactly that. The one
 * assumption the code makes about it is the naming convention
 * identity.X.TLD (web.ts).
 */
const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().default(3200),
  LOG_LEVEL: z.string().default('info'),

  // MySQL — id_db, the shared platform identity database this repo owns
  // (schema is created/upgraded by this app's own migrations at boot).
  DB_HOST: z.string().default('id-database'),
  DB_PORT: z.coerce.number().default(3306),
  DB_USER: z.string().default('echo_app'),
  DB_PASSWORD: z.string().default(''),
  DB_NAME: z.string().default('id_db'),

  // ── Server-to-server trust (POC: IPv4/CIDR network policy) ────────────
  // How applications authenticate to the server-only endpoints
  // (/api/token, /api/apps/register, /api/events, /api/directory/*):
  //   cidr   — caller's IPv4 peer must be inside ID_TRUSTED_APP_CIDRS
  //            (POC default; no client secret required)
  //   secret — legacy ID_CLIENT_SECRET shared-secret check only
  //   dual   — either is accepted (rollout/migration window)
  ID_APP_AUTH_MODE: z.enum(['cidr', 'secret', 'dual']).default('cidr'),
  // Comma-separated IPv4 CIDRs (/32 allowed, bare IPs treated as /32)
  // naming the application servers allowed to call server-only endpoints.
  ID_TRUSTED_APP_CIDRS: z.string().default(''),
  // Comma-separated IPv4 CIDRs of reverse proxies directly connected to
  // id. X-Forwarded-For is honoured only when the socket peer is in here.
  ID_TRUSTED_PROXY_CIDRS: z.string().default(''),

  // NocoDB — settings store. The instance lives at nocodb.<parent-domain>;
  // the API token is generated in the NocoDB UI (Account → Tokens).
  NOCODB_BASE_URL: z.string().url().default('http://nocodb:8080'),
  NOCODB_API_TOKEN: z.string().default(''),
  // Base (project) and table the settings live in. Auto-created on first
  // boot if the token has creator rights.
  NOCODB_BASE_NAME: z.string().default('id'),
  NOCODB_TABLE_NAME: z.string().default('oAuthConfig'),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(): AppConfig {
  return envSchema.parse(process.env);
}
