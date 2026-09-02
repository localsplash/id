import { z } from 'zod';

/**
 * Environment configuration — three things and the process's own knobs.
 *
 * A deployment is expected to state only how to reach the settings store
 * and which network is trusted:
 *
 *   NOCODB_BASE_URL       where the settings store lives
 *   NOCODB_API_TOKEN      the token to read it with
 *   ID_TRUSTED_NETWORK    the one IPv4 CIDR the platform's servers sit on
 *
 * Everything else — the MySQL coordinates included — is a row in the
 * `oAuthConfig` table (see settings.ts), so a deployment is described in
 * one place rather than split between a file on a host and a table.
 *
 * Any of those rows may still be pinned in the environment:
 * `settingOverridesFromEnv()` reads every KNOWN_SETTINGS key straight from
 * process.env and gives it precedence over the store. That is an override
 * for deployments that manage configuration as environment, not a default —
 * nothing here invents a value for something the deployment has not stated.
 *
 * APP_BASE_URL in particular needs no answer anywhere: left unset, the
 * public base URL is the URL the browser actually reached this service on
 * (app.ts), and the setup wizard persists exactly that. The one assumption
 * the code makes about it is the naming convention identity.X.TLD (web.ts).
 */
const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().default(3200),
  LOG_LEVEL: z.string().default('info'),

  // ── Server-to-server trust (POC: IPv4/CIDR network policy) ────────────
  // How applications authenticate to the server-only endpoints
  // (/api/token, /api/apps/register, /api/events, /api/directory/*):
  //   cidr   — caller's IPv4 peer must be inside the trusted network
  //            (POC default; no client secret required)
  //   secret — legacy ID_CLIENT_SECRET shared-secret check only
  //   dual   — either is accepted (rollout/migration window)
  ID_APP_AUTH_MODE: z.enum(['cidr', 'secret', 'dual']).default('cidr'),
  // The network the platform's servers sit on, as one IPv4 CIDR (/32
  // allowed, a bare IP treated as /32). It describes a network, not an
  // application: every first-party app calling from inside it is trusted,
  // and nothing outside it is. A comma-separated list is still parsed, for
  // the deployment whose servers genuinely straddle two ranges.
  ID_TRUSTED_NETWORK: z.string().default(''),
  /** @deprecated Pre-rollout name for ID_TRUSTED_NETWORK; still honoured. */
  ID_TRUSTED_APP_CIDRS: z.string().default(''),
  // Comma-separated IPv4 CIDRs of reverse proxies directly connected to
  // id. X-Forwarded-For is honoured only when the socket peer is in here.
  // Empty (the default) means apps reach this service directly.
  ID_TRUSTED_PROXY_CIDRS: z.string().default(''),

  // NocoDB — the settings store. The instance lives at
  // nocodb.<parent-domain>; the API token is generated in the NocoDB UI
  // (Account → Tokens). No default: an invented address would only fail
  // later, and less clearly, than saying it is unset.
  NOCODB_BASE_URL: z.string().default(''),
  NOCODB_API_TOKEN: z.string().default(''),
  // The base (project) and table the settings live in — this app's own
  // object names rather than a deployment's choice. Auto-created on first
  // boot if the token has creator rights.
  NOCODB_BASE_NAME: z.string().default('id'),
  NOCODB_TABLE_NAME: z.string().default('oAuthConfig'),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(): AppConfig {
  const config = envSchema.parse(process.env);
  // One trusted network, under whichever name the deployment used.
  return {
    ...config,
    ID_TRUSTED_NETWORK: config.ID_TRUSTED_NETWORK || config.ID_TRUSTED_APP_CIDRS,
  };
}
