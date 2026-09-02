import { z } from 'zod';

/**
 * Environment configuration — two things and the process's own knobs.
 *
 * A deployment states only how to reach the settings store:
 *
 *   NOCODB_BASE_URL     where the settings live
 *   NOCODB_API_TOKEN    how to read them
 *
 * Everything else — the MySQL coordinates, the trusted network, the public
 * URL, provider credentials — is a row in the `auth_tbl_Settings` table of
 * the `IdentityBase` base (see settings.ts). The base and table are named by
 * convention, not configured, and the base ID is detected from that name at
 * runtime; a base ID in a config file is exactly the coupling the convention
 * exists to remove.
 *
 * Any of those rows may still be pinned in the environment:
 * `settingOverridesFromEnv()` reads every KNOWN_SETTINGS key (and the
 * environment-shaped aliases beside them) straight from process.env and
 * gives it precedence over the store. That is an override for deployments
 * that manage configuration as environment, not a default — nothing here
 * invents a value for something the deployment has not stated.
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
  //   cidr   — caller's IPv4 peer must be inside the trustedCIDR network
  //            (POC default; no client secret required)
  //   secret — legacy IDENTITY_CLIENT_SECRET shared-secret check only
  //   dual   — either is accepted (rollout/migration window)
  //
  // The network itself is NOT here: `trustedCIDR` is one setting for the
  // whole platform, read from IdentityBase → auth_tbl_Settings so every
  // application spells the same network the same way. The environment may
  // still pin it as IDENTITY_TRUSTED_NETWORK (see ENV_ALIASES).
  IDENTITY_APP_AUTH_MODE: z.enum(['cidr', 'secret', 'dual']).default('cidr'),
  /** @deprecated Pre-rollout name for IDENTITY_APP_AUTH_MODE; still honoured. */
  ID_APP_AUTH_MODE: z.enum(['cidr', 'secret', 'dual']).optional(),
  // Comma-separated IPv4 CIDRs of reverse proxies directly connected to this
  // app. X-Forwarded-For is honoured only when the socket peer is in here.
  // Empty (the default) means applications reach this service directly.
  IDENTITY_TRUSTED_PROXY_CIDRS: z.string().default(''),
  /** @deprecated Pre-rollout name; still honoured. */
  ID_TRUSTED_PROXY_CIDRS: z.string().default(''),

  // NocoDB — the settings store. The instance lives at
  // nocodb.<parent-domain>; the API token is generated in the NocoDB UI
  // (Account → Tokens). No default: an invented address would only fail
  // later, and less clearly, than saying it is unset.
  NOCODB_BASE_URL: z.string().default(''),
  NOCODB_API_TOKEN: z.string().default(''),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const config = envSchema.parse(env);
  return {
    ...config,
    // One spelling each, under whichever name the deployment used. The
    // canonical name wins when it is actually present — zod's default would
    // otherwise look identical to a deliberate 'cidr'.
    IDENTITY_APP_AUTH_MODE:
      env.IDENTITY_APP_AUTH_MODE || !config.ID_APP_AUTH_MODE
        ? config.IDENTITY_APP_AUTH_MODE
        : config.ID_APP_AUTH_MODE,
    IDENTITY_TRUSTED_PROXY_CIDRS:
      config.IDENTITY_TRUSTED_PROXY_CIDRS || config.ID_TRUSTED_PROXY_CIDRS,
  };
}
