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
 */
const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().default(3200),
  LOG_LEVEL: z.string().default('info'),

  // MySQL — identity tables (users, identities, sessions, handoff codes)
  DB_HOST: z.string().default('echo-database'),
  DB_PORT: z.coerce.number().default(3306),
  DB_USER: z.string().default('echo_app'),
  DB_PASSWORD: z.string().default(''),
  DB_NAME: z.string().default('id_db'),

  // NocoDB — settings store. The instance lives at nocodb.<parent-domain>;
  // the API token is generated in the NocoDB UI (Account → Tokens).
  NOCODB_BASE_URL: z.string().url().default('http://nocodb:8080'),
  NOCODB_API_TOKEN: z.string().default(''),
  // AidaOffice is the one base every Aida project shares — NocoDB link fields
  // resolve only within a base, so a shared base is what lets these settings
  // relate to the tables other projects own. The base no longer says whose data
  // it is; NOCODB_TABLE_NAME does. Both are auto-created on first boot if the
  // token has creator rights.
  NOCODB_BASE_NAME: z.string().default('AidaOffice'),
  NOCODB_TABLE_NAME: z.string().default('oAuthConfig'),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(): AppConfig {
  return envSchema.parse(process.env);
}
