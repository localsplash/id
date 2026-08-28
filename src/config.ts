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

  // Aida service-to-service authentication. The private key is the third and
  // last thing the .env has to carry beyond store coordinates: this service
  // signs its calls to other Aida services with it, and publishes the matching
  // public key to `aida_application`. It is unrelated to user sessions —
  // changing it signs nobody out (see docs/service-auth.md).
  //
  // Base64 of the PKCS#8 DER on one line. Generate with `npm run keygen`.
  // Required in production; in development an ephemeral key is generated with
  // a warning.
  AIDA_APP_PRIVATE_KEY: z.string().default(''),
  // Identity in the registry is (application_name, environment) and never a
  // hostname: hostnames change with ingress, replicas share one identity, and
  // a service reachable under two names is still one application.
  AIDA_APP_NAME: z.string().default('id'),
  AIDA_ENVIRONMENT: z.string().default(''),
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(): AppConfig {
  const config = envSchema.parse(process.env);
  // The registry environment defaults to NODE_ENV, which is the right answer
  // for development and production. A deployment with more environments than
  // Node has names — staging, say — sets AIDA_ENVIRONMENT explicitly.
  if (!config.AIDA_ENVIRONMENT) config.AIDA_ENVIRONMENT = config.NODE_ENV;
  return config;
}
