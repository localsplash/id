import { buildApp } from './app';
import { loadConfig } from './config';
import { runMigrations } from './migrations';
import { parseCidrList } from './net';
import { SETTINGS_BASE_NAME, SETTINGS_TABLE_NAME, SettingsUnavailableError } from './settings';
import { drainDeliveries } from './webhooks';

const RETRY_DELAY_MS = 5_000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  const config = loadConfig();
  const { app, db, settingsStore } = buildApp();

  /**
   * The settings store is not optional and there is no fallback: this app
   * cannot know its own database, its trusted network, or its OAuth
   * credentials without it. So the boot sequence is find-or-die — one retry
   * for the ordinary case of NocoDB still coming up beside us, then exit
   * with the reason rather than serving a instance that would answer every
   * request with a fault it cannot explain.
   */
  for (let attempt = 1; ; attempt++) {
    try {
      await settingsStore.bootstrap();
      console.log(`[settings] ${SETTINGS_BASE_NAME}.${SETTINGS_TABLE_NAME} ready`);
      // Seeded rows are empty on purpose: a table being created for the
      // first time is not where a public URL or a domain gets invented. The
      // setup wizard fills those in from the URL the first admin arrives on.
      const pinned = settingsStore.overriddenKeys();
      if (pinned.length) {
        console.log(`[settings] overridden by the environment: ${pinned.join(', ')}`);
      }
      break;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (attempt === 1) {
        console.warn(`[settings] ${message} — retrying once in ${RETRY_DELAY_MS / 1000}s`);
        await sleep(RETRY_DELAY_MS);
        continue;
      }
      console.error(`[settings] ${message}`);
      console.error(
        `[settings] Cannot start without the ${SETTINGS_BASE_NAME} base at ` +
          `${config.NOCODB_BASE_URL}. Fix NOCODB_BASE_URL / NOCODB_API_TOKEN, or create ` +
          `the base (its name must be unique), then start again.`
      );
      process.exit(1);
    }
  }

  const settings = await settingsStore.getAll();

  // Network trust is security configuration: a malformed CIDR entry, or an
  // empty trustedCIDR in a production deployment that admits callers by
  // network, must stop the process at startup rather than fail requests
  // ambiguously at runtime.
  const trusted = parseCidrList(settings.trustedCIDR ?? '');
  parseCidrList(config.IDENTITY_TRUSTED_PROXY_CIDRS);
  if (
    config.NODE_ENV === 'production' &&
    config.IDENTITY_APP_AUTH_MODE !== 'secret' &&
    trusted.length === 0
  ) {
    throw new Error(
      `IDENTITY_APP_AUTH_MODE=${config.IDENTITY_APP_AUTH_MODE} requires trustedCIDR in ` +
        `${SETTINGS_BASE_NAME}.${SETTINGS_TABLE_NAME} to name the trusted network in production`
    );
  }

  // The identity schema — this repo is the sole owner; versioned, additive,
  // recorded migrations (a second run is a no-op).
  //
  // The database coordinates are settings, so on a brand-new install they
  // may not exist yet. That is a first-run state, not a crash: the app still
  // listens, /setup collects the coordinates, and the schema is applied by
  // the ticker below (or by the wizard itself) as soon as they work.
  let schemaReady = false;
  let lastSchemaError = '';
  const ensureSchema = async (): Promise<void> => {
    if (schemaReady) return;
    try {
      const applied = await runMigrations(db);
      schemaReady = true;
      console.log(
        applied.length
          ? `[db] applied migrations: ${applied.join(', ')}`
          : '[db] schema up to date'
      );
    } catch (err) {
      // One line per distinct problem — this retries every tick.
      const message = String(err);
      if (message !== lastSchemaError) {
        lastSchemaError = message;
        console.warn(`[db] schema not applied yet: ${message}`);
      }
    }
  };
  await ensureSchema();

  // Webhook delivery ticker. Deliveries are durable rows, so this is a
  // drain loop rather than a scheduler: a restart mid-retry resumes here,
  // and a due row is picked up within one tick.
  //
  // A pass is serial and each delivery may sit on a 10s timeout, so it can
  // easily outlast the 5s interval. Without this guard the next tick would
  // pick up rows the running pass has not marked yet and send them twice.
  let draining = false;
  const tick = async () => {
    if (draining) return;
    draining = true;
    try {
      await ensureSchema();
      if (!schemaReady) return;
      await drainDeliveries(db);
    } catch (err) {
      console.error(`[webhooks] delivery pass failed: ${String(err)}`);
    } finally {
      draining = false;
    }
  };
  const ticker = setInterval(() => void tick(), 5_000);
  ticker.unref();
  void tick();

  app.listen(config.PORT, () => {
    console.log(`identity listening on :${config.PORT}`);
  });
}

main().catch((err) => {
  if (err instanceof SettingsUnavailableError) console.error(`[settings] ${err.message}`);
  else console.error(err);
  process.exit(1);
});
