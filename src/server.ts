import { buildApp } from './app';
import { loadConfig } from './config';
import { runMigrations } from './migrations';
import { parseCidrList } from './net';
import { drainDeliveries } from './webhooks';

async function main() {
  const config = loadConfig();

  // Network trust is security configuration: a malformed CIDR entry or an
  // empty allowlist in a CIDR-mode production deployment must stop the
  // process at startup, not fail requests ambiguously at runtime.
  const appCidrs = parseCidrList(config.ID_TRUSTED_NETWORK);
  parseCidrList(config.ID_TRUSTED_PROXY_CIDRS);
  if (
    config.NODE_ENV === 'production' &&
    config.ID_APP_AUTH_MODE !== 'secret' &&
    appCidrs.length === 0
  ) {
    throw new Error(
      `ID_APP_AUTH_MODE=${config.ID_APP_AUTH_MODE} requires ID_TRUSTED_NETWORK ` +
        'to name the trusted network in production'
    );
  }

  const { app, db, settingsStore } = buildApp();

  // Best-effort: create/seed the oAuthConfig table in NocoDB. NocoDB may
  // still be starting or the token may not exist yet — the app must come up
  // regardless so the admin can bootstrap in any order.
  try {
    await settingsStore.bootstrap();
    console.log('[settings] oAuthConfig table ready');
    // Seeded rows are empty on purpose: a table being created for the first
    // time is not where a public URL or a domain gets invented. The setup
    // wizard fills those in from the URL the first admin arrives on.
    const pinned = settingsStore.overriddenKeys();
    if (pinned.length) {
      console.log(`[settings] overridden by the environment: ${pinned.join(', ')}`);
    }
  } catch (err) {
    console.warn(`[settings] NocoDB bootstrap failed (will retry on demand): ${String(err)}`);
  }

  // id_db schema — this repo is the sole owner; versioned, additive,
  // recorded migrations (a second run is a no-op).
  //
  // The database coordinates are settings, so on a brand-new install they
  // may not exist yet. That is a first-run state, not a crash: the app
  // still listens, /setup says which store is missing, and the schema is
  // applied by the ticker below as soon as the coordinates work.
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
    console.log(`id listening on :${config.PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
