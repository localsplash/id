import { buildApp } from './app';
import { loadConfig } from './config';
import { ensureSchema } from './db';
import { drainDeliveries } from './webhooks';

async function main() {
  const config = loadConfig();
  const { app, db, settingsStore, aidaService } = buildApp();

  // Identity tables (idempotent; canonical copy lives in EchoDatabase/init).
  await ensureSchema(db);

  // Best-effort: create/seed the oAuthConfig table in NocoDB. NocoDB may
  // still be starting or the token may not exist yet — the app must come up
  // regardless so the admin can bootstrap in any order.
  try {
    await settingsStore.bootstrap();
    console.log('[settings] oAuthConfig table ready');
  } catch (err) {
    console.warn(`[settings] NocoDB bootstrap failed (will retry on demand): ${String(err)}`);
  }

  // Publish this service's public key to `aida_application` and keep
  // last_seen_at fresh. Deliberately not awaited: a NocoDB that is slow or
  // unreachable must not hold up the listener. Until it succeeds /readyz
  // reports unready with the reason, which is the honest state — the process
  // is up, peers cannot yet verify it.
  const registerTick = async () => {
    try {
      await aidaService.register();
    } catch (err) {
      console.error(`[aida] registration pass failed: ${String(err)}`);
    }
  };
  const registration = setInterval(() => void registerTick(), 60_000);
  registration.unref();
  void registerTick();

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
