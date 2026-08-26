import { buildApp } from './app';
import { loadConfig } from './config';
import { ensureSchema } from './db';

async function main() {
  const config = loadConfig();
  const { app, db, settingsStore } = buildApp();

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

  app.listen(config.PORT, () => {
    console.log(`id listening on :${config.PORT}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
