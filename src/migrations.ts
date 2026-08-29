import mysql from 'mysql2/promise';

/**
 * id_db schema migrations — this repository is the sole schema owner.
 *
 * The schema is applied as an ordered list of named, additive migrations.
 * Each applied migration is recorded in id_tbl_Migration, so the history
 * is deterministic: a fresh database runs everything, an existing one runs
 * only what it has not seen, and a second run is a no-op. Migrations must
 * stay additive and idempotent — they run against live data.
 *
 * There is no external schema source: EchoDatabase/init is NOT consulted
 * and must not be. Local/dev MySQL remains disposable (docker-compose).
 */

export interface Migration {
  name: string;
  run(conn: mysql.PoolConnection): Promise<void>;
}

/**
 * The baseline is the schema as it existed when this repo took ownership.
 * Every statement is CREATE TABLE IF NOT EXISTS, so a database created by
 * an earlier deployment records the baseline as applied without change and
 * keeps all data.
 */
async function baseline(conn: mysql.PoolConnection): Promise<void> {
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_User (
      iUserId     BIGINT AUTO_INCREMENT PRIMARY KEY,
      email       VARCHAR(255) NULL,
      displayName VARCHAR(255) NULL,
      dtCreated   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      dtLastLogin DATETIME(3) NULL,
      INDEX idx_email (email)
    ) ENGINE=InnoDB
  `);
  // provider is VARCHAR, not ENUM — new providers must not need DDL.
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_Identity (
      iIdentityId BIGINT AUTO_INCREMENT PRIMARY KEY,
      iUserId     BIGINT NOT NULL,
      provider    VARCHAR(32)  NOT NULL,
      subject     VARCHAR(255) NOT NULL,
      email       VARCHAR(255) NULL,
      dtCreated   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      UNIQUE INDEX uq_provider_subject (provider, subject),
      CONSTRAINT fk_id_identity_user
        FOREIGN KEY (iUserId) REFERENCES id_tbl_User(iUserId) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);
  // Sessions never expire — they end only when revoked (logout or admin).
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_Session (
      sSessionId   CHAR(64) PRIMARY KEY,
      iUserId      BIGINT NOT NULL,
      bSuperAdmin  TINYINT(1) NOT NULL DEFAULT 0,
      sProvider    VARCHAR(32) NULL,
      sSubject     VARCHAR(255) NULL,
      dtCreated    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      dtLastSeen   DATETIME(3) NULL,
      dtRevoked    DATETIME(3) NULL,
      INDEX idx_session_user (iUserId),
      CONSTRAINT fk_id_session_user
        FOREIGN KEY (iUserId) REFERENCES id_tbl_User(iUserId) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);
  // One-time handoff codes minted by /authorize, redeemed at /api/token.
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_AuthCode (
      sCode        CHAR(64) PRIMARY KEY,
      iUserId      BIGINT NOT NULL,
      sRedirectUri VARCHAR(1024) NOT NULL,
      sProvider    VARCHAR(32) NULL,
      sSubject     VARCHAR(255) NULL,
      bSuperAdmin  TINYINT(1) NOT NULL DEFAULT 0,
      dtExpires    DATETIME(3) NOT NULL,
      dtConsumed   DATETIME(3) NULL,
      dtCreated    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      INDEX idx_code_expires (dtExpires),
      CONSTRAINT fk_id_code_user
        FOREIGN KEY (iUserId) REFERENCES id_tbl_User(iUserId) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);
  // Applications under the parent domain.
  //
  // A row appears one of two ways: the app self-registers its webhook
  // endpoint (dtRegistered set), or id notices it redeeming handoff codes
  // and records the origin on its own (dtDiscovered only). The second is
  // what lets the dashboard say "this app is live but is not listening for
  // revocations" without anyone having to maintain a list by hand.
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_App (
      sOrigin              VARCHAR(255) PRIMARY KEY,
      sName                VARCHAR(128) NULL,
      sWebhookUrl          VARCHAR(1024) NULL,
      sSecret              CHAR(64) NULL,
      dtDiscovered         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      dtRegistered         DATETIME(3) NULL,
      dtLastTokenExchange  DATETIME(3) NULL,
      dtLastDeliveryOk     DATETIME(3) NULL,
      dtLastDeliveryFail   DATETIME(3) NULL,
      sLastError           VARCHAR(512) NULL,
      iConsecutiveFailures INT NOT NULL DEFAULT 0
    ) ENGINE=InnoDB
  `);
  // Events are durable and ordered: an app that was down catches up from
  // iEventId on its next boot rather than silently missing a revocation.
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_Event (
      iEventId  BIGINT AUTO_INCREMENT PRIMARY KEY,
      sType     VARCHAR(64) NOT NULL,
      jsonData  JSON NOT NULL,
      dtCreated DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      INDEX idx_event_created (dtCreated)
    ) ENGINE=InnoDB
  `);
  // One delivery row per (event, app), retried with backoff by the ticker in
  // server.ts. Durable so a restart mid-retry does not drop the event.
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_Delivery (
      iDeliveryId   BIGINT AUTO_INCREMENT PRIMARY KEY,
      iEventId      BIGINT NOT NULL,
      sOrigin       VARCHAR(255) NOT NULL,
      iAttempts     INT NOT NULL DEFAULT 0,
      dtNextAttempt DATETIME(3) NULL,
      dtDelivered   DATETIME(3) NULL,
      dtAbandoned   DATETIME(3) NULL,
      sLastError    VARCHAR(512) NULL,
      dtCreated     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      UNIQUE INDEX uq_event_app (iEventId, sOrigin),
      INDEX idx_delivery_due (dtNextAttempt),
      CONSTRAINT fk_delivery_event
        FOREIGN KEY (iEventId) REFERENCES id_tbl_Event(iEventId) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);
  // Single-use nonces from the UISP bridge (replay guard).
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_SsoNonce (
      sNonce    CHAR(32) PRIMARY KEY,
      dtExpires DATETIME(3) NOT NULL,
      dtCreated DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      INDEX idx_nonce_expires (dtExpires)
    ) ENGINE=InnoDB
  `);
}

/**
 * Idempotency keys for the directory ensure endpoint: one row per
 * (idempotencyKey), pointing at the user the first call produced, so a
 * retried POST returns the same iUserId instead of racing.
 */
async function directoryIdempotency(conn: mysql.PoolConnection): Promise<void> {
  await conn.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_DirectoryKey (
      sIdempotencyKey VARCHAR(128) PRIMARY KEY,
      iUserId         BIGINT NOT NULL,
      dtCreated       DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      CONSTRAINT fk_id_dirkey_user
        FOREIGN KEY (iUserId) REFERENCES id_tbl_User(iUserId) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);
}

/** Ordered, append-only. Never rename or reorder an entry once released. */
export const MIGRATIONS: Migration[] = [
  { name: '0001_baseline', run: baseline },
  { name: '0002_directory_idempotency', run: directoryIdempotency },
];

const MIGRATION_LOCK = 'id_db_migrations';

/**
 * Apply every pending migration, in order, exactly once — safe under
 * concurrent boots (advisory lock) and safe to re-run (applied names are
 * recorded and skipped). Returns the names applied in this run.
 */
export async function runMigrations(pool: mysql.Pool): Promise<string[]> {
  const conn = await pool.getConnection();
  const applied: string[] = [];
  try {
    const [lockRows] = await conn.query<mysql.RowDataPacket[]>(
      `SELECT GET_LOCK(?, 60) AS locked`,
      [MIGRATION_LOCK]
    );
    if (Number(lockRows[0]?.locked) !== 1) {
      throw new Error('Could not acquire the id_db migration lock');
    }
    try {
      await conn.query(`
        CREATE TABLE IF NOT EXISTS id_tbl_Migration (
          sName     VARCHAR(128) PRIMARY KEY,
          dtApplied DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
        ) ENGINE=InnoDB
      `);
      const [rows] = await conn.query<mysql.RowDataPacket[]>(
        `SELECT sName FROM id_tbl_Migration`
      );
      const done = new Set(rows.map((r) => r.sName as string));
      for (const migration of MIGRATIONS) {
        if (done.has(migration.name)) continue;
        await migration.run(conn);
        await conn.query(`INSERT INTO id_tbl_Migration (sName) VALUES (?)`, [migration.name]);
        applied.push(migration.name);
      }
    } finally {
      await conn.query(`SELECT RELEASE_LOCK(?)`, [MIGRATION_LOCK]);
    }
    return applied;
  } finally {
    conn.release();
  }
}
