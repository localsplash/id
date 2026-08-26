import mysql from 'mysql2/promise';
import { AppConfig } from './config';

let pool: mysql.Pool | null = null;

export function getDb(config: AppConfig): mysql.Pool {
  if (!pool) {
    pool = mysql.createPool({
      host: config.DB_HOST,
      port: config.DB_PORT,
      user: config.DB_USER,
      password: config.DB_PASSWORD,
      database: config.DB_NAME,
      waitForConnections: true,
      connectionLimit: 5,
      timezone: 'Z',
    });
  }
  return pool;
}

/**
 * Idempotent schema creation, mirrored in EchoDatabase/init for fresh stack
 * installs. Running it here as well lets the app come up against any empty
 * database without cross-repo ordering.
 */
export async function ensureSchema(pool: mysql.Pool): Promise<void> {
  await pool.query(`
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
  await pool.query(`
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
  await pool.query(`
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
  await pool.query(`
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
  await pool.query(`
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
  await pool.query(`
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
  await pool.query(`
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS id_tbl_SsoNonce (
      sNonce    CHAR(32) PRIMARY KEY,
      dtExpires DATETIME(3) NOT NULL,
      dtCreated DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      INDEX idx_nonce_expires (dtExpires)
    ) ENGINE=InnoDB
  `);
}
