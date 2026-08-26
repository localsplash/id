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
