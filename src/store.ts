import crypto from 'crypto';
import mysql from 'mysql2/promise';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface UserRow {
  iUserId: number;
  email: string | null;
  displayName: string | null;
  dtCreated: Date;
  dtLastLogin: Date | null;
}

export interface IdentityRow {
  iIdentityId: number;
  iUserId: number;
  provider: string;
  subject: string;
  email: string | null;
  dtCreated: string;
}

export interface SessionRow {
  sSessionId: string;
  iUserId: number;
  bSuperAdmin: boolean;
  sProvider: string | null;
  sSubject: string | null;
  dtCreated: Date;
}

export function generateId(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

function toMySQLDateTime(d: Date): string {
  return d.toISOString().slice(0, 23).replace('T', ' ');
}

// ─── Users & identities ───────────────────────────────────────────────────────

export async function findUserByIdentity(
  pool: mysql.Pool,
  provider: string,
  subject: string
): Promise<number | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId FROM id_tbl_Identity WHERE provider = ? AND subject = ?`,
    [provider, subject]
  );
  return rows.length ? (rows[0].iUserId as number) : null;
}

export async function findUserByEmail(pool: mysql.Pool, email: string): Promise<number | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId FROM id_tbl_User WHERE email = ? LIMIT 1`,
    [email]
  );
  return rows.length ? (rows[0].iUserId as number) : null;
}

export async function getUser(pool: mysql.Pool, iUserId: number): Promise<UserRow | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId, email, displayName, dtCreated, dtLastLogin FROM id_tbl_User WHERE iUserId = ?`,
    [iUserId]
  );
  return rows.length ? (rows[0] as unknown as UserRow) : null;
}

export async function createUser(
  pool: mysql.Pool,
  email: string | null,
  displayName: string | null
): Promise<number> {
  const [result] = await pool.query<mysql.ResultSetHeader>(
    `INSERT INTO id_tbl_User (email, displayName) VALUES (?, ?)`,
    [email, displayName]
  );
  return result.insertId;
}

export async function touchLastLogin(pool: mysql.Pool, iUserId: number): Promise<void> {
  await pool.query(`UPDATE id_tbl_User SET dtLastLogin = NOW(3) WHERE iUserId = ?`, [iUserId]);
}

export async function ensureIdentity(
  pool: mysql.Pool,
  iUserId: number,
  provider: string,
  subject: string,
  email: string | null = null
): Promise<void> {
  // Refresh the address on re-login so a renamed account doesn't keep its old
  // label, but never overwrite a known one with null.
  await pool.query(
    `INSERT INTO id_tbl_Identity (iUserId, provider, subject, email)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE email = COALESCE(VALUES(email), email)`,
    [iUserId, provider, subject, email]
  );
}

export async function listIdentities(pool: mysql.Pool, iUserId: number): Promise<IdentityRow[]> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iIdentityId, iUserId, provider, subject, email, dtCreated
       FROM id_tbl_Identity WHERE iUserId = ? ORDER BY dtCreated ASC`,
    [iUserId]
  );
  return rows as unknown as IdentityRow[];
}

export async function getIdentity(
  pool: mysql.Pool,
  iIdentityId: number
): Promise<IdentityRow | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iIdentityId, iUserId, provider, subject, email, dtCreated
       FROM id_tbl_Identity WHERE iIdentityId = ?`,
    [iIdentityId]
  );
  return rows.length ? (rows[0] as unknown as IdentityRow) : null;
}

export async function deleteIdentity(pool: mysql.Pool, iIdentityId: number): Promise<void> {
  await pool.query(`DELETE FROM id_tbl_Identity WHERE iIdentityId = ?`, [iIdentityId]);
}

/**
 * Removing a user's only identity would lock them out with no way back in,
 * so unlinking is refused at that point regardless of who is asking.
 */
export async function countIdentities(pool: mysql.Pool, iUserId: number): Promise<number> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT COUNT(*) n FROM id_tbl_Identity WHERE iUserId = ?`,
    [iUserId]
  );
  return Number(rows[0]?.n ?? 0);
}

// ─── Sessions (persist until revoked) ────────────────────────────────────────

export async function createSession(
  pool: mysql.Pool,
  iUserId: number,
  bSuperAdmin: boolean,
  provider: string | null,
  subject: string | null
): Promise<string> {
  const sessionId = generateId(32);
  await pool.query(
    `INSERT INTO id_tbl_Session (sSessionId, iUserId, bSuperAdmin, sProvider, sSubject)
     VALUES (?, ?, ?, ?, ?)`,
    [sessionId, iUserId, bSuperAdmin ? 1 : 0, provider, subject]
  );
  return sessionId;
}

export async function getSession(
  pool: mysql.Pool,
  sessionId: string
): Promise<SessionRow | null> {
  if (!sessionId || !/^[0-9a-f]{64}$/.test(sessionId)) return null;
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT sSessionId, iUserId, bSuperAdmin, sProvider, sSubject, dtCreated
       FROM id_tbl_Session WHERE sSessionId = ? AND dtRevoked IS NULL`,
    [sessionId]
  );
  if (!rows.length) return null;
  const r = rows[0];
  // Fire-and-forget activity stamp; a failed write must not fail the request.
  pool
    .query(`UPDATE id_tbl_Session SET dtLastSeen = NOW(3) WHERE sSessionId = ?`, [sessionId])
    .catch(() => undefined);
  return {
    sSessionId: r.sSessionId as string,
    iUserId: r.iUserId as number,
    bSuperAdmin: Boolean(r.bSuperAdmin),
    sProvider: (r.sProvider as string) ?? null,
    sSubject: (r.sSubject as string) ?? null,
    dtCreated: new Date(r.dtCreated as string),
  };
}

export async function revokeSession(pool: mysql.Pool, sessionId: string): Promise<void> {
  await pool.query(
    `UPDATE id_tbl_Session SET dtRevoked = NOW(3) WHERE sSessionId = ? AND dtRevoked IS NULL`,
    [sessionId]
  );
}

export async function revokeAllSessions(pool: mysql.Pool, iUserId: number): Promise<number> {
  const [result] = await pool.query<mysql.ResultSetHeader>(
    `UPDATE id_tbl_Session SET dtRevoked = NOW(3) WHERE iUserId = ? AND dtRevoked IS NULL`,
    [iUserId]
  );
  return result.affectedRows;
}

// ─── Handoff codes ────────────────────────────────────────────────────────────

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

export async function createAuthCode(
  pool: mysql.Pool,
  params: {
    iUserId: number;
    redirectUri: string;
    provider: string | null;
    subject: string | null;
    bSuperAdmin: boolean;
  }
): Promise<string> {
  const code = generateId(32);
  await pool.query(
    `INSERT INTO id_tbl_AuthCode
       (sCode, iUserId, sRedirectUri, sProvider, sSubject, bSuperAdmin, dtExpires)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      code,
      params.iUserId,
      params.redirectUri,
      params.provider,
      params.subject,
      params.bSuperAdmin ? 1 : 0,
      toMySQLDateTime(new Date(Date.now() + AUTH_CODE_TTL_MS)),
    ]
  );
  return code;
}

export interface ConsumedAuthCode {
  iUserId: number;
  sProvider: string | null;
  sSubject: string | null;
  bSuperAdmin: boolean;
}

/**
 * Single-use redemption: the UPDATE claims the row atomically, so a replayed
 * or expired code — or one presented with a different redirect_uri than it
 * was minted for — gets nothing.
 */
export async function consumeAuthCode(
  pool: mysql.Pool,
  code: string,
  redirectUri: string
): Promise<ConsumedAuthCode | null> {
  if (!/^[0-9a-f]{64}$/.test(code)) return null;
  const [result] = await pool.query<mysql.ResultSetHeader>(
    `UPDATE id_tbl_AuthCode SET dtConsumed = NOW(3)
      WHERE sCode = ? AND sRedirectUri = ? AND dtConsumed IS NULL AND dtExpires > NOW(3)`,
    [code, redirectUri]
  );
  if (result.affectedRows !== 1) return null;
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId, sProvider, sSubject, bSuperAdmin FROM id_tbl_AuthCode WHERE sCode = ?`,
    [code]
  );
  if (!rows.length) return null;
  return {
    iUserId: rows[0].iUserId as number,
    sProvider: (rows[0].sProvider as string) ?? null,
    sSubject: (rows[0].sSubject as string) ?? null,
    bSuperAdmin: Boolean(rows[0].bSuperAdmin),
  };
}

// ─── UISP SSO nonces ─────────────────────────────────────────────────────────

/** Returns false if the nonce was already used (replay). */
export async function consumeNonce(
  pool: mysql.Pool,
  nonce: string,
  expUnix: number
): Promise<boolean> {
  try {
    await pool.query(`INSERT INTO id_tbl_SsoNonce (sNonce, dtExpires) VALUES (?, ?)`, [
      nonce,
      toMySQLDateTime(new Date(expUnix * 1000)),
    ]);
    return true; // first use
  } catch {
    return false; // duplicate key = replay
  }
}

// ─── Admin views ─────────────────────────────────────────────────────────────

export interface AdminUserView {
  iUserId: number;
  email: string | null;
  displayName: string | null;
  dtCreated: string;
  dtLastLogin: string | null;
  identities: Array<{ iIdentityId: number; provider: string; subject: string; email: string | null }>;
  activeSessions: number;
}

export async function adminListUsers(pool: mysql.Pool): Promise<AdminUserView[]> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT u.iUserId, u.email, u.displayName, u.dtCreated, u.dtLastLogin,
            i.iIdentityId, i.provider, i.subject, i.email AS identityEmail,
            (SELECT COUNT(*) FROM id_tbl_Session s
              WHERE s.iUserId = u.iUserId AND s.dtRevoked IS NULL) AS activeSessions
       FROM id_tbl_User u
       LEFT JOIN id_tbl_Identity i ON i.iUserId = u.iUserId
      ORDER BY u.iUserId, i.provider`
  );
  const users = new Map<number, AdminUserView>();
  for (const r of rows) {
    let user = users.get(r.iUserId as number);
    if (!user) {
      user = {
        iUserId: r.iUserId as number,
        email: (r.email as string) ?? null,
        displayName: (r.displayName as string) ?? null,
        dtCreated: String(r.dtCreated),
        dtLastLogin: r.dtLastLogin ? String(r.dtLastLogin) : null,
        identities: [],
        activeSessions: Number(r.activeSessions ?? 0),
      };
      users.set(user.iUserId, user);
    }
    if (r.iIdentityId != null) {
      user.identities.push({
        iIdentityId: r.iIdentityId as number,
        provider: r.provider as string,
        subject: r.subject as string,
        email: (r.identityEmail as string) ?? null,
      });
    }
  }
  return Array.from(users.values());
}
