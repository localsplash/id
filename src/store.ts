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
    `SELECT iUserId FROM identity_tbl_Identity WHERE provider = ? AND subject = ?`,
    [provider, subject]
  );
  return rows.length ? (rows[0].iUserId as number) : null;
}

export async function findUserByEmail(pool: mysql.Pool, email: string): Promise<number | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId FROM identity_tbl_User WHERE email = ? LIMIT 1`,
    [email]
  );
  return rows.length ? (rows[0].iUserId as number) : null;
}

export async function getUser(pool: mysql.Pool, iUserId: number): Promise<UserRow | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId, email, displayName, dtCreated, dtLastLogin FROM identity_tbl_User WHERE iUserId = ?`,
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
    `INSERT INTO identity_tbl_User (email, displayName) VALUES (?, ?)`,
    [email, displayName]
  );
  return result.insertId;
}

export async function touchLastLogin(pool: mysql.Pool, iUserId: number): Promise<void> {
  await pool.query(`UPDATE identity_tbl_User SET dtLastLogin = NOW(3) WHERE iUserId = ?`, [iUserId]);
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
    `INSERT INTO identity_tbl_Identity (iUserId, provider, subject, email)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE email = COALESCE(VALUES(email), email)`,
    [iUserId, provider, subject, email]
  );
}

export async function listIdentities(pool: mysql.Pool, iUserId: number): Promise<IdentityRow[]> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iIdentityId, iUserId, provider, subject, email, dtCreated
       FROM identity_tbl_Identity WHERE iUserId = ? ORDER BY dtCreated ASC`,
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
       FROM identity_tbl_Identity WHERE iIdentityId = ?`,
    [iIdentityId]
  );
  return rows.length ? (rows[0] as unknown as IdentityRow) : null;
}

export async function deleteIdentity(pool: mysql.Pool, iIdentityId: number): Promise<void> {
  await pool.query(`DELETE FROM identity_tbl_Identity WHERE iIdentityId = ?`, [iIdentityId]);
}

/**
 * Removing a user's only identity would lock them out with no way back in,
 * so unlinking is refused at that point regardless of who is asking.
 */
export async function countIdentities(pool: mysql.Pool, iUserId: number): Promise<number> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT COUNT(*) n FROM identity_tbl_Identity WHERE iUserId = ?`,
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
    `INSERT INTO identity_tbl_Session (sSessionId, iUserId, bSuperAdmin, sProvider, sSubject)
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
       FROM identity_tbl_Session WHERE sSessionId = ? AND dtRevoked IS NULL`,
    [sessionId]
  );
  if (!rows.length) return null;
  const r = rows[0];
  // Fire-and-forget activity stamp; a failed write must not fail the request.
  pool
    .query(`UPDATE identity_tbl_Session SET dtLastSeen = NOW(3) WHERE sSessionId = ?`, [sessionId])
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
    `UPDATE identity_tbl_Session SET dtRevoked = NOW(3) WHERE sSessionId = ? AND dtRevoked IS NULL`,
    [sessionId]
  );
}

export async function revokeAllSessions(pool: mysql.Pool, iUserId: number): Promise<number> {
  const [result] = await pool.query<mysql.ResultSetHeader>(
    `UPDATE identity_tbl_Session SET dtRevoked = NOW(3) WHERE iUserId = ? AND dtRevoked IS NULL`,
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
    `INSERT INTO identity_tbl_AuthCode
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
    `UPDATE identity_tbl_AuthCode SET dtConsumed = NOW(3)
      WHERE sCode = ? AND sRedirectUri = ? AND dtConsumed IS NULL AND dtExpires > NOW(3)`,
    [code, redirectUri]
  );
  if (result.affectedRows !== 1) return null;
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iUserId, sProvider, sSubject, bSuperAdmin FROM identity_tbl_AuthCode WHERE sCode = ?`,
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
    await pool.query(`INSERT INTO identity_tbl_SsoNonce (sNonce, dtExpires) VALUES (?, ?)`, [
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
            (SELECT COUNT(*) FROM identity_tbl_Session s
              WHERE s.iUserId = u.iUserId AND s.dtRevoked IS NULL) AS activeSessions
       FROM identity_tbl_User u
       LEFT JOIN identity_tbl_Identity i ON i.iUserId = u.iUserId
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

// ─── Application registry ─────────────────────────────────────────────────────

export interface AppRow {
  sOrigin: string;
  sName: string | null;
  sWebhookUrl: string | null;
  dtDiscovered: string;
  dtRegistered: string | null;
  dtLastTokenExchange: string | null;
  dtLastDeliveryOk: string | null;
  dtLastDeliveryFail: string | null;
  sLastError: string | null;
  iConsecutiveFailures: number;
}

/**
 * Note an application exists because it just redeemed a handoff code.
 *
 * This is the discovery half of the registry: an app that integrates login
 * but never registers a webhook still shows up, which is precisely the
 * misconfiguration the dashboard needs to be able to name.
 */
export async function recordAppOrigin(pool: mysql.Pool, origin: string): Promise<void> {
  await pool.query(
    `INSERT INTO identity_tbl_App (sOrigin, dtLastTokenExchange) VALUES (?, NOW(3))
     ON DUPLICATE KEY UPDATE dtLastTokenExchange = NOW(3)`,
    [origin]
  );
}

/**
 * Register (or re-register) an app's webhook endpoint, returning the secret
 * it must verify deliveries with. The secret is minted once and returned on
 * every registration, so an app can hold it in memory and re-fetch it on
 * boot instead of carrying yet another configured value.
 */
export async function registerApp(
  pool: mysql.Pool,
  params: { origin: string; name: string | null; webhookUrl: string }
): Promise<{ secret: string; rotated: boolean }> {
  const [existing] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT sSecret FROM identity_tbl_App WHERE sOrigin = ?`,
    [params.origin]
  );
  const current = existing.length ? (existing[0].sSecret as string | null) : null;
  const secret = current ?? generateId(32);

  await pool.query(
    `INSERT INTO identity_tbl_App (sOrigin, sName, sWebhookUrl, sSecret, dtRegistered)
     VALUES (?, ?, ?, ?, NOW(3))
     ON DUPLICATE KEY UPDATE
       sName = VALUES(sName),
       sWebhookUrl = VALUES(sWebhookUrl),
       sSecret = COALESCE(sSecret, VALUES(sSecret)),
       dtRegistered = NOW(3),
       iConsecutiveFailures = 0,
       sLastError = NULL`,
    [params.origin, params.name, params.webhookUrl, secret]
  );
  return { secret, rotated: current === null };
}

export async function listApps(pool: mysql.Pool): Promise<AppRow[]> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT sOrigin, sName, sWebhookUrl, dtDiscovered, dtRegistered, dtLastTokenExchange,
            dtLastDeliveryOk, dtLastDeliveryFail, sLastError, iConsecutiveFailures
       FROM identity_tbl_App ORDER BY sOrigin`
  );
  return rows as unknown as AppRow[];
}

export async function getAppSecret(pool: mysql.Pool, origin: string): Promise<string | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT sSecret FROM identity_tbl_App WHERE sOrigin = ?`,
    [origin]
  );
  return rows.length ? ((rows[0].sSecret as string) ?? null) : null;
}

/** Pending (undelivered, unabandoned) deliveries per app, for the dashboard. */
export async function pendingDeliveryCounts(
  pool: mysql.Pool
): Promise<Record<string, { pending: number; abandoned: number }>> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT sOrigin,
            SUM(dtDelivered IS NULL AND dtAbandoned IS NULL) AS pending,
            SUM(dtAbandoned IS NOT NULL) AS abandoned
       FROM identity_tbl_Delivery GROUP BY sOrigin`
  );
  const out: Record<string, { pending: number; abandoned: number }> = {};
  for (const r of rows) {
    out[r.sOrigin as string] = {
      pending: Number(r.pending ?? 0),
      abandoned: Number(r.abandoned ?? 0),
    };
  }
  return out;
}

/** Events after `since`, oldest first — the boot-time catch-up feed. */
export async function listEventsSince(
  pool: mysql.Pool,
  since: number,
  limit = 200
): Promise<Array<{ id: number; type: string; occurredAt: string; data: unknown }>> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT iEventId, sType, jsonData, dtCreated
       FROM identity_tbl_Event WHERE iEventId > ? ORDER BY iEventId ASC LIMIT ?`,
    [since, limit]
  );
  return rows.map((r) => ({
    id: r.iEventId as number,
    type: r.sType as string,
    occurredAt: new Date(r.dtCreated as string).toISOString(),
    data: typeof r.jsonData === 'string' ? JSON.parse(r.jsonData) : r.jsonData,
  }));
}

// ─── Central user directory (CIDR-trusted server API) ────────────────────────

export interface DirectoryUser {
  iUserId: number;
  email: string | null;
  displayName: string | null;
  /** True once any login method is attached — the pre-created UID was taken
   *  over by a real sign-in (trusted-provider email match does this). */
  claimed: boolean;
}

const dirUserSelect = `
  SELECT u.iUserId, u.email, u.displayName,
         EXISTS(SELECT 1 FROM identity_tbl_Identity i WHERE i.iUserId = u.iUserId) AS claimed
    FROM identity_tbl_User u`;

function toDirectoryUser(r: mysql.RowDataPacket): DirectoryUser {
  return {
    iUserId: r.iUserId as number,
    email: (r.email as string) ?? null,
    displayName: (r.displayName as string) ?? null,
    claimed: Boolean(r.claimed),
  };
}

export async function getDirectoryUser(
  pool: mysql.Pool,
  iUserId: number
): Promise<DirectoryUser | null> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `${dirUserSelect} WHERE u.iUserId = ?`,
    [iUserId]
  );
  return rows.length ? toDirectoryUser(rows[0]) : null;
}

/**
 * Idempotent, concurrency-safe ensure-by-email.
 *
 * Two guards: the caller's idempotencyKey maps to the user its first call
 * produced (a retried POST returns the same UID), and an advisory lock on
 * the normalised email serialises concurrent ensures for the same person
 * so exactly one row is created. Matching an existing user by email means
 * repeat ensures — and ensures racing a login — converge on one UID.
 */
export async function ensureDirectoryUser(
  pool: mysql.Pool,
  params: { email: string; displayName: string | null; idempotencyKey: string | null }
): Promise<DirectoryUser> {
  const email = params.email.trim().toLowerCase();
  const conn = await pool.getConnection();
  try {
    if (params.idempotencyKey) {
      const [keyRows] = await conn.query<mysql.RowDataPacket[]>(
        `${dirUserSelect} JOIN identity_tbl_DirectoryKey k ON k.iUserId = u.iUserId
          WHERE k.sIdempotencyKey = ?`,
        [params.idempotencyKey]
      );
      if (keyRows.length) return toDirectoryUser(keyRows[0]);
    }

    // Advisory lock name is hashed: emails can exceed MySQL's 64-char
    // lock-name limit, and the lock only needs to collide for equal emails.
    const lockName = `id_dir_${crypto.createHash('sha256').update(email).digest('hex').slice(0, 40)}`;
    const [lockRows] = await conn.query<mysql.RowDataPacket[]>(`SELECT GET_LOCK(?, 10) AS l`, [
      lockName,
    ]);
    if (Number(lockRows[0]?.l) !== 1) throw new Error('Directory ensure lock timeout');
    try {
      const [existing] = await conn.query<mysql.RowDataPacket[]>(
        `${dirUserSelect} WHERE u.email = ? ORDER BY u.iUserId ASC LIMIT 1`,
        [email]
      );
      let user: DirectoryUser;
      if (existing.length) {
        user = toDirectoryUser(existing[0]);
      } else {
        const [ins] = await conn.query<mysql.ResultSetHeader>(
          `INSERT INTO identity_tbl_User (email, displayName) VALUES (?, ?)`,
          [email, params.displayName]
        );
        user = { iUserId: ins.insertId, email, displayName: params.displayName, claimed: false };
      }
      if (params.idempotencyKey) {
        await conn.query(
          `INSERT IGNORE INTO identity_tbl_DirectoryKey (sIdempotencyKey, iUserId) VALUES (?, ?)`,
          [params.idempotencyKey, user.iUserId]
        );
      }
      return user;
    } finally {
      await conn.query(`SELECT RELEASE_LOCK(?)`, [lockName]);
    }
  } finally {
    conn.release();
  }
}

/**
 * Keyset-paginated directory search. `cursor` is the last iUserId of the
 * previous page (opaque to callers); results are minimal by design — no
 * identities, sessions, codes, or credentials ever leave this endpoint.
 */
export async function searchDirectoryUsers(
  pool: mysql.Pool,
  params: { query: string; limit: number; cursor: number }
): Promise<{ items: DirectoryUser[]; nextCursor: number | null }> {
  const limit = Math.min(Math.max(1, Math.floor(params.limit) || 25), 100);
  const clauses: string[] = ['u.iUserId > ?'];
  const args: unknown[] = [params.cursor];
  if (params.query) {
    // Escape LIKE metacharacters so a query is always a literal substring.
    const like = `%${params.query.replace(/[\\%_]/g, '\\$&')}%`;
    clauses.push('(u.email LIKE ? OR u.displayName LIKE ?)');
    args.push(like, like);
  }
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `${dirUserSelect} WHERE ${clauses.join(' AND ')} ORDER BY u.iUserId ASC LIMIT ?`,
    [...args, limit + 1]
  );
  const items = rows.slice(0, limit).map(toDirectoryUser);
  const nextCursor = rows.length > limit ? items[items.length - 1].iUserId : null;
  return { items, nextCursor };
}

// ─── Identity remapping ───────────────────────────────────────────────────────

export interface MergeResult {
  movedIdentities: number;
  revokedSessions: number;
}

/**
 * Fold one id user into another: every login method on `fromUserId` becomes
 * a login method of `toUserId`, and the retired user's sessions end.
 *
 * This is the repair for the two ways a person ends up as two users — they
 * signed in with Google having previously come through the ISP bridge, or a
 * provider that does not vouch for its addresses could not be auto-linked.
 * An identity already present on the target is dropped rather than
 * duplicated (the unique key on (provider, subject) would refuse it anyway).
 */
export async function mergeUsers(
  pool: mysql.Pool,
  fromUserId: number,
  toUserId: number
): Promise<MergeResult> {
  if (fromUserId === toUserId) throw new Error('Cannot merge a user into itself');

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [moved] = await conn.query<mysql.ResultSetHeader>(
      `UPDATE IGNORE identity_tbl_Identity SET iUserId = ? WHERE iUserId = ?`,
      [toUserId, fromUserId]
    );
    // Whatever IGNORE skipped was a duplicate of an identity the target
    // already holds; the source row is redundant either way.
    await conn.query(`DELETE FROM identity_tbl_Identity WHERE iUserId = ?`, [fromUserId]);

    const [revoked] = await conn.query<mysql.ResultSetHeader>(
      `UPDATE identity_tbl_Session SET dtRevoked = NOW(3)
        WHERE iUserId = ? AND dtRevoked IS NULL`,
      [fromUserId]
    );

    // Keep an address on the surviving user if it had none.
    await conn.query(
      `UPDATE identity_tbl_User t
          JOIN identity_tbl_User f ON f.iUserId = ?
          SET t.email = COALESCE(t.email, f.email),
              t.displayName = COALESCE(t.displayName, f.displayName)
        WHERE t.iUserId = ?`,
      [fromUserId, toUserId]
    );

    await conn.query(`DELETE FROM identity_tbl_User WHERE iUserId = ?`, [fromUserId]);
    await conn.commit();

    return { movedIdentities: moved.affectedRows, revokedSessions: revoked.affectedRows };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}
