import crypto from 'crypto';
import mysql from 'mysql2/promise';

/**
 * The integration standard every application under the parent domain
 * implements to stay in step with id.
 *
 * Apps do not poll and do not run cron. They register one endpoint; id
 * pushes signed events to it and retries with backoff until the app
 * acknowledges. An app that was down while an event fired catches up from
 * `GET /api/events?since=` once at boot — the durable event log means a
 * revocation is never silently lost, which polling on a timer could not
 * promise either.
 *
 * Wire format (POST, application/json):
 *
 *   X-Id-Event: session.revoked
 *   X-Id-Event-Id: 1234
 *   X-Id-Timestamp: 1774500000
 *   X-Id-Signature: sha256=<hex>
 *
 *   { "id": 1234, "type": "session.revoked",
 *     "occurredAt": "2026-08-26T06:00:00.000Z", "data": { … } }
 *
 * POC trust model: the receiver's /id/events endpoint allowlists id's
 * egress IPv4/CIDRs and TLS protects the transport, so the HMAC signature
 * is OPTIONAL — sent when the app holds a webhook secret (legacy
 * secret-mode receivers), omitted otherwise. Receivers that do verify it
 * must check against the raw body (not a re-serialised object), reject a
 * timestamp outside ±300s, and compare in constant time.
 *
 * A receiver answers 2xx once the event is durably handled. Any other
 * status — or a timeout — is a failure and will be retried, so handlers
 * must be idempotent: the same event id can arrive more than once. Event
 * ids and timestamps are what replay/idempotency handling keys on.
 */

export const EVENT_TYPES = [
  /** Nothing happened; delivered to prove the endpoint is reachable. */
  'ping',
  /**
   * Sessions for a user were revoked at id. The app must end its own
   * sessions for that user — its local session is independent of id's, so
   * without acting on this the person stays signed in to the app.
   * data: { iUserId, scope: 'all' | 'one', sessionId?: string }
   */
  'session.revoked',
  /**
   * Two id users were merged: everything that pointed at `fromUserId` now
   * belongs to `toUserId`. Apps holding a local mapping (EchoWeb's
   * auth_tbl_User.iIdUserId) must repoint it, and should end sessions
   * belonging to the retired id user.
   * data: { fromUserId, toUserId }
   */
  'user.merged',
  /**
   * A login method was attached to or removed from a user. Informational
   * for most apps; apps that key on a specific identity (EchoWeb binds an
   * org by UISP clientId) may need to react.
   * data: { iUserId, provider, subject }
   */
  'identity.linked',
  'identity.unlinked',
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

export interface IdEvent {
  id: number;
  type: EventType;
  occurredAt: string;
  data: Record<string, unknown>;
}

/** Attempt schedule in seconds; length is also the give-up count. */
const RETRY_BACKOFF_SECONDS = [0, 30, 120, 600, 3600, 21600];
const DELIVERY_TIMEOUT_MS = 10_000;
/** Consecutive failures before the dashboard calls an app "not listening". */
export const FAILING_THRESHOLD = 1;

export function signPayload(secret: string, timestamp: number, rawBody: string): string {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
}

/**
 * Constant-time verification, exported so receivers in this codebase and
 * the reference implementation in the docs agree byte for byte.
 */
export function verifySignature(
  secret: string,
  timestamp: number,
  rawBody: string,
  signatureHeader: string,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): boolean {
  if (!secret || !signatureHeader) return false;
  if (!Number.isFinite(timestamp) || Math.abs(nowSeconds - timestamp) > 300) return false;

  const provided = signatureHeader.startsWith('sha256=')
    ? signatureHeader.slice('sha256='.length)
    : signatureHeader;
  const expected = signPayload(secret, timestamp, rawBody);

  let a: Buffer;
  let b: Buffer;
  try {
    a = Buffer.from(expected, 'hex');
    b = Buffer.from(provided, 'hex');
  } catch {
    return false;
  }
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function toMySQLDateTime(d: Date): string {
  return d.toISOString().slice(0, 23).replace('T', ' ');
}

// ─── Emitting ─────────────────────────────────────────────────────────────────

/**
 * Record an event and queue it for every registered app.
 *
 * The event is written even when no app is listening yet: it is the audit
 * trail, and a later registration can catch up from it.
 */
export async function emitEvent(
  pool: mysql.Pool,
  type: EventType,
  data: Record<string, unknown>,
  options: { onlyOrigin?: string } = {}
): Promise<number> {
  const [result] = await pool.query<mysql.ResultSetHeader>(
    `INSERT INTO id_tbl_Event (sType, jsonData) VALUES (?, ?)`,
    [type, JSON.stringify(data)]
  );
  const iEventId = result.insertId;

  const params: unknown[] = [iEventId];
  let where = `sWebhookUrl IS NOT NULL`;
  if (options.onlyOrigin) {
    where += ` AND sOrigin = ?`;
    params.push(options.onlyOrigin);
  }
  // dtNextAttempt = now → the ticker picks it up on its next pass.
  await pool.query(
    `INSERT IGNORE INTO id_tbl_Delivery (iEventId, sOrigin, dtNextAttempt)
     SELECT ?, sOrigin, NOW(3) FROM id_tbl_App WHERE ${where}`,
    params
  );
  return iEventId;
}

// ─── Delivering ───────────────────────────────────────────────────────────────

interface DueDelivery {
  iDeliveryId: number;
  iEventId: number;
  sOrigin: string;
  iAttempts: number;
  sType: EventType;
  jsonData: string | Record<string, unknown>;
  dtCreated: string;
  sWebhookUrl: string;
  sSecret: string | null;
}

async function markSuccess(pool: mysql.Pool, d: DueDelivery): Promise<void> {
  await pool.query(
    `UPDATE id_tbl_Delivery
        SET dtDelivered = NOW(3), iAttempts = iAttempts + 1, dtNextAttempt = NULL, sLastError = NULL
      WHERE iDeliveryId = ?`,
    [d.iDeliveryId]
  );
  await pool.query(
    `UPDATE id_tbl_App
        SET dtLastDeliveryOk = NOW(3), iConsecutiveFailures = 0, sLastError = NULL
      WHERE sOrigin = ?`,
    [d.sOrigin]
  );
}

async function markFailure(pool: mysql.Pool, d: DueDelivery, error: string): Promise<void> {
  const attempts = d.iAttempts + 1;
  const backoff = RETRY_BACKOFF_SECONDS[attempts];
  const giveUp = backoff === undefined;

  await pool.query(
    `UPDATE id_tbl_Delivery
        SET iAttempts = ?, sLastError = ?,
            dtNextAttempt = ${giveUp ? 'NULL' : '?'},
            dtAbandoned = ${giveUp ? 'NOW(3)' : 'NULL'}
      WHERE iDeliveryId = ?`,
    giveUp
      ? [attempts, error.slice(0, 500), d.iDeliveryId]
      : [
          attempts,
          error.slice(0, 500),
          toMySQLDateTime(new Date(Date.now() + backoff * 1000)),
          d.iDeliveryId,
        ]
  );
  await pool.query(
    `UPDATE id_tbl_App
        SET dtLastDeliveryFail = NOW(3), iConsecutiveFailures = iConsecutiveFailures + 1,
            sLastError = ?
      WHERE sOrigin = ?`,
    [error.slice(0, 500), d.sOrigin]
  );
}

async function deliverOne(pool: mysql.Pool, d: DueDelivery): Promise<boolean> {
  const data = typeof d.jsonData === 'string' ? JSON.parse(d.jsonData) : d.jsonData;
  const event: IdEvent = {
    id: d.iEventId,
    type: d.sType,
    occurredAt: new Date(d.dtCreated).toISOString(),
    data,
  };
  const rawBody = JSON.stringify(event);
  const timestamp = Math.floor(Date.now() / 1000);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Id-Event': d.sType,
    'X-Id-Event-Id': String(d.iEventId),
    'X-Id-Timestamp': String(timestamp),
  };
  // Signature is legacy/optional in the POC: sent only when the app holds a
  // webhook secret; network trust (IP allowlist at the receiver) + TLS is
  // the POC integrity story.
  if (d.sSecret) {
    headers['X-Id-Signature'] = `sha256=${signPayload(d.sSecret, timestamp, rawBody)}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);
  try {
    const resp = await fetch(d.sWebhookUrl, {
      method: 'POST',
      headers,
      body: rawBody,
      signal: controller.signal,
    });
    if (!resp.ok) {
      await markFailure(pool, d, `HTTP ${resp.status}`);
      return false;
    }
    await markSuccess(pool, d);
    return true;
  } catch (err) {
    await markFailure(pool, d, err instanceof Error ? err.message : String(err));
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Deliver everything currently due. Called on a short timer by the server;
 * safe to call concurrently-ish since a failed row is pushed forward before
 * the next pass would pick it up.
 */
export async function drainDeliveries(pool: mysql.Pool, limit = 50): Promise<number> {
  const [rows] = await pool.query<mysql.RowDataPacket[]>(
    `SELECT d.iDeliveryId, d.iEventId, d.sOrigin, d.iAttempts,
            e.sType, e.jsonData, e.dtCreated,
            a.sWebhookUrl, a.sSecret
       FROM id_tbl_Delivery d
       JOIN id_tbl_Event e ON e.iEventId = d.iEventId
       JOIN id_tbl_App   a ON a.sOrigin  = d.sOrigin
      WHERE d.dtDelivered IS NULL AND d.dtAbandoned IS NULL
        AND d.dtNextAttempt IS NOT NULL AND d.dtNextAttempt <= NOW(3)
        AND a.sWebhookUrl IS NOT NULL
      ORDER BY d.iEventId ASC
      LIMIT ?`,
    [limit]
  );

  let delivered = 0;
  for (const row of rows as unknown as DueDelivery[]) {
    if (await deliverOne(pool, row)) delivered++;
  }
  return delivered;
}
