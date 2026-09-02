import mysql from 'mysql2/promise';
import { Settings } from './settings';

/**
 * The MySQL pool for id_db.
 *
 * Its coordinates are settings like any other — a row in `oAuthConfig`, or
 * an environment override — rather than a second configuration file. That
 * means they are not known when the app is constructed, only when the
 * settings store is first read, so the pool is created lazily on first use.
 *
 * A change of coordinates takes a restart: the pool is created once and
 * kept, because silently reconnecting a live app to a different database
 * mid-request is worse than an explicit bounce.
 */

export interface DbCoordinates {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

/**
 * The coordinates the settings describe, or null when they are not stated.
 * Host, user and database are required; the port falls back to MySQL's own
 * registered port, which is the protocol's default and not a guess about
 * this deployment.
 */
export function dbCoordinates(settings: Settings): DbCoordinates | null {
  const host = (settings.DB_HOST ?? '').trim();
  const user = (settings.DB_USER ?? '').trim();
  const database = (settings.DB_NAME ?? '').trim();
  if (!host || !user || !database) return null;
  const port = Number.parseInt((settings.DB_PORT ?? '').trim(), 10);
  return {
    host,
    port: Number.isFinite(port) && port > 0 ? port : 3306,
    user,
    password: settings.DB_PASSWORD ?? '',
    database,
  };
}

export class DatabaseNotConfiguredError extends Error {
  constructor() {
    super(
      'The id_db coordinates are not set. Fill in DB_HOST, DB_USER, DB_NAME ' +
        '(and DB_PASSWORD) in the oAuthConfig settings table, or set them in ' +
        "this app's environment, then restart."
    );
    this.name = 'DatabaseNotConfiguredError';
  }
}

let pool: mysql.Pool | null = null;
let opening: Promise<mysql.Pool> | null = null;

/**
 * A pool-shaped handle that connects on first use, resolving its
 * coordinates through `resolve`. Only the surface this codebase uses is
 * forwarded (`query`, `getConnection`, `end`) — everything goes through the
 * real pool once it exists.
 */
export function getDb(resolve: () => Promise<DbCoordinates | null>): mysql.Pool {
  async function real(): Promise<mysql.Pool> {
    if (pool) return pool;
    if (!opening) {
      opening = (async () => {
        const coords = await resolve();
        if (!coords) throw new DatabaseNotConfiguredError();
        pool = mysql.createPool({
          ...coords,
          waitForConnections: true,
          connectionLimit: 5,
          timezone: 'Z',
        });
        return pool;
      })().finally(() => {
        opening = null;
      });
    }
    return opening;
  }

  const lazy = {
    async query(...args: unknown[]) {
      const p = await real();
      return (p.query as (...a: unknown[]) => unknown)(...args);
    },
    async getConnection() {
      return (await real()).getConnection();
    },
    async end() {
      if (pool) await pool.end();
      pool = null;
    },
  };
  return lazy as unknown as mysql.Pool;
}

/** Test/reset hook: drop the memoised pool without ending it. */
export function resetDb(): void {
  pool = null;
  opening = null;
}
