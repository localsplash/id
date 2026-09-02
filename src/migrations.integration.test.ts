import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import mysql from 'mysql2/promise';
import { runMigrations, MIGRATIONS } from './migrations';

/**
 * Real-MySQL migration tests: clean install, upgrade of a pre-ownership
 * database, and second-run no-op. Skipped unless TEST_DB_URL points at a
 * disposable MySQL (CI provides one; locally e.g.
 * TEST_DB_URL=mysql://root:devpass@127.0.0.1:13306/id_db_migration_test).
 * The named database is DROPPED and recreated — never point this at real data.
 */

const url = process.env.TEST_DB_URL;
const suite = describe.skipIf(!url);

suite('id_db migrations (real MySQL)', () => {
  let pool: mysql.Pool;
  let dbName: string;

  beforeAll(async () => {
    const parsed = new URL(url!);
    dbName = parsed.pathname.replace(/^\//, '') || 'id_db_migration_test';
    const admin = await mysql.createConnection({
      host: parsed.hostname,
      port: Number(parsed.port || 3306),
      user: decodeURIComponent(parsed.username),
      password: decodeURIComponent(parsed.password),
    });
    await admin.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
    await admin.query(`CREATE DATABASE \`${dbName}\``);
    await admin.end();
    pool = mysql.createPool({ uri: url!, connectionLimit: 3, timezone: 'Z' });
  });

  afterAll(async () => {
    await pool?.end();
  });

  async function tableNames(): Promise<string[]> {
    const [rows] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT TABLE_NAME name FROM information_schema.tables WHERE table_schema = ?`,
      [dbName]
    );
    return rows.map((r) => String(r.name)).sort();
  }

  it('clean install applies every migration and creates the full schema', async () => {
    const applied = await runMigrations(pool);
    expect(applied).toEqual(MIGRATIONS.map((m) => m.name));
    const tables = await tableNames();
    for (const t of [
      'identity_tbl_User',
      'identity_tbl_Identity',
      'identity_tbl_Session',
      'identity_tbl_AuthCode',
      'identity_tbl_App',
      'identity_tbl_Event',
      'identity_tbl_Delivery',
      'identity_tbl_SsoNonce',
      'identity_tbl_DirectoryKey',
      'identity_tbl_Migration',
    ]) {
      expect(tables).toContain(t);
    }
  });

  it('a second run is a no-op', async () => {
    expect(await runMigrations(pool)).toEqual([]);
    expect(await runMigrations(pool)).toEqual([]);
  });

  it('upgrades a pre-ownership database without data loss', async () => {
    // Simulate a database created by an earlier deployment: the current
    // tables and data exist, but no migration history was ever recorded.
    await pool.query(`INSERT INTO identity_tbl_User (email, displayName) VALUES (?, ?)`, [
      'ada@x.tld',
      'Ada',
    ]);
    const [before] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT iUserId FROM identity_tbl_User WHERE email = 'ada@x.tld'`
    );
    const iUserId = before[0].iUserId as number;

    await pool.query(`DROP TABLE identity_tbl_DirectoryKey`);
    await pool.query(`DROP TABLE identity_tbl_Migration`);

    const applied = await runMigrations(pool);
    expect(applied).toEqual(MIGRATIONS.map((m) => m.name));

    // Existing users retain their iUserId (and can therefore authenticate).
    const [after] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT iUserId, email, displayName FROM identity_tbl_User WHERE email = 'ada@x.tld'`
    );
    expect(after).toHaveLength(1);
    expect(after[0].iUserId).toBe(iUserId);
    expect(after[0].displayName).toBe('Ada');

    expect(await runMigrations(pool)).toEqual([]);
  });
});
