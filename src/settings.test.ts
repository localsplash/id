import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  KNOWN_SETTINGS,
  SettingsStore,
  SettingOverriddenError,
  settingOverridesFromEnv,
} from './settings';
import type { AppConfig } from './config';
import { dbCoordinates } from './db';

/**
 * The settings precedence rule: the environment overrides the store, the
 * store holds what the wizard and /admin write, and nothing is invented for
 * a key neither of them has answered.
 */

const config = {
  NOCODB_BASE_URL: 'http://nocodb.test',
  NOCODB_API_TOKEN: 'token',
  NOCODB_BASE_NAME: 'id',
  NOCODB_TABLE_NAME: 'oAuthConfig',
} as AppConfig;

/** A NocoDB stub holding one row per key, enough for the store's own calls. */
function stubNocoDb(rows: Array<{ Id: number; Key: string; Value: string | null }>) {
  const posted: unknown[] = [];
  const patched: unknown[] = [];
  const fetchMock = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(init.body) : undefined;
    const json = (value: unknown) => ({ ok: true, json: async () => value }) as unknown as Response;

    if (url.endsWith('/api/v2/meta/bases')) return json({ list: [{ id: 'b1', title: 'id' }] });
    if (url.endsWith('/api/v2/meta/bases/b1/tables')) {
      return json({ list: [{ id: 't1', title: 'oAuthConfig' }] });
    }
    if (url.includes('/api/v2/tables/t1/records')) {
      if (method === 'POST') {
        posted.push(body);
        return json({});
      }
      if (method === 'PATCH') {
        patched.push(body);
        return json({});
      }
      return json({
        list: rows.map((r) => ({ ...r, Description: '' })),
        pageInfo: { isLastPage: true },
      });
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return { posted, patched };
}

beforeEach(() => {
  vi.unstubAllGlobals();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('settingOverridesFromEnv', () => {
  it('picks up every known key that the environment states', () => {
    const overrides = settingOverridesFromEnv({
      APP_BASE_URL: ' https://identity.wisp.net ',
      PARENT_DOMAIN: 'wisp.net',
      GOOGLE_CLIENT_ID: 'gid',
      UNRELATED_VARIABLE: 'ignored',
    } as NodeJS.ProcessEnv);
    expect(overrides).toEqual({
      APP_BASE_URL: 'https://identity.wisp.net',
      PARENT_DOMAIN: 'wisp.net',
      GOOGLE_CLIENT_ID: 'gid',
    });
  });

  it('treats blank as "not set here" rather than as an empty override', () => {
    expect(settingOverridesFromEnv({ APP_BASE_URL: '', PARENT_DOMAIN: '   ' })).toEqual({});
  });

  it('covers the whole documented settings menu', () => {
    const env = Object.fromEntries(KNOWN_SETTINGS.map((s) => [s.key, 'x']));
    expect(Object.keys(settingOverridesFromEnv(env)).sort()).toEqual(
      KNOWN_SETTINGS.map((s) => s.key).sort()
    );
  });
});

describe('SettingsStore precedence', () => {
  it('lets the environment win over the stored row', async () => {
    stubNocoDb([
      { Id: 1, Key: 'APP_BASE_URL', Value: 'https://stale.wisp.net' },
      { Id: 2, Key: 'PARENT_DOMAIN', Value: 'wisp.net' },
    ]);
    const store = new SettingsStore(config, { APP_BASE_URL: 'https://identity.wisp.net' });
    const settings = await store.getAll();
    expect(settings.APP_BASE_URL).toBe('https://identity.wisp.net');
    expect(settings.PARENT_DOMAIN).toBe('wisp.net');
  });

  it('reads the store when the environment says nothing', async () => {
    stubNocoDb([{ Id: 1, Key: 'APP_BASE_URL', Value: 'https://identity.wisp.net' }]);
    const store = new SettingsStore(config, {});
    expect((await store.getAll()).APP_BASE_URL).toBe('https://identity.wisp.net');
    expect(store.isOverridden('APP_BASE_URL')).toBe(false);
  });

  it('leaves an unanswered key unset — no value is invented', async () => {
    stubNocoDb([{ Id: 1, Key: 'APP_BASE_URL', Value: '' }]);
    const store = new SettingsStore(config, {});
    expect((await store.getAll()).APP_BASE_URL).toBeUndefined();
  });

  it('refuses to write a key the environment pins', async () => {
    stubNocoDb([{ Id: 1, Key: 'APP_BASE_URL', Value: '' }]);
    const store = new SettingsStore(config, { APP_BASE_URL: 'https://identity.wisp.net' });
    await expect(store.set('APP_BASE_URL', 'https://other.wisp.net')).rejects.toBeInstanceOf(
      SettingOverriddenError
    );
    expect(store.overriddenKeys()).toEqual(['APP_BASE_URL']);
  });

  it('still answers from the environment when NocoDB is unreachable', () => {
    const store = new SettingsStore(config, { PARENT_DOMAIN: 'wisp.net' });
    expect(store.fromEnvOnly()).toEqual({ PARENT_DOMAIN: 'wisp.net' });
  });

  it('shows the admin what is in force and where it came from', async () => {
    stubNocoDb([
      { Id: 1, Key: 'APP_BASE_URL', Value: 'https://stale.wisp.net' },
      { Id: 2, Key: 'PARENT_DOMAIN', Value: 'wisp.net' },
    ]);
    const store = new SettingsStore(config, {
      APP_BASE_URL: 'https://identity.wisp.net',
      GOOGLE_CLIENT_ID: 'gid',
    });
    const items = await store.listForAdmin();
    const byKey = Object.fromEntries(items.map((i) => [i.key, i]));

    expect(byKey.APP_BASE_URL).toMatchObject({
      value: 'https://identity.wisp.net',
      source: 'environment',
    });
    expect(byKey.PARENT_DOMAIN).toMatchObject({ value: 'wisp.net', source: 'store' });
    // In force without a row of its own — still visible rather than silent.
    expect(byKey.GOOGLE_CLIENT_ID).toMatchObject({ value: 'gid', source: 'environment' });
  });
});

describe('database coordinates as settings', () => {
  it('reads the pool coordinates out of the settings', () => {
    expect(
      dbCoordinates({
        DB_HOST: 'mysql.internal',
        DB_PORT: '13306',
        DB_USER: 'id_app',
        DB_PASSWORD: 'pw',
        DB_NAME: 'id_db',
      })
    ).toEqual({
      host: 'mysql.internal',
      port: 13306,
      user: 'id_app',
      password: 'pw',
      database: 'id_db',
    });
  });

  it("falls back to MySQL's own port, and to no password", () => {
    expect(dbCoordinates({ DB_HOST: 'mysql.internal', DB_USER: 'id_app', DB_NAME: 'id_db' })).toEqual({
      host: 'mysql.internal',
      port: 3306,
      user: 'id_app',
      password: '',
      database: 'id_db',
    });
  });

  it('invents nothing when the deployment has not said where the database is', () => {
    expect(dbCoordinates({})).toBeNull();
    expect(dbCoordinates({ DB_HOST: 'mysql.internal' })).toBeNull();
    expect(dbCoordinates({ DB_HOST: 'mysql.internal', DB_USER: 'id_app' })).toBeNull();
  });
});
