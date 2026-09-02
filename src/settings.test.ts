import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  KNOWN_SETTINGS,
  SettingsStore,
  SettingOverriddenError,
  SettingsUnavailableError,
  SETTINGS_BASE_NAME,
  SETTINGS_TABLE_NAME,
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
} as AppConfig;

type Row = { Id: number; Key: string; Value: string | null };

/**
 * A NocoDB stub. `bases` is what /meta/bases answers with, so a test can
 * present a missing base, two bases of the same name, or a rename between
 * calls — the cases the unique-name convention exists to catch.
 */
function stubNocoDb(
  rows: Row[],
  opts: { bases?: () => Array<{ id: string; title: string }>; tableTitle?: string } = {}
) {
  const calls: string[] = [];
  const bases = opts.bases ?? (() => [{ id: 'b1', title: SETTINGS_BASE_NAME }]);
  const tableTitle = opts.tableTitle ?? SETTINGS_TABLE_NAME;
  const fetchMock = vi.fn(async (url: string, init?: { method?: string; body?: string }) => {
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${url}`);
    const json = (value: unknown) => ({ ok: true, json: async () => value }) as unknown as Response;

    if (url.endsWith('/api/v2/meta/bases')) return json({ list: bases() });
    if (/\/api\/v2\/meta\/bases\/[^/]+\/tables$/.test(url)) {
      return json({ list: [{ id: 't1', title: tableTitle }] });
    }
    if (url.includes('/api/v2/tables/t1/records')) {
      if (method === 'POST' || method === 'PATCH') return json({});
      return json({
        list: rows.map((r) => ({ ...r, Description: '' })),
        pageInfo: { isLastPage: true },
      });
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls };
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

  it('fails loudly when the store cannot answer — there is no fallback', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      })
    );
    const store = new SettingsStore(config, { PARENT_DOMAIN: 'wisp.net' });
    await expect(store.getAll()).rejects.toBeInstanceOf(SettingsUnavailableError);
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

/**
 * The base is found by name, and the name is unique because we say it is.
 * Everything here is about not carrying a base ID around: a stored ID
 * survives a rename, outlives a restore, and cannot be checked by eye.
 */
describe('base-ID detection', () => {
  it('resolves the base by name and the table inside it', async () => {
    const { calls } = stubNocoDb([{ Id: 1, Key: 'PARENT_DOMAIN', Value: 'wisp.net' }]);
    const store = new SettingsStore(config, {});
    await store.getAll();
    expect(calls[0]).toBe('GET http://nocodb.test/api/v2/meta/bases');
    expect(calls[1]).toBe('GET http://nocodb.test/api/v2/meta/bases/b1/tables');
  });

  it('says so when no base carries the name', async () => {
    stubNocoDb([], { bases: () => [{ id: 'b9', title: 'SomethingElse' }] });
    const store = new SettingsStore(config, {});
    await expect(store.getAll()).rejects.toMatchObject({
      name: 'SettingsUnavailableError',
      reason: 'base_missing',
    });
  });

  it('refuses to guess when two bases carry the name', async () => {
    stubNocoDb([], {
      bases: () => [
        { id: 'b1', title: SETTINGS_BASE_NAME },
        { id: 'b2', title: SETTINGS_BASE_NAME },
      ],
    });
    const store = new SettingsStore(config, {});
    await expect(store.getAll()).rejects.toMatchObject({ reason: 'base_ambiguous' });
  });

  it('says so when the base has no settings table', async () => {
    stubNocoDb([], { tableTitle: 'some_other_table' });
    const store = new SettingsStore(config, {});
    await expect(store.getAll()).rejects.toMatchObject({ reason: 'table_missing' });
  });

  it('never remembers an ID it could not confirm', async () => {
    let title = 'RenamedByMistake';
    stubNocoDb([{ Id: 1, Key: 'PARENT_DOMAIN', Value: 'wisp.net' }], {
      bases: () => [{ id: 'b1', title }],
    });
    const store = new SettingsStore(config, {});
    await expect(store.getAll()).rejects.toMatchObject({ reason: 'base_missing' });

    // Renamed back in NocoDB: the next read re-detects, no restart.
    title = SETTINGS_BASE_NAME;
    expect((await store.getAll()).PARENT_DOMAIN).toBe('wisp.net');
  });

  it('re-detects the base after a rename once the cache turns over', async () => {
    let baseId = 'b1';
    const { calls } = stubNocoDb([{ Id: 1, Key: 'PARENT_DOMAIN', Value: 'wisp.net' }], {
      bases: () => [{ id: baseId, title: SETTINGS_BASE_NAME }],
    });
    const store = new SettingsStore(config, {});
    await store.getAll();

    // Inside the 30s window the cached IDs are reused — no extra lookups.
    const before = calls.length;
    await store.getAll();
    expect(calls.length).toBe(before);

    // invalidate() is what the operator-facing retry does; it drops the IDs
    // as well as the values, so a base restored under a new ID is found.
    baseId = 'b2';
    store.invalidate();
    await store.getAll();
    expect(calls).toContain('GET http://nocodb.test/api/v2/meta/bases/b2/tables');
  });
});

describe('environment aliases', () => {
  it('pins trustedCIDR from an environment-shaped name', () => {
    expect(settingOverridesFromEnv({ IDENTITY_TRUSTED_NETWORK: '10.9.0.0/16' })).toEqual({
      trustedCIDR: '10.9.0.0/16',
    });
  });

  it('still honours the pre-rollout names', () => {
    expect(settingOverridesFromEnv({ ID_TRUSTED_APP_CIDRS: '10.9.0.0/16' })).toEqual({
      trustedCIDR: '10.9.0.0/16',
    });
    expect(settingOverridesFromEnv({ ID_CLIENT_SECRET: 's3cret' })).toEqual({
      IDENTITY_CLIENT_SECRET: 's3cret',
    });
  });

  it('prefers the canonical name when a deployment sets both', () => {
    expect(
      settingOverridesFromEnv({
        IDENTITY_TRUSTED_NETWORK: '10.9.0.0/16',
        ID_TRUSTED_APP_CIDRS: '192.0.2.0/24',
      })
    ).toEqual({ trustedCIDR: '10.9.0.0/16' });
  });
});
