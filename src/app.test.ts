import { describe, it, expect, beforeEach, vi } from 'vitest';
import crypto from 'crypto';
import request from 'supertest';

/**
 * HTTP-level tests of the server-to-server surface: CIDR admission,
 * proxy/spoofing behaviour, the directory API's authorization, and —
 * pinned by the POC contract — superAdmin provenance through the
 * Session → AuthCode → redemption chain.
 *
 * MySQL and NocoDB are replaced with in-memory fakes; the network-trust
 * code (src/net.ts) and every route handler run for real.
 */

// ── In-memory fakes ──────────────────────────────────────────────────────────

interface FakeSession {
  sSessionId: string;
  iUserId: number;
  bSuperAdmin: boolean;
  sProvider: string | null;
  sSubject: string | null;
  dtCreated: Date;
}

const fake = {
  settings: {} as Record<string, string>,
  /** Keys the environment pins — they win over `settings` and cannot be written. */
  overrides: {} as Record<string, string>,
  /** State of the identity database as the wizard's probe would find it. */
  db: 'ok' as 'ok' | 'unconfigured' | 'unreachable',
  /** When set, the settings store fails with this reason. */
  settingsError: null as string | null,
  sessions: new Map<string, FakeSession>(),
  authCodes: new Map<
    string,
    { iUserId: number; redirectUri: string; provider: string | null; subject: string | null; bSuperAdmin: boolean; consumed: boolean }
  >(),
  users: new Map<number, { iUserId: number; email: string | null; displayName: string | null; claimed: boolean }>(),
  nextUserId: 1,
  events: [] as Array<{ id: number; type: string; occurredAt: string; data: unknown }>,
};

function resetFakes() {
  fake.settings = { PARENT_DOMAIN: 'wisp.net' };
  fake.overrides = {};
  fake.db = 'ok';
  fake.settingsError = null;
  fake.sessions.clear();
  fake.authCodes.clear();
  fake.users.clear();
  fake.nextUserId = 1;
  fake.events = [];
}

vi.mock('./db', () => ({
  getDb: () => ({
    async query() {
      if (fake.db === 'unreachable') throw new Error('ECONNREFUSED');
      return [[{ 1: 1 }], []];
    },
  }),
  // The real one reads DB_HOST/DB_USER/DB_NAME out of the settings, so
  // "unconfigured" is what a fresh install looks like before anyone fills
  // the rows in.
  dbCoordinates: () =>
    fake.db === 'unconfigured'
      ? null
      : { host: 'db.test', port: 3306, user: 'id', password: '', database: 'id_db' },
}));

vi.mock('./settings', () => {
  class SettingsUnavailableError extends Error {
    constructor(
      public reason: string,
      message: string
    ) {
      super(message);
      this.name = 'SettingsUnavailableError';
    }
  }
  const failIfAsked = () => {
    if (fake.settingsError) {
      throw new SettingsUnavailableError(
        fake.settingsError,
        `No NocoDB base named IdentityBase at http://nocodb.test (${fake.settingsError})`
      );
    }
  };
  class SettingsStore {
    async getAll() {
      failIfAsked();
      return { ...fake.settings, ...fake.overrides };
    }
    async ping() {
      failIfAsked();
    }
    fromEnvOnly() {
      return { ...fake.overrides };
    }
    async get(key: string) {
      return { ...fake.settings, ...fake.overrides }[key];
    }
    isOverridden(key: string) {
      return key in fake.overrides;
    }
    overriddenKeys() {
      return Object.keys(fake.overrides);
    }
    invalidate() {}
    isConfigured() {
      return true;
    }
    async bootstrap() {
      failIfAsked();
    }
    async listForAdmin() {
      return Object.entries({ ...fake.settings, ...fake.overrides }).map(([key, value]) => ({
        key,
        value,
        description: '',
        source: key in fake.overrides ? 'environment' : 'store',
      }));
    }
    async set(key: string, value: string) {
      fake.settings[key] = value;
    }
  }
  return {
    SettingsStore,
    SettingsUnavailableError,
    SETTINGS_BASE_NAME: 'IdentityBase',
    SETTINGS_TABLE_NAME: 'auth_tbl_Settings',
  };
});

vi.mock('./webhooks', () => ({
  EVENT_TYPES: ['ping', 'session.revoked', 'user.merged', 'identity.linked', 'identity.unlinked'],
  FAILING_THRESHOLD: 1,
  emitEvent: vi.fn(async () => 1),
}));

vi.mock('./store', () => {
  const generateId = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');
  return {
    generateId,
    getSession: async (_db: unknown, id: string) => fake.sessions.get(id) ?? null,
    createSession: async () => generateId(32),
    touchLastLogin: async () => {},
    createAuthCode: async (
      _db: unknown,
      params: { iUserId: number; redirectUri: string; provider: string | null; subject: string | null; bSuperAdmin: boolean }
    ) => {
      const code = generateId(32);
      fake.authCodes.set(code, { ...params, consumed: false });
      return code;
    },
    consumeAuthCode: async (_db: unknown, code: string, redirectUri: string) => {
      const row = fake.authCodes.get(code);
      if (!row || row.consumed || row.redirectUri !== redirectUri) return null;
      row.consumed = true;
      return {
        iUserId: row.iUserId,
        sProvider: row.provider,
        sSubject: row.subject,
        bSuperAdmin: row.bSuperAdmin,
      };
    },
    getUser: async (_db: unknown, id: number) => {
      const u = fake.users.get(id);
      return u ? { iUserId: u.iUserId, email: u.email, displayName: u.displayName, dtCreated: new Date(), dtLastLogin: null } : null;
    },
    listIdentities: async () => [],
    recordAppOrigin: async () => {},
    registerApp: async () => ({ secret: 'app-secret', rotated: false }),
    getAppSecret: async () => null,
    listApps: async () => [],
    pendingDeliveryCounts: async () => ({}),
    listEventsSince: async (_db: unknown, since: number) => fake.events.filter((e) => e.id > since),
    adminListUsers: async () => [],
    revokeSession: async () => {},
    revokeAllSessions: async () => 0,
    findUserByIdentity: async () => null,
    findUserByEmail: async () => null,
    createUser: async () => fake.nextUserId++,
    ensureIdentity: async () => {},
    getIdentity: async () => null,
    deleteIdentity: async () => {},
    countIdentities: async () => 1,
    mergeUsers: async () => ({ movedIdentities: 0, revokedSessions: 0 }),
    consumeNonce: async () => true,
    ensureDirectoryUser: async (
      _db: unknown,
      params: { email: string; displayName: string | null; idempotencyKey: string | null }
    ) => {
      for (const u of fake.users.values()) {
        if (u.email === params.email) return { ...u };
      }
      const user = {
        iUserId: fake.nextUserId++,
        email: params.email,
        displayName: params.displayName,
        claimed: false,
      };
      fake.users.set(user.iUserId, user);
      return { ...user };
    },
    getDirectoryUser: async (_db: unknown, id: number) => {
      const u = fake.users.get(id);
      return u ? { ...u } : null;
    },
    searchDirectoryUsers: async (
      _db: unknown,
      params: { query: string; limit: number; cursor: number }
    ) => {
      const all = [...fake.users.values()]
        .filter((u) => u.iUserId > params.cursor)
        .filter(
          (u) =>
            !params.query ||
            (u.email ?? '').includes(params.query) ||
            (u.displayName ?? '').includes(params.query)
        )
        .sort((a, b) => a.iUserId - b.iUserId);
      const items = all.slice(0, params.limit).map((u) => ({ ...u }));
      return { items, nextCursor: all.length > params.limit ? items[items.length - 1].iUserId : null };
    },
  };
});

import { buildApp } from './app';

const ENV_KEYS = [
  'IDENTITY_APP_AUTH_MODE',
  'IDENTITY_TRUSTED_PROXY_CIDRS',
  'ID_APP_AUTH_MODE',
  'ID_TRUSTED_PROXY_CIDRS',
  'NODE_ENV',
] as const;

/**
 * `trustedCIDR` is a setting, not an environment variable — one value for
 * the whole platform, read from the settings store per request — so the
 * harness seeds it there and leaves the environment for the rest.
 */
function makeApp(
  opts: Partial<Record<(typeof ENV_KEYS)[number], string>> & { trustedCIDR?: string } = {}
) {
  const { trustedCIDR, ...env } = opts;
  for (const k of ENV_KEYS) delete process.env[k];
  Object.assign(process.env, env);
  if (trustedCIDR !== undefined) fake.settings.trustedCIDR = trustedCIDR;
  return buildApp().app;
}

function seedSession(params: { iUserId: number; bSuperAdmin: boolean; email: string | null }) {
  const sSessionId = crypto.randomBytes(32).toString('hex');
  fake.sessions.set(sSessionId, {
    sSessionId,
    iUserId: params.iUserId,
    bSuperAdmin: params.bSuperAdmin,
    sProvider: 'google',
    sSubject: `sub-${params.iUserId}`,
    dtCreated: new Date(),
  });
  fake.users.set(params.iUserId, {
    iUserId: params.iUserId,
    email: params.email,
    displayName: 'Test User',
    claimed: true,
  });
  return sSessionId;
}

// supertest connects over loopback, so 127.0.0.1/32 = "caller is trusted".
const LOOPBACK = '127.0.0.1/32';
const ELSEWHERE = '10.9.0.0/16';
const REDIRECT = 'https://app.wisp.net/auth/callback';

beforeEach(resetFakes);

// ── CIDR admission on the app endpoints ──────────────────────────────────────

describe('CIDR trust on /api/token, /api/apps/register, /api/events', () => {
  it('allows a peer inside trustedCIDR (exact /32), no client secret needed', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).get('/api/events?since=0');
    expect(res.status).toBe(200);
    expect(res.body.items).toEqual([]);
  });

  it('allows a peer inside a subnet range', async () => {
    // Trusted-proxy loopback lets the test present a subnet client address.
    const app = makeApp({
      trustedCIDR: ELSEWHERE,
      IDENTITY_TRUSTED_PROXY_CIDRS: LOOPBACK,
    });
    const res = await request(app).get('/api/events?since=0').set('X-Forwarded-For', '10.9.44.5');
    expect(res.status).toBe(200);
  });

  it('rejects a peer outside the allowlist with a generic 403 + correlation id', async () => {
    const app = makeApp({ trustedCIDR: ELSEWHERE });
    const res = await request(app).get('/api/events?since=0');
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Forbidden');
    expect(res.body.correlationId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('rejects everything when the allowlist is empty', async () => {
    const app = makeApp({});
    const res = await request(app).post('/api/apps/register').send({ webhook_url: REDIRECT });
    expect(res.status).toBe(403);
  });

  it('ignores a spoofed X-Forwarded-For when the peer is not a trusted proxy', async () => {
    const app = makeApp({ trustedCIDR: ELSEWHERE });
    const res = await request(app).get('/api/events?since=0').set('X-Forwarded-For', '10.9.0.5');
    expect(res.status).toBe(403);
  });

  it('rejects IPv6/mapped forms smuggled through a trusted proxy header', async () => {
    const app = makeApp({
      trustedCIDR: ELSEWHERE,
      IDENTITY_TRUSTED_PROXY_CIDRS: LOOPBACK,
    });
    for (const spoof of ['::ffff:10.9.0.5', '2001:db8::1', 'garbage']) {
      const res = await request(app).get('/api/events?since=0').set('X-Forwarded-For', spoof);
      expect(res.status).toBe(403);
    }
  });

  it('evaluates a reverse-proxy chain only across configured trusted hops', async () => {
    const app = makeApp({
      trustedCIDR: ELSEWHERE,
      IDENTITY_TRUSTED_PROXY_CIDRS: `${LOOPBACK}, 172.16.0.0/24`,
    });
    // client 10.9.0.5 → proxy 172.16.0.2 → loopback → id: allowed
    const ok = await request(app)
      .get('/api/events?since=0')
      .set('X-Forwarded-For', '10.9.0.5, 172.16.0.2');
    expect(ok.status).toBe(200);
    // attacker outside the allowlist behind the same proxies: denied
    const bad = await request(app)
      .get('/api/events?since=0')
      .set('X-Forwarded-For', '198.51.100.9, 172.16.0.2');
    expect(bad.status).toBe(403);
  });
});

describe('IDENTITY_APP_AUTH_MODE rollout flag', () => {
  it("mode=cidr ignores a valid legacy secret from an untrusted peer", async () => {
    fake.settings.IDENTITY_CLIENT_SECRET = 's3cret';
    const app = makeApp({ IDENTITY_APP_AUTH_MODE: 'cidr', trustedCIDR: ELSEWHERE });
    const res = await request(app)
      .get('/api/events?since=0')
      .set('X-Id-Client-Secret', 's3cret');
    expect(res.status).toBe(403);
  });

  it('mode=secret keeps the legacy check and does not require a CIDR match', async () => {
    fake.settings.IDENTITY_CLIENT_SECRET = 's3cret';
    const app = makeApp({ IDENTITY_APP_AUTH_MODE: 'secret', trustedCIDR: ELSEWHERE });
    const ok = await request(app).get('/api/events?since=0').set('X-Id-Client-Secret', 's3cret');
    expect(ok.status).toBe(200);
    const bad = await request(app).get('/api/events?since=0').set('X-Id-Client-Secret', 'wrong');
    expect(bad.status).toBe(403);
  });

  it('mode=dual accepts either a trusted peer or a valid secret', async () => {
    fake.settings.IDENTITY_CLIENT_SECRET = 's3cret';
    const byIp = makeApp({ IDENTITY_APP_AUTH_MODE: 'dual', trustedCIDR: LOOPBACK });
    expect((await request(byIp).get('/api/events?since=0')).status).toBe(200);

    const bySecret = makeApp({ IDENTITY_APP_AUTH_MODE: 'dual', trustedCIDR: ELSEWHERE });
    expect(
      (await request(bySecret).get('/api/events?since=0').set('X-Id-Client-Secret', 's3cret')).status
    ).toBe(200);
    expect(
      (await request(bySecret).get('/api/events?since=0').set('X-Id-Client-Secret', 'nope')).status
    ).toBe(403);
  });
});

// ── superAdmin provenance (pinned by the POC contract) ───────────────────────

describe('superAdmin provenance: Session → AuthCode → redemption', () => {
  async function authorizeAndRedeem(session: { iUserId: number; bSuperAdmin: boolean; email: string | null }) {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const sessionId = seedSession(session);

    const auth = await request(app)
      .get('/authorize')
      .query({ redirect_uri: REDIRECT, state: 'opaque-123' })
      .set('Cookie', `identity_sso=${sessionId}`);
    expect(auth.status).toBe(302);
    const location = new URL(auth.headers.location);
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT);
    expect(location.searchParams.get('state')).toBe('opaque-123');
    const code = location.searchParams.get('code')!;
    expect(code).toMatch(/^[0-9a-f]{64}$/);

    const token = await request(app)
      .post('/api/token')
      .send({ code, redirect_uri: REDIRECT });
    return token;
  }

  it("redemption returns the session's bSuperAdmin — email plays no part", async () => {
    // The email is NOT on any super-admin domain; only the session says admin.
    const res = await authorizeAndRedeem({
      iUserId: 7,
      bSuperAdmin: true,
      email: 'eve@outside.example',
    });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ iUserId: 7, superAdmin: true });
  });

  it('redemption never recalculates privilege from an on-domain email', async () => {
    // The email IS on the super-admin domain, but the session says not-admin.
    fake.settings.SUPERADMIN_DOMAIN = 'wisp.net';
    const res = await authorizeAndRedeem({
      iUserId: 8,
      bSuperAdmin: false,
      email: 'admin@wisp.net',
    });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ iUserId: 8, superAdmin: false });
  });

  it('codes are single-use and bound to the exact redirect_uri', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const sessionId = seedSession({ iUserId: 9, bSuperAdmin: false, email: 'a@wisp.net' });
    const auth = await request(app)
      .get('/authorize')
      .query({ redirect_uri: REDIRECT })
      .set('Cookie', `identity_sso=${sessionId}`);
    const code = new URL(auth.headers.location).searchParams.get('code')!;

    const wrongUri = await request(app)
      .post('/api/token')
      .send({ code, redirect_uri: 'https://other.wisp.net/cb' });
    expect(wrongUri.status).toBe(400);

    const ok = await request(app).post('/api/token').send({ code, redirect_uri: REDIRECT });
    expect(ok.status).toBe(200);

    const replay = await request(app).post('/api/token').send({ code, redirect_uri: REDIRECT });
    expect(replay.status).toBe(400);
  });
});

// ── Directory API ────────────────────────────────────────────────────────────

describe('directory API', () => {
  it('is CIDR-only: a valid client secret never grants access, in any mode', async () => {
    fake.settings.IDENTITY_CLIENT_SECRET = 's3cret';
    const app = makeApp({ IDENTITY_APP_AUTH_MODE: 'dual', trustedCIDR: ELSEWHERE });
    const res = await request(app)
      .post('/api/directory/users')
      .set('X-Id-Client-Secret', 's3cret')
      .send({ email: 'a@wisp.net', client_secret: 's3cret' });
    expect(res.status).toBe(403);
  });

  it('ensure is idempotent and returns minimal fields only', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const first = await request(app)
      .post('/api/directory/users')
      .send({ email: 'Ada@Wisp.NET', displayName: 'Ada', idempotencyKey: 'k1' });
    expect(first.status).toBe(200);
    expect(first.body).toEqual({
      iUserId: expect.any(Number),
      email: 'ada@wisp.net',
      displayName: 'Ada',
      claimed: false,
    });

    const second = await request(app)
      .post('/api/directory/users')
      .send({ email: 'ada@wisp.net', displayName: 'Ada', idempotencyKey: 'k1' });
    expect(second.body.iUserId).toBe(first.body.iUserId);
  });

  it('validates input', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    expect((await request(app).post('/api/directory/users').send({})).status).toBe(400);
    expect(
      (await request(app).post('/api/directory/users').send({ email: 'not-an-email' })).status
    ).toBe(400);
  });

  it('gets a user by iUserId and 404s unknown ids without leaking', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const created = await request(app)
      .post('/api/directory/users')
      .send({ email: 'b@wisp.net' });
    const got = await request(app).get(`/api/directory/users/${created.body.iUserId}`);
    expect(got.status).toBe(200);
    expect(got.body).toEqual(created.body);
    expect((await request(app).get('/api/directory/users/999999')).status).toBe(404);
    expect((await request(app).get('/api/directory/users/abc')).status).toBe(400);
  });

  it('searches with bounded pagination and a cursor', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    for (let i = 1; i <= 4; i++) {
      await request(app).post('/api/directory/users').send({ email: `user${i}@wisp.net` });
    }
    const page1 = await request(app).get('/api/directory/users?query=user&limit=3');
    expect(page1.status).toBe(200);
    expect(page1.body.items).toHaveLength(3);
    expect(page1.body.nextCursor).toBe(page1.body.items[2].iUserId);

    const page2 = await request(app).get(
      `/api/directory/users?query=user&limit=3&cursor=${page1.body.nextCursor}`
    );
    expect(page2.body.items).toHaveLength(1);
    expect(page2.body.nextCursor).toBeNull();

    expect((await request(app).get('/api/directory/users?limit=0')).status).toBe(400);
    expect((await request(app).get('/api/directory/users?limit=101')).status).toBe(400);
    expect((await request(app).get('/api/directory/users?cursor=-1')).status).toBe(400);
  });

  it('rejects browser-style requests from outside the allowlist', async () => {
    const app = makeApp({ trustedCIDR: ELSEWHERE });
    const res = await request(app).get('/api/directory/users?query=a');
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'Forbidden', correlationId: expect.any(String) });
  });
});

// ── Zero-config: where this service thinks it lives ──────────────────────────

/**
 * APP_BASE_URL has three possible answers and a strict order: the
 * environment override, the settings row, and — when neither exists — the
 * URL the browser actually used. Nothing else is invented, and the setup
 * wizard writes down what the browser reported rather than a guess.
 */
describe('APP_BASE_URL resolution', () => {
  const CREDENTIALS = { provider: 'google', clientId: 'gid', clientSecret: 'gsecret' };

  function redirectUriOf(authUrl: string): string {
    return new URL(authUrl).searchParams.get('redirect_uri') ?? '';
  }

  it('offers no server-side guess to the wizard, only what is already pinned', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).get('/api/setup/status').set('Host', 'identity.wisp.net');
    expect(res.status).toBe(200);
    expect(res.body.pinned).toEqual({ appBaseUrl: '', parentDomain: 'wisp.net' });
    expect(res.body.locked).toEqual({ appBaseUrl: false, parentDomain: false });
    expect(res.body.identityHostLabel).toBe('identity');
  });

  it('reports a pinned value as locked so the wizard cannot contradict it', async () => {
    fake.overrides.APP_BASE_URL = 'https://identity.wisp.net';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).get('/api/setup/status');
    expect(res.body.pinned.appBaseUrl).toBe('https://identity.wisp.net');
    expect(res.body.locked.appBaseUrl).toBe(true);
  });

  it('builds the OAuth callback from the URL the browser reported', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'https://identity.wisp.net/setup', ...CREDENTIALS });
    expect(res.status).toBe(200);
    expect(redirectUriOf(res.body.authUrl)).toBe('https://identity.wisp.net/auth/google/callback');
  });

  it('falls back to the request when the browser sends nothing', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app)
      .post('/api/setup/start')
      .set('X-Forwarded-Proto', 'https')
      .set('X-Forwarded-Host', 'identity.wisp.net')
      .send({ parentDomain: 'wisp.net', ...CREDENTIALS });
    expect(res.status).toBe(200);
    expect(redirectUriOf(res.body.authUrl)).toBe('https://identity.wisp.net/auth/google/callback');
  });

  it('rejects a base URL that is not one', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'identity.wisp.net', ...CREDENTIALS });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('https://identity.wisp.net');
  });

  it('in production, refuses a base URL off the domain being claimed', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK, NODE_ENV: 'production' });
    const off = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'https://identity.attacker.example', ...CREDENTIALS });
    expect(off.status).toBe(400);
    expect(off.body.error).toContain('wisp.net');

    const on = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'https://identity.wisp.net', ...CREDENTIALS });
    expect(on.status).toBe(200);
  });

  it('lets the environment override win over the browser', async () => {
    fake.overrides.APP_BASE_URL = 'https://identity.wisp.net';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'https://somewhere.else.example', ...CREDENTIALS });
    expect(res.status).toBe(200);
    expect(redirectUriOf(res.body.authUrl)).toBe('https://identity.wisp.net/auth/google/callback');
  });
});

describe('/admin config and the environment', () => {
  it('reports each setting with the source that is actually in force', async () => {
    fake.overrides.APP_BASE_URL = 'https://identity.wisp.net';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const session = seedSession({ iUserId: 1, bSuperAdmin: true, email: 'admin@wisp.net' });
    const res = await request(app).get('/api/admin/config').set('Cookie', `identity_sso=${session}`);
    expect(res.status).toBe(200);
    expect(res.body.appBaseUrl).toBe('https://identity.wisp.net');
    expect(res.body.appBaseUrlSource).toBe('environment');
    expect(res.body.items).toContainEqual(
      expect.objectContaining({ key: 'APP_BASE_URL', source: 'environment' })
    );
    expect(res.body.providers[0].callbackUrl).toBe('https://identity.wisp.net/auth/google/callback');
  });

  it('says the callback URLs follow the request when nothing pins them', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const session = seedSession({ iUserId: 1, bSuperAdmin: true, email: 'admin@wisp.net' });
    const res = await request(app)
      .get('/api/admin/config')
      .set('Cookie', `identity_sso=${session}`)
      .set('X-Forwarded-Proto', 'https')
      .set('X-Forwarded-Host', 'identity.wisp.net');
    expect(res.body.appBaseUrl).toBe('https://identity.wisp.net');
    expect(res.body.appBaseUrlSource).toBe('request');
  });

  it('refuses a write to a key the environment pins, and says why', async () => {
    fake.overrides.APP_BASE_URL = 'https://identity.wisp.net';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const session = seedSession({ iUserId: 1, bSuperAdmin: true, email: 'admin@wisp.net' });
    const res = await request(app)
      .put('/api/admin/config/APP_BASE_URL')
      .set('Cookie', `identity_sso=${session}`)
      .send({ value: 'https://elsewhere.wisp.net' });
    expect(res.status).toBe(409);
    expect(res.body.error).toContain('environment');
    expect(fake.settings.APP_BASE_URL).toBeUndefined();
  });
});

// ── The .env carries two things; the rest is settings ────────────────────────

describe('trusted network', () => {
  it('is one value read from the settings, not the environment', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    expect((await request(app).get('/api/events?since=0')).status).toBe(200);

    const elsewhere = makeApp({ trustedCIDR: ELSEWHERE });
    expect((await request(elsewhere).get('/api/events?since=0')).status).toBe(403);
  });

  it('follows a change in the settings without a restart', async () => {
    const app = makeApp({ trustedCIDR: ELSEWHERE });
    expect((await request(app).get('/api/events?since=0')).status).toBe(403);

    // What a NocoDB edit looks like once the 30s cache has turned over.
    fake.settings.trustedCIDR = LOOPBACK;
    expect((await request(app).get('/api/events?since=0')).status).toBe(200);
  });

  it('trusts nobody when it is unset', async () => {
    const app = makeApp({});
    expect((await request(app).get('/api/events?since=0')).status).toBe(403);
  });
});

/**
 * No fallback: an app that cannot read its configuration says so. The
 * alternative — carrying on as though nothing were configured — renders a
 * missing base as a login page with no buttons, which reads as an
 * application fault rather than the configuration fault it is.
 */
describe('settings store unavailable', () => {
  it('answers 503 and names the reason instead of pretending', async () => {
    fake.settingsError = 'base_missing';
    const app = makeApp({ trustedCIDR: LOOPBACK });

    const page = await request(app).get('/').set('Accept', 'text/html');
    expect(page.status).toBe(503);

    const api = await request(app).get('/api/providers').set('Accept', 'application/json');
    expect(api.status).toBe(503);
    expect(api.body.reason).toBe('base_missing');
    expect(api.body.error).toContain('IdentityBase');
  });

  it('keeps answering /healthz, which needs no settings', async () => {
    fake.settingsError = 'unreachable';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, service: 'identity' });
  });

  it('re-detects on retry rather than remembering the failure', async () => {
    fake.settingsError = 'base_missing';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    expect((await request(app).get('/api/settings/health')).status).toBe(503);

    fake.settingsError = null; // the base was created (or renamed back)
    const res = await request(app).get('/api/settings/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, base: 'IdentityBase', table: 'auth_tbl_Settings' });
  });
});

/**
 * The identity database is a setting like any other, so "not filled in yet"
 * is an ordinary first-run state: the app answers, and the wizard says which
 * store is missing instead of failing at the moment of the claim.
 */
describe('id_db as a setting', () => {
  const CREDENTIALS = { provider: 'google', clientId: 'gid', clientSecret: 'gsecret' };

  it('tells the wizard the database is not configured yet', async () => {
    fake.db = 'unconfigured';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).get('/api/setup/status');
    expect(res.status).toBe(200);
    expect(res.body.database).toBe('unconfigured');
    expect(res.body.databaseHint).toContain('DB_HOST');
  });

  it('reports an unreachable database separately from an unset one', async () => {
    fake.db = 'unreachable';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).get('/api/setup/status');
    expect(res.body.database).toBe('unreachable');
  });

  it('refuses to start a claim it could not record', async () => {
    fake.db = 'unconfigured';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'https://identity.wisp.net', ...CREDENTIALS });
    expect(res.status).toBe(503);
    expect(res.body.error).toContain('DB_HOST');
  });

  it('proceeds once both stores answer', async () => {
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const status = await request(app).get('/api/setup/status');
    expect(status.body.database).toBe('ok');
    const res = await request(app)
      .post('/api/setup/start')
      .send({ parentDomain: 'wisp.net', appBaseUrl: 'https://identity.wisp.net', ...CREDENTIALS });
    expect(res.status).toBe(200);
  });
});

describe('first-run database step', () => {
  it('refuses coordinates it could not connect to, and saves nothing', async () => {
    fake.db = 'unconfigured';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app)
      .post('/api/setup/database')
      .send({ host: 'nope.invalid', user: 'identity', database: 'identity_db' });
    expect(res.status).toBe(400);
    expect(fake.settings.DB_HOST).toBeUndefined();
  });

  it('requires host, user and database', async () => {
    fake.db = 'unconfigured';
    const app = makeApp({ trustedCIDR: LOOPBACK });
    const res = await request(app).post('/api/setup/database').send({ host: 'mysql.internal' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('required');
  });
});
