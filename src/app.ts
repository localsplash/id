import express from 'express';
import path from 'path';
import pinoHttp from 'pino-http';
import pino from 'pino';
import { loadConfig } from './config';
import { getDb } from './db';
import { SettingsStore, Settings } from './settings';
import {
  PROVIDERS,
  getProvider,
  isProviderConfigured,
  availableLoginMethods,
  isSuperAdmin,
  isTenantLocked,
  OAuthState,
  OAuthUserInfo,
  ProviderDescriptor,
} from './providers';
import {
  SESSION_COOKIE,
  getCookie,
  setSessionCookie,
  clearSessionCookie,
  setOAuthStateCookie,
  clearOAuthStateCookie,
  OAUTH_STATE_COOKIE,
  decodeState,
  setAuthRequestCookie,
  clearAuthRequestCookie,
  getAuthRequestFromCookie,
  validateRedirectUri,
  verifySsoCode,
  SetupRequest,
  setSetupCookie,
  clearSetupCookie,
  getSetupFromCookie,
  suggestParentDomain,
  isValidDomain,
} from './web';
import * as store from './store';

const publicDir = path.join(__dirname, '..', 'public');

export function buildApp() {
  const config = loadConfig();
  const db = getDb(config);
  const settingsStore = new SettingsStore(config);
  const logger = pino({ level: config.LOG_LEVEL });
  const app = express();

  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(pinoHttp({ logger }));
  app.use(express.static(publicDir, { index: false }));

  /**
   * Settings are read per-request (30s cache in the store) so a config change
   * in NocoDB takes effect without a restart. When NocoDB is unreachable we
   * fall back to "nothing configured" — the login page then honestly shows no
   * methods rather than the app crashing.
   */
  async function getSettings(): Promise<Settings> {
    try {
      return await settingsStore.getAll();
    } catch (err) {
      logger.error({ err }, '[settings] NocoDB read failed');
      return {};
    }
  }

  function baseUrl(settings: Settings, req: express.Request): string {
    if (settings.APP_BASE_URL) return settings.APP_BASE_URL.replace(/\/+$/, '');
    const proto = String(req.headers['x-forwarded-proto'] ?? req.protocol ?? 'https').split(',')[0];
    const host = String(req.headers['x-forwarded-host'] ?? req.headers.host ?? '');
    return `${proto}://${host}`;
  }

  async function resolveSession(req: express.Request): Promise<store.SessionRow | null> {
    const id = getCookie(req, SESSION_COOKIE);
    if (!id) return null;
    return store.getSession(db, id);
  }

  // ── Login completion (shared by every provider and the UISP bridge) ────────

  /**
   * The user has proven who they are; give them an id session and send them
   * wherever they were headed. If an application's /authorize request is
   * pending, mint a one-time handoff code and complete the round trip;
   * otherwise fall back to DEFAULT_REDIRECT_URI (state=sso marks it as an
   * unsolicited SSO entry, e.g. straight from the ISP portal) or the account
   * page.
   */
  async function finishLogin(
    req: express.Request,
    res: express.Response,
    settings: Settings,
    params: {
      iUserId: number;
      provider: string;
      subject: string;
      superAdmin: boolean;
    }
  ): Promise<string> {
    await store.touchLastLogin(db, params.iUserId);
    const sessionId = await store.createSession(
      db,
      params.iUserId,
      params.superAdmin,
      params.provider,
      params.subject
    );
    setSessionCookie(res, settings, sessionId);

    const authreq = getAuthRequestFromCookie(req);
    clearAuthRequestCookie(res);

    if (authreq) {
      const redirectUri = validateRedirectUri(authreq.redirect_uri, settings, config.NODE_ENV);
      if (redirectUri) {
        const code = await store.createAuthCode(db, {
          iUserId: params.iUserId,
          redirectUri,
          provider: params.provider,
          subject: params.subject,
          bSuperAdmin: params.superAdmin,
        });
        const url = new URL(redirectUri);
        url.searchParams.set('code', code);
        if (authreq.state) url.searchParams.set('state', authreq.state);
        return url.toString();
      }
    }

    const fallback = settings.DEFAULT_REDIRECT_URI
      ? validateRedirectUri(settings.DEFAULT_REDIRECT_URI, settings, config.NODE_ENV)
      : null;
    if (fallback) {
      const code = await store.createAuthCode(db, {
        iUserId: params.iUserId,
        redirectUri: fallback,
        provider: params.provider,
        subject: params.subject,
        bSuperAdmin: params.superAdmin,
      });
      const url = new URL(fallback);
      url.searchParams.set('code', code);
      url.searchParams.set('state', 'sso');
      return url.toString();
    }

    return '/account';
  }

  /**
   * Map a provider identity onto an id user. Match by (provider, subject)
   * first; when the provider vouches for the address (trustEmail), fall
   * back to matching an existing user by email so a person's different
   * logins converge on one account. Unverified addresses never auto-link —
   * they create a fresh user unless linked explicitly from the account page.
   */
  async function upsertUserForIdentity(
    providerId: string,
    trustEmail: boolean,
    userInfo: OAuthUserInfo
  ): Promise<number> {
    let iUserId = await store.findUserByIdentity(db, providerId, userInfo.sub);
    if (!iUserId && trustEmail && userInfo.email) {
      iUserId = await store.findUserByEmail(db, userInfo.email);
    }
    if (!iUserId) {
      iUserId = await store.createUser(db, userInfo.email || null, userInfo.name || null);
    }
    await store.ensureIdentity(db, iUserId, providerId, userInfo.sub, userInfo.email || null);
    return iUserId;
  }

  /**
   * "Unclaimed" = no OAuth provider has working config yet, so nobody can
   * sign in and nobody is Super System Admin. In that state the first-run
   * setup wizard is open; the moment one provider is configured it closes.
   */
  function isUnclaimed(settings: Settings): boolean {
    return !PROVIDERS.some((p) => isProviderConfigured(p, settings));
  }

  // ── Basic pages ────────────────────────────────────────────────────────────

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, service: 'id' });
  });

  app.get('/', async (req, res) => {
    const session = await resolveSession(req);
    if (session) return res.redirect('/account');
    const settings = await getSettings();
    if (isUnclaimed(settings)) return res.redirect('/setup');
    return res.sendFile(path.join(publicDir, 'login.html'));
  });

  app.get('/account', async (req, res) => {
    const session = await resolveSession(req);
    if (!session) return res.redirect('/');
    return res.sendFile(path.join(publicDir, 'account.html'));
  });

  app.get('/admin', async (req, res) => {
    const session = await resolveSession(req);
    if (!session?.bSuperAdmin) return res.redirect('/');
    return res.sendFile(path.join(publicDir, 'admin.html'));
  });

  // Which login methods are currently usable. A method whose settings are
  // missing is absent — the login page renders only what can actually work.
  app.get('/api/providers', async (_req, res) => {
    const settings = await getSettings();
    res.json({ items: availableLoginMethods(settings), unclaimed: isUnclaimed(settings) });
  });

  // ── First-run setup wizard ─────────────────────────────────────────────────

  app.get('/setup', async (_req, res) => {
    const settings = await getSettings();
    if (!isUnclaimed(settings)) return res.redirect('/');
    return res.sendFile(path.join(publicDir, 'setup.html'));
  });

  app.get('/api/setup/status', async (req, res) => {
    settingsStore.invalidate();
    const settings = await getSettings();

    let nocodb: 'ok' | 'unconfigured' | 'unreachable' = 'ok';
    let nocodbHint: string | undefined;
    if (!settingsStore.isConfigured()) {
      nocodb = 'unconfigured';
      nocodbHint =
        'NOCODB_API_TOKEN is not set. Generate an API token in NocoDB ' +
        '(Account → Tokens) and set NOCODB_API_TOKEN (and NOCODB_BASE_URL) ' +
        "in this app's environment, then restart it.";
    } else {
      try {
        await settingsStore.ping();
      } catch {
        nocodb = 'unreachable';
        nocodbHint =
          `NocoDB at ${config.NOCODB_BASE_URL} did not accept the request. ` +
          'Check NOCODB_BASE_URL and NOCODB_API_TOKEN in the environment.';
      }
    }

    const base = baseUrl(settings, req);
    return res.json({
      unclaimed: isUnclaimed(settings),
      nocodb,
      nocodbHint,
      suggested: {
        parentDomain: settings.PARENT_DOMAIN ?? suggestParentDomain(String(req.headers.host ?? '')),
        appBaseUrl: base,
      },
      callbackUrls: {
        google: `${base}/auth/google/callback`,
        microsoft: `${base}/auth/microsoft/callback`,
      },
    });
  });

  /**
   * Step 2 of the wizard: hold the typed-in credentials in a short-lived
   * cookie and send the person through a real OAuth round trip against
   * them. Nothing touches the settings store yet — that happens in the
   * callback, and only if the round trip works AND the signed-in address is
   * provably on the claimed domain.
   */
  app.post('/api/setup/start', async (req, res, next) => {
    try {
      settingsStore.invalidate();
      const settings = await getSettings();
      if (!isUnclaimed(settings)) {
        return res.status(409).json({ error: 'This instance is already set up.' });
      }
      if (!settingsStore.isConfigured()) {
        return res.status(503).json({
          error:
            'NOCODB_API_TOKEN must be set in the environment before setup can save anything.',
        });
      }
      try {
        await settingsStore.ping();
      } catch {
        return res.status(503).json({
          error: `NocoDB at ${config.NOCODB_BASE_URL} is unreachable or rejected the token — fix the environment first.`,
        });
      }

      const body = (req.body ?? {}) as Record<string, string>;
      const parentDomain = String(body.parentDomain ?? '').trim().toLowerCase();
      const providerId = String(body.provider ?? '');
      const clientId = String(body.clientId ?? '').trim();
      const clientSecret = String(body.clientSecret ?? '').trim();
      const tenant = String(body.tenant ?? '').trim();

      if (!isValidDomain(parentDomain)) {
        return res.status(400).json({ error: 'Enter a valid parent domain, e.g. example.com.' });
      }
      // The wizard is limited to providers that can prove the claimer's domain.
      if (providerId !== 'google' && providerId !== 'microsoft') {
        return res.status(400).json({ error: 'Setup supports Google or Microsoft only.' });
      }
      if (!clientId || !clientSecret) {
        return res.status(400).json({ error: 'Client ID and client secret are required.' });
      }
      if (providerId === 'microsoft' && !isTenantLocked({ MICROSOFT_TENANT: tenant })) {
        return res.status(400).json({
          error:
            "Microsoft setup needs your directory (tenant) ID — with 'common' any tenant " +
            'could assert an address on your domain, so it cannot prove the claim.',
        });
      }

      const setup: SetupRequest = {
        csrf: store.generateId(16),
        parentDomain,
        appBaseUrl: baseUrl(settings, req),
        provider: providerId,
        clientId,
        clientSecret,
        tenant: tenant || undefined,
      };
      setSetupCookie(res, setup);

      const state: OAuthState = { csrf: setup.csrf, context: 'setup', provider: providerId };
      setOAuthStateCookie(res, state);

      const provider = getProvider(providerId)!;
      const candidate = candidateSettings(setup);
      return res.json({
        authUrl: provider.buildAuthUrl(
          candidate,
          setup.appBaseUrl,
          Buffer.from(JSON.stringify(state)).toString('base64url')
        ),
      });
    } catch (err) {
      next(err);
    }
  });

  /** The settings the wizard is proposing, before anything is saved. */
  function candidateSettings(setup: SetupRequest): Settings {
    const candidate: Settings = {
      PARENT_DOMAIN: setup.parentDomain,
      APP_BASE_URL: setup.appBaseUrl,
    };
    if (setup.provider === 'google') {
      candidate.GOOGLE_CLIENT_ID = setup.clientId;
      candidate.GOOGLE_CLIENT_SECRET = setup.clientSecret;
    } else {
      candidate.MICROSOFT_CLIENT_ID = setup.clientId;
      candidate.MICROSOFT_CLIENT_SECRET = setup.clientSecret;
      candidate.MICROSOFT_TENANT = setup.tenant ?? 'common';
    }
    return candidate;
  }

  /**
   * Finish the claim: the round trip came back, so the credentials work.
   * The claim itself holds only if the person who signed in would be Super
   * System Admin under the very settings being proposed — same rule, same
   * code path, as every later login.
   */
  async function handleSetupCallback(
    req: express.Request,
    res: express.Response,
    provider: ProviderDescriptor,
    stored: OAuthState
  ): Promise<string> {
    clearSetupCookie(res);

    settingsStore.invalidate();
    const current = await getSettings();
    if (!isUnclaimed(current)) return '/?auth_error=already_claimed';

    const setup = getSetupFromCookie(req);
    if (!setup || setup.csrf !== stored.csrf || setup.provider !== provider.id) {
      return '/setup?error=state';
    }

    const returned = decodeState(String(req.query.state ?? ''));
    if (!returned || returned.csrf !== stored.csrf) return '/setup?error=state';
    if (req.query.error) return '/setup?error=denied';
    const code = String(req.query.code ?? '');
    if (!code) return '/setup?error=denied';

    const candidate = candidateSettings(setup);
    const userInfo = await provider.fetchUserInfo(candidate, setup.appBaseUrl, code);
    if (!userInfo?.sub) return '/setup?error=verify_failed';

    if (!isSuperAdmin(provider, userInfo, candidate)) {
      return `/setup?error=domain_mismatch&domain=${encodeURIComponent(setup.parentDomain)}`;
    }

    // Verified: persist the claim. bootstrap() seeds the full key menu; the
    // exchange secret is minted here so apps have one from day one.
    await settingsStore.bootstrap();
    for (const [key, value] of Object.entries(candidate)) {
      await settingsStore.set(key, value);
    }
    if (!current.ID_CLIENT_SECRET) {
      await settingsStore.set('ID_CLIENT_SECRET', store.generateId(32));
    }
    settingsStore.invalidate();

    const iUserId = await upsertUserForIdentity(provider.id, true, userInfo);
    logger.warn(
      `[setup] instance claimed for ${setup.parentDomain} by ${userInfo.email} via ${provider.id}`
    );

    const dest = await finishLogin(req, res, await getSettings(), {
      iUserId,
      provider: provider.id,
      subject: userInfo.sub,
      superAdmin: true,
    });
    // A pending app request still wins; otherwise land on the admin console.
    return dest === '/account' ? '/admin?setup=complete' : dest;
  }

  // ── Application entry: /authorize ──────────────────────────────────────────

  /**
   * An application under the parent domain starts login here:
   *   GET /authorize?redirect_uri=https://app.X.TLD/auth/callback&state=<opaque>
   *
   * With a live SSO session the answer is immediate — a handoff code goes
   * straight back. Otherwise the request is parked in a cookie and the login
   * page takes over; finishLogin() completes the round trip.
   */
  app.get('/authorize', async (req, res, next) => {
    try {
      const settings = await getSettings();
      const redirectUri = validateRedirectUri(
        String(req.query.redirect_uri ?? ''),
        settings,
        config.NODE_ENV
      );
      if (!redirectUri) {
        return res
          .status(400)
          .send(
            'Invalid redirect_uri: must be an https URL under the configured parent domain.'
          );
      }
      const state = req.query.state ? String(req.query.state) : undefined;

      const session = await resolveSession(req);
      if (session) {
        const code = await store.createAuthCode(db, {
          iUserId: session.iUserId,
          redirectUri,
          provider: session.sProvider,
          subject: session.sSubject,
          bSuperAdmin: session.bSuperAdmin,
        });
        const url = new URL(redirectUri);
        url.searchParams.set('code', code);
        if (state) url.searchParams.set('state', state);
        return res.redirect(url.toString());
      }

      setAuthRequestCookie(res, { redirect_uri: redirectUri, state });
      return res.sendFile(path.join(publicDir, 'login.html'));
    } catch (err) {
      next(err);
    }
  });

  // ── OAuth providers (generic routes over the registry) ─────────────────────

  app.get('/auth/:provider', async (req, res, next) => {
    try {
      const settings = await getSettings();
      const provider = getProvider(req.params.provider);
      if (!provider || !isProviderConfigured(provider, settings)) {
        return res.redirect('/?auth_error=provider_not_configured');
      }
      const state: OAuthState = {
        csrf: store.generateId(16),
        context: 'login',
        provider: provider.id,
      };
      setOAuthStateCookie(res, state);
      return res.redirect(
        provider.buildAuthUrl(settings, baseUrl(settings, req), Buffer.from(JSON.stringify(state)).toString('base64url'))
      );
    } catch (err) {
      next(err);
    }
  });

  // Link an additional identity to the already-signed-in user. The target
  // user comes from the server-side session, never from the request.
  app.get('/auth/:provider/link', async (req, res, next) => {
    try {
      const settings = await getSettings();
      const provider = getProvider(req.params.provider);
      if (!provider || !isProviderConfigured(provider, settings)) {
        return res.redirect('/?auth_error=provider_not_configured');
      }
      const session = await resolveSession(req);
      if (!session) return res.redirect('/');

      const state: OAuthState = {
        csrf: store.generateId(16),
        context: 'link',
        provider: provider.id,
        linkSessionId: session.sSessionId,
      };
      setOAuthStateCookie(res, state);
      return res.redirect(
        provider.buildAuthUrl(settings, baseUrl(settings, req), Buffer.from(JSON.stringify(state)).toString('base64url'))
      );
    } catch (err) {
      next(err);
    }
  });

  app.get('/auth/:provider/callback', async (req, res, next) => {
    try {
      clearOAuthStateCookie(res);
      const settings = await getSettings();
      const provider = getProvider(req.params.provider);
      if (!provider) return res.redirect('/?auth_error=provider_not_configured');

      // CSRF: the state echoed by the provider must match the cookie we set
      // when we left, and must have been minted for this provider.
      const storedRaw = getCookie(req, OAUTH_STATE_COOKIE);
      const stored = storedRaw ? decodeState(storedRaw) : null;
      if (!stored || stored.provider !== provider.id) {
        return res.redirect('/?auth_error=invalid_state');
      }

      // The setup wizard verifies credentials that are not saved yet, so it
      // runs before the is-this-provider-configured gate.
      if (stored.context === 'setup') {
        return res.redirect(await handleSetupCallback(req, res, provider, stored));
      }

      if (!isProviderConfigured(provider, settings)) {
        return res.redirect('/?auth_error=provider_not_configured');
      }

      if (req.query.error) return res.redirect('/?auth_error=provider_denied');
      const code = String(req.query.code ?? '');
      if (!code) return res.redirect('/?auth_error=missing_code');

      const returned = decodeState(String(req.query.state ?? ''));
      if (!returned || stored.csrf !== returned.csrf) {
        return res.redirect('/?auth_error=csrf_mismatch');
      }

      const userInfo = await provider.fetchUserInfo(settings, baseUrl(settings, req), code);
      if (!userInfo?.sub) return res.redirect('/?auth_error=userinfo_failed');

      // ── Link context: attach to the signed-in account ────────────────────
      if (stored.context === 'link' && stored.linkSessionId) {
        const linkSession = await store.getSession(db, stored.linkSessionId);
        if (!linkSession) return res.redirect('/?auth_error=link_expired');

        const owner = await store.findUserByIdentity(db, provider.id, userInfo.sub);
        if (owner && owner !== linkSession.iUserId) {
          // Already someone else's login; two people must not share one.
          return res.redirect('/account?link_error=already_linked');
        }
        await store.ensureIdentity(db, linkSession.iUserId, provider.id, userInfo.sub, userInfo.email);
        await db.query(`UPDATE id_tbl_User SET email = COALESCE(email, ?) WHERE iUserId = ?`, [
          userInfo.email,
          linkSession.iUserId,
        ]);
        return res.redirect(`/account?linked=${provider.id}`);
      }

      // ── Login context ────────────────────────────────────────────────────
      const iUserId = await upsertUserForIdentity(
        provider.id,
        provider.verifiesEmailDomain(settings),
        userInfo
      );
      const superAdmin = isSuperAdmin(provider, userInfo, settings);
      const dest = await finishLogin(req, res, settings, {
        iUserId,
        provider: provider.id,
        subject: userInfo.sub,
        superAdmin,
      });
      return res.redirect(dest);
    } catch (err) {
      next(err);
    }
  });

  // ── UISP SSO bridge callback ───────────────────────────────────────────────
  // The bridge plugin verifies the ISP portal session, then redirects here
  // with a signed one-time code: ?code=<base64url-payload>&sig=<hmac-hex>.

  app.get('/sso/callback', async (req, res, next) => {
    try {
      const settings = await getSettings();
      const code = String(req.query.code ?? '');
      const sig = String(req.query.sig ?? '');
      if (!code || !sig) return res.redirect('/?auth_error=missing_sso_params');

      if (!settings.UISP_SSO_SECRET) {
        logger.error('[sso] UISP_SSO_SECRET not configured');
        return res.redirect('/?auth_error=sso_not_configured');
      }

      const payload = verifySsoCode(settings.UISP_SSO_SECRET, code, sig);
      if (!payload) return res.redirect('/?auth_error=invalid_sso_code');

      const nonceOk = await store.consumeNonce(db, payload.nonce, payload.exp);
      if (!nonceOk) return res.redirect('/?auth_error=sso_replay');

      // Best-effort enrichment so the account has a label; the sign-in is
      // valid even when the CRM cannot be reached.
      let email: string | null = null;
      let name: string | null = null;
      if (settings.UISP_BASE_URL && settings.UISP_CRM_APP_KEY_READ) {
        try {
          const resp = await fetch(
            `${settings.UISP_BASE_URL.replace(/\/+$/, '')}/crm/api/v1.0/clients/${encodeURIComponent(payload.clientId)}`,
            {
              headers: {
                'X-Auth-App-Key': settings.UISP_CRM_APP_KEY_READ,
                Accept: 'application/json',
              },
            }
          );
          if (resp.ok) {
            const data = (await resp.json()) as Record<string, unknown>;
            const contacts =
              (data.contacts as Array<{ email?: string; isBilling?: boolean }>) ?? [];
            email =
              contacts.find((c) => c.isBilling)?.email ?? contacts[0]?.email ?? null;
            const company = data.companyName as string | null;
            const first = (data.firstName as string) ?? '';
            const last = (data.lastName as string) ?? '';
            name = company ?? (`${first} ${last}`.trim() || null);
          }
        } catch (err) {
          logger.warn({ err }, '[sso] CRM enrichment failed');
        }
      }

      const iUserId = await upsertUserForIdentity('uisp', false, {
        sub: payload.clientId,
        email: email ?? '',
        name: name ?? `ISP client ${payload.clientId}`,
      });

      const dest = await finishLogin(req, res, settings, {
        iUserId,
        provider: 'uisp',
        subject: payload.clientId,
        superAdmin: false,
      });
      return res.redirect(dest);
    } catch (err) {
      next(err);
    }
  });

  // ── Token exchange (application → id, server to server) ────────────────────

  /**
   * POST /api/token  { code, redirect_uri, client_secret }
   *
   * The application proves the code was addressed to it (redirect_uri must
   * match what the code was minted for) and that it is one of ours
   * (ID_CLIENT_SECRET from oAuthConfig — the same secret all apps under the
   * domain read from NocoDB). Codes are single-use and expire in 5 minutes.
   */
  app.post('/api/token', async (req, res, next) => {
    try {
      const settings = await getSettings();
      const { code, redirect_uri, client_secret } = (req.body ?? {}) as Record<string, string>;

      if (!settings.ID_CLIENT_SECRET) {
        return res.status(503).json({ error: 'ID_CLIENT_SECRET is not configured' });
      }
      if (!client_secret || client_secret !== settings.ID_CLIENT_SECRET) {
        return res.status(401).json({ error: 'Invalid client secret' });
      }
      if (!code || !redirect_uri) {
        return res.status(400).json({ error: 'code and redirect_uri are required' });
      }

      const consumed = await store.consumeAuthCode(db, code, redirect_uri);
      if (!consumed) return res.status(400).json({ error: 'Invalid, expired, or reused code' });

      const user = await store.getUser(db, consumed.iUserId);
      if (!user) return res.status(400).json({ error: 'Unknown user' });
      const identities = await store.listIdentities(db, consumed.iUserId);

      return res.json({
        user: {
          iUserId: user.iUserId,
          email: user.email,
          displayName: user.displayName,
          superAdmin: consumed.bSuperAdmin,
        },
        identity: { provider: consumed.sProvider, subject: consumed.sSubject },
        identities: identities.map((i) => ({
          provider: i.provider,
          subject: i.subject,
          email: i.email,
        })),
      });
    } catch (err) {
      next(err);
    }
  });

  // ── Own account ────────────────────────────────────────────────────────────

  app.get('/api/me', async (req, res, next) => {
    try {
      const session = await resolveSession(req);
      if (!session) return res.status(401).json({ error: 'Not logged in' });
      const user = await store.getUser(db, session.iUserId);
      const identities = await store.listIdentities(db, session.iUserId);
      const settings = await getSettings();
      return res.json({
        iUserId: session.iUserId,
        email: user?.email ?? null,
        displayName: user?.displayName ?? null,
        superAdmin: session.bSuperAdmin,
        identities: identities.map((i) => ({
          iIdentityId: i.iIdentityId,
          provider: i.provider,
          label: i.email ?? (i.provider === 'uisp' ? `ISP client ${i.subject}` : i.subject),
          dtCreated: i.dtCreated,
          removable: i.provider !== 'uisp',
        })),
        linkable: availableLoginMethods(settings)
          .filter((m) => m.kind === 'oauth')
          .map((m) => ({ id: m.id, label: m.label })),
      });
    } catch (err) {
      next(err);
    }
  });

  app.delete('/api/identities/:id', async (req, res, next) => {
    try {
      const session = await resolveSession(req);
      if (!session) return res.status(401).json({ error: 'Not logged in' });

      const id = Number(req.params.id);
      const identity = await store.getIdentity(db, id);
      if (!identity || identity.iUserId !== session.iUserId) {
        // Don't disclose whether the id exists on someone else's account.
        return res.status(404).json({ error: 'Not found' });
      }
      if (identity.provider === 'uisp') {
        return res.status(400).json({
          error: 'Your ISP sign-in is managed by your provider and cannot be removed here.',
        });
      }
      if ((await store.countIdentities(db, session.iUserId)) <= 1) {
        return res.status(400).json({
          error: 'This is your only sign-in method — link another before removing it.',
        });
      }
      await store.deleteIdentity(db, id);
      return res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  // Revoke this session (sign out of id — apps keep their own sessions).
  // GET is accepted too: applications end their own session and then send
  // the browser here so "sign out" ends the domain-wide login as well.
  const logoutHandler: express.RequestHandler = async (req, res, next) => {
    try {
      const settings = await getSettings();
      const session = await resolveSession(req);
      if (session) await store.revokeSession(db, session.sSessionId);
      clearSessionCookie(res, settings);
      return res.redirect('/');
    } catch (err) {
      next(err);
    }
  };
  app.post('/logout', logoutHandler);
  app.get('/logout', logoutHandler);

  // Revoke every session for this user, everywhere.
  app.post('/api/logout-everywhere', async (req, res, next) => {
    try {
      const settings = await getSettings();
      const session = await resolveSession(req);
      if (!session) return res.status(401).json({ error: 'Not logged in' });
      const n = await store.revokeAllSessions(db, session.iUserId);
      clearSessionCookie(res, settings);
      return res.json({ ok: true, revoked: n });
    } catch (err) {
      next(err);
    }
  });

  // ── Super System Admin ─────────────────────────────────────────────────────

  async function requireSuperAdmin(
    req: express.Request,
    res: express.Response
  ): Promise<store.SessionRow | null> {
    const session = await resolveSession(req);
    if (!session?.bSuperAdmin) {
      res.status(403).json({ error: 'Forbidden' });
      return null;
    }
    return session;
  }

  app.get('/api/admin/config', async (req, res, next) => {
    try {
      if (!(await requireSuperAdmin(req, res))) return;
      const rows = await settingsStore.listForAdmin();
      const knownProviders = PROVIDERS.map((p) => ({
        id: p.id,
        label: p.label,
        requiredKeys: p.requiredKeys,
      }));
      return res.json({ items: rows, providers: knownProviders });
    } catch (err) {
      next(err);
    }
  });

  app.put('/api/admin/config/:key', async (req, res, next) => {
    try {
      const session = await requireSuperAdmin(req, res);
      if (!session) return;
      const key = String(req.params.key ?? '').trim();
      if (!/^[A-Za-z0-9_.-]{1,128}$/.test(key)) {
        return res.status(400).json({ error: 'Invalid key' });
      }
      const value = String((req.body ?? {}).value ?? '');
      await settingsStore.set(key, value);
      logger.warn(`[admin] user ${session.iUserId} set oAuthConfig ${key}`);
      return res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  app.get('/api/admin/users', async (req, res, next) => {
    try {
      if (!(await requireSuperAdmin(req, res))) return;
      return res.json({ items: await store.adminListUsers(db) });
    } catch (err) {
      next(err);
    }
  });

  // Revocation is the only way a login ends, so the admin can end them all.
  app.post('/api/admin/users/:id/revoke-sessions', async (req, res, next) => {
    try {
      const session = await requireSuperAdmin(req, res);
      if (!session) return;
      const iUserId = Number(req.params.id);
      const n = await store.revokeAllSessions(db, iUserId);
      logger.warn(`[admin] user ${session.iUserId} revoked ${n} session(s) of user ${iUserId}`);
      return res.json({ ok: true, revoked: n });
    } catch (err) {
      next(err);
    }
  });

  app.delete('/api/admin/identities/:id', async (req, res, next) => {
    try {
      const session = await requireSuperAdmin(req, res);
      if (!session) return;
      const id = Number(req.params.id);
      const identity = await store.getIdentity(db, id);
      if (!identity) return res.status(404).json({ error: 'Not found' });
      // Same floor as self-service: never strip a user's last way in.
      if ((await store.countIdentities(db, identity.iUserId)) <= 1) {
        return res.status(400).json({
          error: "That is the user's only sign-in method — removing it would lock them out.",
        });
      }
      await store.deleteIdentity(db, id);
      logger.warn(
        `[admin] user ${session.iUserId} unlinked identity ${id} (${identity.provider}) from user ${identity.iUserId}`
      );
      return res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  // ── Error handler ──────────────────────────────────────────────────────────

  app.use(
    (err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      logger.error(err);
      res.status(500).json({ error: 'Internal server error' });
    }
  );

  return { app, db, settingsStore };
}
