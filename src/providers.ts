import { Settings } from './settings';

/**
 * OAuth provider registry.
 *
 * Each provider declares which oAuthConfig keys it needs; a provider whose
 * keys are not all set simply does not exist as far as the login page and
 * the /auth routes are concerned. Adding a provider later means adding one
 * descriptor here — no route changes.
 *
 * The UISP bridge is not an OAuth redirect provider (the plugin pushes a
 * signed assertion at /sso/callback), so it is described separately in
 * availableLoginMethods() but shares the same "hidden until configured"
 * rule.
 */

export interface OAuthUserInfo {
  sub: string;
  email: string;
  name: string;
  /** Verified hosted domain, when the provider vouches for one (Google `hd`). */
  hd?: string;
}

export interface OAuthState {
  csrf: string;
  /**
   * 'link' attaches the returning identity to an already-signed-in user;
   * 'setup' is the first-run wizard verifying not-yet-saved credentials.
   */
  context: 'login' | 'link' | 'setup';
  provider: string;
  linkSessionId?: string;
}

export interface ProviderDescriptor {
  id: string;
  label: string;
  /** oAuthConfig keys that must be non-empty for this provider to be offered. */
  requiredKeys: string[];
  /**
   * Whether the provider vouches for the email's domain under the given
   * settings. Only then can it grant Super System Admin — an unverified
   * email claim could be minted by any tenant on earth. Google always
   * verifies; Microsoft only when the app is locked to one tenant (with
   * 'common' any directory could assert any address).
   */
  verifiesEmailDomain(settings: Settings): boolean;
  buildAuthUrl(settings: Settings, baseUrl: string, encodedState: string): string;
  /** Exchange the callback `code` for the user's identity. */
  fetchUserInfo(settings: Settings, baseUrl: string, code: string): Promise<OAuthUserInfo | null>;
}

// ─── Google ───────────────────────────────────────────────────────────────────

interface GoogleUserInfo {
  sub: string;
  email: string;
  name: string;
  email_verified: boolean;
  hd?: string;
}

const google: ProviderDescriptor = {
  id: 'google',
  label: 'Google',
  requiredKeys: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'],
  verifiesEmailDomain: () => true,

  buildAuthUrl(settings, baseUrl, encodedState) {
    const params = new URLSearchParams({
      client_id: settings.GOOGLE_CLIENT_ID,
      redirect_uri: `${baseUrl}/auth/google/callback`,
      response_type: 'code',
      scope: 'openid email profile',
      state: encodedState,
      access_type: 'online',
      prompt: 'select_account',
    });
    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  },

  async fetchUserInfo(settings, baseUrl, code) {
    const resp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: settings.GOOGLE_CLIENT_ID,
        client_secret: settings.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${baseUrl}/auth/google/callback`,
        grant_type: 'authorization_code',
      }),
    });
    if (!resp.ok) return null;
    const tokens = (await resp.json()) as { access_token?: string };
    if (!tokens.access_token) return null;

    const userResp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userResp.ok) return null;
    const info = (await userResp.json()) as GoogleUserInfo;
    if (!info.sub || !info.email) return null;
    return {
      sub: info.sub,
      email: info.email.toLowerCase(),
      name: info.name ?? info.email,
      hd: info.hd,
    };
  },
};

// ─── Microsoft (Entra ID) ─────────────────────────────────────────────────────

interface MicrosoftIdTokenClaims {
  sub?: string;
  name?: string;
  email?: string;
  preferred_username?: string;
}

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function microsoftAuthority(settings: Settings): string {
  return `https://login.microsoftonline.com/${encodeURIComponent(settings.MICROSOFT_TENANT || 'common')}`;
}

/**
 * Read the signed-in user out of the id_token. The token comes straight back
 * from Microsoft's token endpoint over TLS on a request authenticated with
 * our client secret, so the claims are trustworthy without local signature
 * verification — same trust model as Google's direct userinfo call.
 *
 * NOTE: Entra's email claim is set by the user's own tenant and is not proof
 * of address ownership, which is why this provider has
 * verifiesEmailDomain=false and can never grant Super System Admin.
 */
export function parseMicrosoftIdToken(idToken: string): OAuthUserInfo | null {
  const claims = decodeJwtPayload(idToken) as MicrosoftIdTokenClaims | null;
  if (!claims?.sub) return null;

  // preferred_username is the UPN for work/school accounts and the address
  // for personal ones; email is only present when the tenant publishes it.
  const candidate = claims.email ?? claims.preferred_username ?? '';
  const email = candidate.includes('@') ? candidate.toLowerCase() : '';
  if (!email) return null;

  return { sub: claims.sub, email, name: claims.name ?? email };
}

/**
 * A tenant GUID (or domain) locks sign-in to one directory, whose admin is
 * the claiming organisation — addresses it asserts are then trustworthy.
 * The multiplexed authorities are not.
 */
export function isTenantLocked(settings: Settings): boolean {
  const tenant = (settings.MICROSOFT_TENANT || 'common').toLowerCase();
  return !['common', 'organizations', 'consumers'].includes(tenant);
}

const microsoft: ProviderDescriptor = {
  id: 'microsoft',
  label: 'Microsoft',
  requiredKeys: ['MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET'],
  verifiesEmailDomain: isTenantLocked,

  buildAuthUrl(settings, baseUrl, encodedState) {
    const params = new URLSearchParams({
      client_id: settings.MICROSOFT_CLIENT_ID,
      redirect_uri: `${baseUrl}/auth/microsoft/callback`,
      response_type: 'code',
      // openid+profile+email is all we need; no Graph scopes, no admin consent.
      scope: 'openid profile email',
      state: encodedState,
      response_mode: 'query',
      prompt: 'select_account',
    });
    return `${microsoftAuthority(settings)}/oauth2/v2.0/authorize?${params.toString()}`;
  },

  async fetchUserInfo(settings, baseUrl, code) {
    const resp = await fetch(`${microsoftAuthority(settings)}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: settings.MICROSOFT_CLIENT_ID,
        client_secret: settings.MICROSOFT_CLIENT_SECRET,
        redirect_uri: `${baseUrl}/auth/microsoft/callback`,
        grant_type: 'authorization_code',
        scope: 'openid profile email',
      }),
    });
    if (!resp.ok) return null;
    const tokens = (await resp.json()) as { id_token?: string };
    if (!tokens.id_token) return null;
    // Microsoft returns the profile in the id_token itself — no second
    // userinfo round-trip as there is for Google.
    return parseMicrosoftIdToken(tokens.id_token);
  },
};

// ─── Registry ─────────────────────────────────────────────────────────────────

export const PROVIDERS: ProviderDescriptor[] = [google, microsoft];

export function getProvider(id: string): ProviderDescriptor | undefined {
  return PROVIDERS.find((p) => p.id === id);
}

export function isProviderConfigured(p: ProviderDescriptor, settings: Settings): boolean {
  return p.requiredKeys.every((k) => Boolean(settings[k]));
}

export interface LoginMethod {
  id: string;
  label: string;
  /** Where the login button sends the browser. */
  href: string;
  kind: 'oauth' | 'external';
}

/**
 * The login methods that are actually usable right now — a method whose
 * required settings are missing is not shown at all.
 */
export function availableLoginMethods(settings: Settings): LoginMethod[] {
  const methods: LoginMethod[] = PROVIDERS.filter((p) => isProviderConfigured(p, settings)).map(
    (p) => ({ id: p.id, label: p.label, href: `/auth/${p.id}`, kind: 'oauth' as const })
  );

  // The UISP bridge starts at the plugin's public URL inside the ISP portal;
  // it lands back on /sso/callback with a signed assertion.
  if (settings.UISP_PLUGIN_URL && settings.UISP_SSO_SECRET) {
    methods.push({
      id: 'uisp',
      label: 'ISP account',
      href: settings.UISP_PLUGIN_URL,
      kind: 'external',
    });
  }
  return methods;
}

/**
 * Domains are configured as a comma-separated list, so one deployment can
 * accept identities from more than one domain. Entries are normalised: case
 * folded, whitespace trimmed, a leading '@' dropped.
 */
export function parseDomainList(raw: string): string[] {
  return raw
    .split(',')
    .map((d) => d.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean);
}

/**
 * The domains whose (provider-verified) members are Super System Admins.
 *
 * Defaults to PARENT_DOMAIN, but the two are genuinely different things and
 * frequently differ in practice. PARENT_DOMAIN is where the *applications*
 * live — it sets the SSO cookie scope and the redirect allowlist. This is
 * where the *identities* come from, and the provider decides that, not us.
 *
 * The common case is a Google Workspace domain alias: with apps at
 * app.example.ai and a Workspace whose primary domain is example.com,
 * every token comes back as user@example.com / hd=example.com — Google
 * never asserts the alias. SUPERADMIN_DOMAIN=example.com is the answer, and
 * the list form covers a later move to a secondary domain where some users
 * really do hold example.ai primaries.
 */
export function superAdminDomains(settings: Settings): string[] {
  return parseDomainList(settings.SUPERADMIN_DOMAIN || settings.PARENT_DOMAIN || '');
}

/**
 * Super System Admin = a user whose provider-verified email domain is one of
 * SUPERADMIN_DOMAIN (default: PARENT_DOMAIN). Only providers that vouch for
 * the domain count; anyone can put any address in an unverified claim.
 */
export function isSuperAdmin(
  provider: ProviderDescriptor,
  userInfo: OAuthUserInfo,
  settings: Settings
): boolean {
  if (!provider.verifiesEmailDomain(settings)) return false;
  const domains = superAdminDomains(settings);
  return domains.some((d) => emailMatchesDomain(userInfo, d));
}

export function emailMatchesDomain(userInfo: OAuthUserInfo, domain: string): boolean {
  const d = domain.toLowerCase();
  if (!d) return false;
  if (userInfo.hd?.toLowerCase() === d) return true;
  return userInfo.email.toLowerCase().endsWith(`@${d}`);
}

/**
 * The domain this identity actually presented — what the provider vouched
 * for, which is what an admin needs to see when a claim does not match.
 * `hd` wins because it names the Workspace/tenant rather than the address.
 */
export function verifiedDomain(userInfo: OAuthUserInfo): string {
  if (userInfo.hd) return userInfo.hd.toLowerCase();
  const at = userInfo.email.lastIndexOf('@');
  return at === -1 ? '' : userInfo.email.slice(at + 1).toLowerCase();
}
