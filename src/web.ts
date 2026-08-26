import crypto from 'crypto';
import type express from 'express';
import { Settings } from './settings';
import { OAuthState } from './providers';

/**
 * HTTP plumbing: cookies, redirect validation, and the UISP bridge code —
 * kept free of Express state so the logic is unit-testable.
 */

export const SESSION_COOKIE = 'id_sso';
export const OAUTH_STATE_COOKIE = 'id_oauth_state';
export const AUTHREQ_COOKIE = 'id_authreq';

// "Forever until revoked": the cookie carries a ten-year Max-Age (a cookie
// must have some lifetime); validity is decided server-side by dtRevoked.
const SESSION_COOKIE_MAX_AGE = 10 * 365 * 24 * 3600;

/**
 * Constant-time comparison for shared secrets.
 *
 * `!==` returns as soon as two bytes differ, which leaks how much of the
 * secret a caller got right. Hashing both sides first means differing
 * lengths neither throw nor leak, and the comparison itself is fixed-time.
 */
export function secretsMatch(a: string, b: string): boolean {
  if (!a || !b) return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ─── Redirect validation ──────────────────────────────────────────────────────

/**
 * A redirect_uri is acceptable iff it is https (http allowed only outside
 * production) and its host is the parent domain or any subdomain of it.
 * That is the whole registration model: every app under X.TLD is a client,
 * nothing else is.
 */
export function validateRedirectUri(
  raw: string,
  settings: Settings,
  nodeEnv = 'production'
): string | null {
  const parentDomain = (settings.PARENT_DOMAIN ?? '').toLowerCase().replace(/^\.+/, '');
  if (!parentDomain) return null;

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && !(nodeEnv !== 'production' && url.protocol === 'http:')) {
    return null;
  }
  if (url.username || url.password) return null;

  const host = url.hostname.toLowerCase();
  if (host !== parentDomain && !host.endsWith(`.${parentDomain}`)) return null;

  return url.toString();
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────

export function appendCookie(res: express.Response, cookie: string): void {
  const prev = res.getHeader('Set-Cookie');
  const list = prev ? (Array.isArray(prev) ? prev.map(String) : [String(prev)]) : [];
  res.setHeader('Set-Cookie', [...list, cookie]);
}

function cookieDomainAttr(settings: Settings): string {
  // Scoped to the parent domain so every app.X.TLD sees the SSO session and
  // /authorize can answer without showing a login page. Host-only when the
  // domain isn't configured yet (bootstrap).
  const d = (settings.PARENT_DOMAIN ?? '').replace(/^\.+/, '');
  return d ? `; Domain=.${d}` : '';
}

export function setSessionCookie(
  res: express.Response,
  settings: Settings,
  sessionId: string
): void {
  appendCookie(
    res,
    `${SESSION_COOKIE}=${sessionId}; Path=/; Max-Age=${SESSION_COOKIE_MAX_AGE}` +
      `${cookieDomainAttr(settings)}; HttpOnly; SameSite=Lax; Secure`
  );
}

export function clearSessionCookie(res: express.Response, settings: Settings): void {
  appendCookie(
    res,
    `${SESSION_COOKIE}=; Path=/; Max-Age=0${cookieDomainAttr(settings)}; HttpOnly; SameSite=Lax; Secure`
  );
}

export function getCookie(req: express.Request, name: string): string | null {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

// ─── OAuth state cookie ───────────────────────────────────────────────────────

export function encodeState(state: OAuthState): string {
  return Buffer.from(JSON.stringify(state)).toString('base64url');
}

export function decodeState(encoded: string): OAuthState | null {
  try {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as OAuthState;
  } catch {
    return null;
  }
}

export function setOAuthStateCookie(res: express.Response, state: OAuthState): string {
  const encoded = encodeState(state);
  appendCookie(
    res,
    `${OAUTH_STATE_COOKIE}=${encoded}; Path=/auth; Max-Age=600; HttpOnly; SameSite=Lax; Secure`
  );
  return encoded;
}

export function clearOAuthStateCookie(res: express.Response): void {
  appendCookie(
    res,
    `${OAUTH_STATE_COOKIE}=; Path=/auth; Max-Age=0; HttpOnly; SameSite=Lax; Secure`
  );
}

// ─── Pending application request ("authreq") ─────────────────────────────────

export interface AuthRequest {
  redirect_uri: string;
  state?: string;
}

export function setAuthRequestCookie(res: express.Response, authreq: AuthRequest): void {
  const encoded = Buffer.from(JSON.stringify(authreq)).toString('base64url');
  appendCookie(
    res,
    `${AUTHREQ_COOKIE}=${encoded}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure`
  );
}

export function clearAuthRequestCookie(res: express.Response): void {
  appendCookie(res, `${AUTHREQ_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`);
}

export function getAuthRequestFromCookie(req: express.Request): AuthRequest | null {
  const raw = getCookie(req, AUTHREQ_COOKIE);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as AuthRequest;
    return parsed.redirect_uri ? parsed : null;
  } catch {
    return null;
  }
}

// ─── First-run setup wizard ──────────────────────────────────────────────────

export const SETUP_COOKIE = 'id_setup';

/**
 * The wizard's pending claim: provider credentials the person typed, held in
 * a short-lived HttpOnly cookie while the verification OAuth round trip runs.
 * Nothing is written to the settings store until the round trip proves the
 * credentials work AND the signed-in address is on the claimed domain.
 */
export interface SetupRequest {
  csrf: string;
  parentDomain: string;
  /**
   * Domain(s) whose provider-verified members become Super System Admin.
   * Usually the same as parentDomain, but not when the identity provider
   * vouches for a different domain than the one the apps live on — a Google
   * Workspace domain alias being the everyday case. Empty means "same as
   * parentDomain".
   */
  adminDomain?: string;
  appBaseUrl: string;
  provider: 'google' | 'microsoft';
  clientId: string;
  clientSecret: string;
  tenant?: string;
}

export function setSetupCookie(res: express.Response, setup: SetupRequest): void {
  const encoded = Buffer.from(JSON.stringify(setup)).toString('base64url');
  appendCookie(
    res,
    `${SETUP_COOKIE}=${encoded}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure`
  );
}

export function clearSetupCookie(res: express.Response): void {
  appendCookie(res, `${SETUP_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`);
}

export function getSetupFromCookie(req: express.Request): SetupRequest | null {
  const raw = getCookie(req, SETUP_COOKIE);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as SetupRequest;
    if (!parsed.csrf || !parsed.parentDomain || !parsed.provider || !parsed.clientId) return null;
    return parsed;
  } catch {
    return null;
  }
}

/** id.wisp.net → wisp.net; a bare or two-label host is returned unchanged. */
export function suggestParentDomain(host: string): string {
  const h = host.toLowerCase().split(':')[0];
  const labels = h.split('.');
  return labels.length > 2 ? labels.slice(1).join('.') : h;
}

export function isValidDomain(domain: string): boolean {
  return /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i.test(domain);
}

/** Every entry of a comma-separated domain list must parse. */
export function isValidDomainList(raw: string): boolean {
  const parts = raw
    .split(',')
    .map((d) => d.trim().replace(/^@/, ''))
    .filter(Boolean);
  return parts.length > 0 && parts.every(isValidDomain);
}

// ─── UISP bridge code verification ───────────────────────────────────────────

export interface SsoPayload {
  clientId: string;
  nonce: string;
  exp: number; // unix seconds
}

export function verifySsoCode(secret: string, code: string, sig: string): SsoPayload | null {
  const expected = crypto.createHmac('sha256', secret).update(code).digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  let actualBuf: Buffer;
  try {
    actualBuf = Buffer.from(sig, 'hex');
  } catch {
    return null;
  }
  if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    return null;
  }

  let payload: SsoPayload;
  try {
    payload = JSON.parse(Buffer.from(code, 'base64url').toString('utf8')) as SsoPayload;
  } catch {
    return null;
  }
  if (!payload.clientId || !payload.nonce || !payload.exp) return null;
  if (Math.floor(Date.now() / 1000) > payload.exp) return null; // expired

  return payload;
}
