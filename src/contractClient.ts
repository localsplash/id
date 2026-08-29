/**
 * Typed client for the X.TLD application integration contract
 * (docs/openapi.json). Mirrors the contract exactly — the contract tests
 * and CI keep it honest — and compiles with the repo's build, so a
 * consuming first-party application can copy or import this file as-is.
 *
 * All calls except the browser /authorize redirect are server-to-server
 * and are admitted by IPv4/CIDR network policy: run them from an
 * allowlisted host. No application secret is required by the POC contract.
 */

export interface TokenRequest {
  code: string;
  redirect_uri: string;
}

export interface TokenResponse {
  user: {
    iUserId: number;
    email: string | null;
    displayName: string | null;
    /** Session-scoped; provenance Session → AuthCode → redemption. */
    superAdmin: boolean;
  };
  identity: { provider: string | null; subject: string | null };
  identities: Array<{ provider: string; subject: string; email: string | null }>;
}

export interface RegistrationRequest {
  name?: string;
  webhook_url: string;
}

export type EventType =
  | 'ping'
  | 'session.revoked'
  | 'user.merged'
  | 'identity.linked'
  | 'identity.unlinked';

export interface RegistrationResponse {
  ok: true;
  origin: string;
  /** Legacy webhook-HMAC secret; verifying deliveries with it is optional. */
  secret?: string;
  events: EventType[];
  signature?: {
    header: string;
    scheme: string;
    toleranceSeconds: number;
    required: false;
  };
}

export interface IdEvent {
  /** Strictly increasing; dedupe on this — the same id can arrive twice. */
  id: number;
  type: EventType;
  occurredAt: string;
  data: Record<string, unknown>;
}

export interface EventsResponse {
  items: IdEvent[];
}

export interface DirectoryEnsureRequest {
  email: string;
  displayName?: string;
  idempotencyKey?: string;
}

export interface DirectoryUser {
  iUserId: number;
  email: string | null;
  displayName: string | null;
  claimed: boolean;
}

export interface DirectoryPage {
  items: DirectoryUser[];
  nextCursor: number | null;
}

export interface ContractError {
  error: string;
  correlationId?: string;
}

export class IdApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ContractError
  ) {
    super(`id API ${status}: ${body.error}`);
  }
}

export class IdClient {
  /** @param baseUrl e.g. `https://id.X.TLD` (no trailing slash needed). */
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  /** The URL to send a browser to when the app has no local session. */
  authorizeUrl(redirectUri: string, state?: string): string {
    const url = new URL(`${this.baseUrl}/authorize`);
    url.searchParams.set('redirect_uri', redirectUri);
    if (state) url.searchParams.set('state', state);
    return url.toString();
  }

  async redeemCode(request: TokenRequest): Promise<TokenResponse> {
    return this.post('/api/token', request);
  }

  async register(request: RegistrationRequest): Promise<RegistrationResponse> {
    return this.post('/api/apps/register', request);
  }

  async eventsSince(since = 0): Promise<EventsResponse> {
    return this.get(`/api/events?since=${encodeURIComponent(since)}`);
  }

  async ensureDirectoryUser(request: DirectoryEnsureRequest): Promise<DirectoryUser> {
    return this.post('/api/directory/users', request);
  }

  async getDirectoryUser(iUserId: number): Promise<DirectoryUser> {
    return this.get(`/api/directory/users/${encodeURIComponent(iUserId)}`);
  }

  async searchDirectoryUsers(
    params: { query?: string; limit?: number; cursor?: number } = {}
  ): Promise<DirectoryPage> {
    const search = new URLSearchParams();
    if (params.query) search.set('query', params.query);
    if (params.limit !== undefined) search.set('limit', String(params.limit));
    if (params.cursor !== undefined) search.set('cursor', String(params.cursor));
    const qs = search.toString();
    return this.get(`/api/directory/users${qs ? `?${qs}` : ''}`);
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const resp = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = (await resp.json().catch(() => ({ error: 'Invalid response' }))) as never;
    if (!resp.ok) throw new IdApiError(resp.status, json);
    return json;
  }
}
