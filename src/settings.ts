import { AppConfig } from './config';

/**
 * Settings live in NocoDB, not in the environment — with the environment
 * kept as an override for deployments that need to pin a value.
 *
 * The `oAuthConfig` table (base `id` by default) is a plain key/value store
 * that a Super System Admin can edit either through NocoDB itself at
 * nocodb.<parent-domain>, or through this app's /admin page. Every app under
 * the parent domain reads the same table with its own NocoDB API token, so
 * one set of credentials serves echo.X.TLD, aida.X.TLD, and whatever comes
 * next.
 *
 * Resolution order for every key below:
 *
 *   1. the process environment (`.env`) — an explicit override. A key set
 *      there wins over the store, is not writable from /admin, and is never
 *      copied into the store (it would go stale the moment the env changed).
 *   2. the `oAuthConfig` row — where the setup wizard and /admin write.
 *   3. nothing. There is deliberately no third place: a value that can be
 *      observed rather than configured (APP_BASE_URL, PARENT_DOMAIN) is
 *      derived from the URL the browser actually used to reach this service,
 *      at the point of use — see web.ts. The only assumption this codebase
 *      makes about that URL is the naming convention identity.X.TLD.
 *
 * On boot the table is created and seeded with every known key if it does
 * not exist yet, so the admin sees the full menu of settings rather than
 * having to guess key names. Seeded rows are left EMPTY on purpose — no
 * value is invented for a database that is still being created. Unknown
 * keys are kept — new applications may store their own settings here
 * without this app needing to learn about them.
 */

/**
 * The base and table are named by convention, not configured: one base per
 * repository, `{Repo}Base`, holding `auth_tbl_Settings`. A base name is
 * unique because we say it is — NocoDB does not enforce it — which is what
 * lets an application find its own base by name at runtime instead of
 * carrying a base ID that survives a rename and outlives a restore.
 */
export const SETTINGS_BASE_NAME = 'IdentityBase';
export const SETTINGS_TABLE_NAME = 'auth_tbl_Settings';

export interface SettingDef {
  key: string;
  description: string;
}

export const KNOWN_SETTINGS: SettingDef[] = [
  {
    key: 'PARENT_DOMAIN',
    description:
      'Apex domain (X.TLD) that all participating apps live under, e.g. wisp.net. ' +
      'Drives the SSO cookie scope and the redirect_uri allowlist (any https host ' +
      'under this domain). This is where the applications live; where the ' +
      'identities come from is SUPERADMIN_DOMAIN, which defaults to this but is ' +
      'not always the same domain.',
  },
  {
    key: 'APP_BASE_URL',
    description:
      'Public base URL of this identity app, e.g. https://identity.wisp.net. Used to ' +
      'build the OAuth callback URIs registered with each provider. Leave it empty ' +
      'and the URL the browser reached this service on is used instead — the setup ' +
      'wizard writes exactly that, so it normally never has to be typed.',
  },
  {
    key: 'DB_HOST',
    description:
      'Hostname of the MySQL server holding id_db, the shared platform identity ' +
      'database this app owns and migrates itself. Required — the app has no ' +
      'sessions, users or identities until it is set. A change takes a restart.',
  },
  {
    key: 'DB_PORT',
    description: "MySQL port. Empty means MySQL's own default, 3306.",
  },
  { key: 'DB_USER', description: 'MySQL user for id_db. Required.' },
  { key: 'DB_PASSWORD', description: 'Password for DB_USER.' },
  {
    key: 'DB_NAME',
    description: 'Database name, conventionally id_db. Required.',
  },
  {
    key: 'trustedCIDR',
    description:
      'The network the platform\'s servers sit on, as an IPv4 CIDR (/32 allowed, a ' +
      'bare IP treated as /32). ONE value for the whole platform — every application ' +
      'reads this same key rather than spelling the same network under its own name. ' +
      'It admits callers to the server-only endpoints (/api/token, /api/apps/register, ' +
      '/api/events, /api/directory/*); nothing outside it is trusted, and IPv6 never ' +
      'is. A comma-separated list is parsed, for servers that straddle two ranges.',
  },
  {
    key: 'IDENTITY_CLIENT_SECRET',
    description:
      'LEGACY (rollout only). Shared secret applications present at POST /api/token ' +
      'when IDENTITY_APP_AUTH_MODE is secret or dual. The POC default (cidr) trusts ' +
      'the trustedCIDR network instead and ignores this. ' +
      'Generate with: openssl rand -hex 32',
  },
  {
    key: 'SUPERADMIN_DOMAIN',
    description:
      'Domain(s) whose provider-verified users become Super System Admins — a ' +
      'comma-separated list is accepted. Defaults to PARENT_DOMAIN when empty. ' +
      'Set it explicitly whenever the identity provider vouches for a different ' +
      'domain than the apps are served from: with a Google Workspace domain alias ' +
      '(apps at app.example.ai, Workspace primary example.com) every token comes ' +
      'back as user@example.com with hd=example.com — Google never asserts the ' +
      'alias — so this must be example.com.',
  },
  {
    key: 'DEFAULT_REDIRECT_URI',
    description:
      'Where to send a user who signs in without a pending application request ' +
      '(e.g. entering straight from the UISP portal), such as ' +
      'https://echo.wisp.net/auth/callback. Empty = show the account page.',
  },
  { key: 'GOOGLE_CLIENT_ID', description: 'Google OAuth 2.0 client ID.' },
  { key: 'GOOGLE_CLIENT_SECRET', description: 'Google OAuth 2.0 client secret.' },
  { key: 'MICROSOFT_CLIENT_ID', description: 'Microsoft Entra ID application (client) ID.' },
  { key: 'MICROSOFT_CLIENT_SECRET', description: 'Microsoft Entra ID client secret.' },
  {
    key: 'MICROSOFT_TENANT',
    description:
      "Entra authority segment: 'common' accepts any account; a tenant GUID restricts " +
      'sign-in to that tenant. Defaults to common when empty.',
  },
  {
    key: 'UISP_SSO_SECRET',
    description:
      'HMAC-SHA256 hex secret shared with the UISP bridge plugin. Must match the ' +
      "plugin's SSO Shared Secret setting exactly.",
  },
  {
    key: 'UISP_PLUGIN_URL',
    description:
      "The UISP bridge plugin's public URL (UCRM generates it at install time). The " +
      'ISP login button is hidden until this is set.',
  },
  { key: 'UISP_BASE_URL', description: 'UISP instance base URL, e.g. https://my.wisp.net.' },
  {
    key: 'UISP_CRM_APP_KEY_READ',
    description:
      'Read-only UISP CRM App Key. Used by applications (e.g. EchoWeb) to look up ' +
      'subscriber records when provisioning accounts.',
  },
];

export type Settings = Record<string, string>;

// ─── Environment overrides ────────────────────────────────────────────────────

/**
 * Any known setting may be pinned in the environment, where it wins over the
 * store. This is the escape hatch for deployments that manage configuration
 * as environment (a Helm chart, a CI secret) and for bringing an instance up
 * before NocoDB exists at all; the zero-config path leaves all of it unset.
 *
 * Blank and whitespace-only values are ignored rather than treated as an
 * override of "" — an empty variable in a compose file means "not set here".
 */
export function settingOverridesFromEnv(env: NodeJS.ProcessEnv = process.env): Settings {
  const overrides: Settings = {};
  const take = (key: string, from: string): void => {
    if (key in overrides) return;
    const raw = env[from];
    if (typeof raw === 'string' && raw.trim() !== '') overrides[key] = raw.trim();
  };
  for (const { key } of KNOWN_SETTINGS) take(key, key);
  // Environment-shaped spellings for keys whose canonical name is not, and
  // the pre-rollout names kept working for one release.
  for (const [key, names] of Object.entries(ENV_ALIASES)) {
    for (const name of names) take(key, name);
  }
  return overrides;
}

/**
 * Environment names that pin a setting whose canonical key reads oddly as a
 * variable (`trustedCIDR`), plus the names this app used before `id` became
 * `identity`. First one set wins, canonical spelling first.
 */
export const ENV_ALIASES: Record<string, string[]> = {
  trustedCIDR: ['IDENTITY_TRUSTED_NETWORK', 'ID_TRUSTED_NETWORK', 'ID_TRUSTED_APP_CIDRS'],
  IDENTITY_CLIENT_SECRET: ['ID_CLIENT_SECRET'],
};

/** Raised when a write targets a key the environment has pinned. */
export class SettingOverriddenError extends Error {
  constructor(public key: string) {
    super(
      `${key} is set in this app's environment, which overrides the settings ` +
        'store. Change it there (and restart) or unset it to manage it here.'
    );
    this.name = 'SettingOverriddenError';
  }
}

/**
 * The settings store could not answer. There is no fallback: an application
 * that cannot read its configuration says so, loudly, rather than carrying
 * on as though nothing were configured — which reads to an operator as an
 * application fault instead of the configuration fault it is.
 */
export class SettingsUnavailableError extends Error {
  constructor(
    public reason: 'unconfigured' | 'unreachable' | 'base_missing' | 'base_ambiguous' | 'table_missing',
    message: string
  ) {
    super(message);
    this.name = 'SettingsUnavailableError';
  }
}

/** Where an effective value came from — surfaced to /admin and the wizard. */
export type SettingSource = 'environment' | 'store';

export interface AdminSetting {
  key: string;
  value: string;
  description: string;
  source: SettingSource;
}

// ─── NocoDB v2 API client ─────────────────────────────────────────────────────

interface NocoTableRow {
  Id: number;
  Key: string;
  Value: string | null;
  Description: string | null;
}

/**
 * How long a value — and the resolved base/table ID with it — is trusted
 * without asking NocoDB again. A change made in NocoDB reaches every running
 * application within this window, with no restart; that includes renaming or
 * restoring the base, because the IDs live on the same clock as the values
 * rather than being resolved once per process.
 */
export const CACHE_TTL_MS = 30_000;

interface ResolvedIds {
  baseId: string;
  tableId: string;
}

export class SettingsStore {
  private ids: { at: number; ids: ResolvedIds } | null = null;
  private cache: { at: number; settings: Settings } | null = null;

  constructor(
    private config: AppConfig,
    private overrides: Settings = settingOverridesFromEnv()
  ) {}

  /** True when the environment pins this key, so the store cannot decide it. */
  isOverridden(key: string): boolean {
    return key in this.overrides;
  }

  /** The keys the environment is pinning, for logging and the admin UI. */
  overriddenKeys(): string[] {
    return Object.keys(this.overrides);
  }

  private headers(): Record<string, string> {
    return {
      'xc-token': this.config.NOCODB_API_TOKEN,
      'Content-Type': 'application/json',
    };
  }

  private async api<T>(method: string, path: string, body?: unknown): Promise<T> {
    const resp = await fetch(`${this.config.NOCODB_BASE_URL}${path}`, {
      method,
      headers: this.headers(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      throw new Error(`NocoDB ${method} ${path} failed: ${resp.status} ${text.slice(0, 200)}`);
    }
    return resp.json() as Promise<T>;
  }

  /** True when an API token is present in the environment at all. */
  isConfigured(): boolean {
    return Boolean(this.config.NOCODB_API_TOKEN);
  }

  /**
   * Prove the store is usable right now: reachable, token accepted, exactly
   * one base by our name, and the settings table inside it. Throws a
   * SettingsUnavailableError naming which of those failed.
   */
  async ping(): Promise<void> {
    await this.resolveIds();
  }

  /**
   * The base and table IDs, found by name.
   *
   * The base name is unique by our convention, so exactly one match is the
   * only acceptable answer: none means the base has not been created (or has
   * been renamed), and more than one is a configuration error we refuse to
   * guess our way past. Cached for CACHE_TTL_MS and dropped on any failure,
   * so a rename in NocoDB is picked up on the next refresh rather than at
   * the next restart.
   */
  private async resolveIds(): Promise<ResolvedIds> {
    if (this.ids && Date.now() - this.ids.at < CACHE_TTL_MS) return this.ids.ids;
    if (!this.isConfigured()) {
      throw new SettingsUnavailableError(
        'unconfigured',
        'NOCODB_BASE_URL and NOCODB_API_TOKEN must both be set — they are the ' +
          'only two things this app reads from its environment.'
      );
    }
    try {
      const bases = await this.api<{ list: Array<{ id: string; title: string }> }>(
        'GET',
        '/api/v2/meta/bases'
      );
      const matches = bases.list.filter((b) => b.title === SETTINGS_BASE_NAME);
      if (matches.length === 0) {
        throw new SettingsUnavailableError(
          'base_missing',
          `No NocoDB base named ${SETTINGS_BASE_NAME} at ${this.config.NOCODB_BASE_URL}. ` +
            'Create it (or check the token can see it) — the base is found by name, ' +
            'so a renamed base looks like a missing one.'
        );
      }
      if (matches.length > 1) {
        throw new SettingsUnavailableError(
          'base_ambiguous',
          `${matches.length} NocoDB bases are named ${SETTINGS_BASE_NAME} at ` +
            `${this.config.NOCODB_BASE_URL}. The name must be unique — this app will ` +
            'not guess which one holds its settings. Rename or delete the duplicates.'
        );
      }
      const baseId = matches[0].id;

      const tables = await this.api<{ list: Array<{ id: string; title: string }> }>(
        'GET',
        `/api/v2/meta/bases/${baseId}/tables`
      );
      const table = tables.list.find((t) => t.title === SETTINGS_TABLE_NAME);
      if (!table) {
        throw new SettingsUnavailableError(
          'table_missing',
          `The base ${SETTINGS_BASE_NAME} has no table named ${SETTINGS_TABLE_NAME}.`
        );
      }

      const ids = { baseId, tableId: table.id };
      this.ids = { at: Date.now(), ids };
      return ids;
    } catch (err) {
      this.ids = null; // never reuse an ID we could not confirm
      throw this.asUnavailable(err);
    }
  }

  /** Everything that is not already a SettingsUnavailableError is a reach failure. */
  private asUnavailable(err: unknown): SettingsUnavailableError {
    if (err instanceof SettingsUnavailableError) return err;
    return new SettingsUnavailableError(
      'unreachable',
      `NocoDB at ${this.config.NOCODB_BASE_URL} did not answer or rejected the ` +
        `token: ${String(err instanceof Error ? err.message : err).slice(0, 200)}`
    );
  }

  /**
   * Create the base and table if they are missing, and seed every known key
   * so the admin never has to guess what goes in the table.
   *
   * This is the one path allowed to create the base — everywhere else a
   * missing base is an error, because a second base appearing by accident is
   * exactly what the unique-name convention exists to prevent.
   */
  async bootstrap(): Promise<void> {
    if (!this.isConfigured()) {
      throw new SettingsUnavailableError(
        'unconfigured',
        'NOCODB_BASE_URL and NOCODB_API_TOKEN must both be set before this app ' +
          'can read or create its settings.'
      );
    }
    try {
      const bases = await this.api<{ list: Array<{ id: string; title: string }> }>(
        'GET',
        '/api/v2/meta/bases'
      );
      const matches = bases.list.filter((b) => b.title === SETTINGS_BASE_NAME);
      if (matches.length > 1) {
        throw new SettingsUnavailableError(
          'base_ambiguous',
          `${matches.length} NocoDB bases are named ${SETTINGS_BASE_NAME}. The name ` +
            'must be unique; rename or delete the duplicates.'
        );
      }
      const base =
        matches[0] ??
        (await this.api<{ id: string; title: string }>('POST', '/api/v2/meta/bases', {
          title: SETTINGS_BASE_NAME,
        }));

      const tables = await this.api<{ list: Array<{ id: string; title: string }> }>(
        'GET',
        `/api/v2/meta/bases/${base.id}/tables`
      );
      const table =
        tables.list.find((t) => t.title === SETTINGS_TABLE_NAME) ??
        (await this.api<{ id: string; title: string }>(
          'POST',
          `/api/v2/meta/bases/${base.id}/tables`,
          {
            table_name: SETTINGS_TABLE_NAME,
            title: SETTINGS_TABLE_NAME,
            columns: [
              { column_name: 'id', title: 'Id', uidt: 'ID', pk: true },
              { column_name: 'key', title: 'Key', uidt: 'SingleLineText' },
              { column_name: 'value', title: 'Value', uidt: 'LongText' },
              { column_name: 'description', title: 'Description', uidt: 'LongText' },
            ],
          }
        ));
      this.ids = { at: Date.now(), ids: { baseId: base.id, tableId: table.id } };

      // Seed missing keys so the full settings menu is visible. Values are
      // left EMPTY — a table being created for the first time is not the
      // place to invent a public URL or a domain, and an environment
      // override is not copied in either: it would be a snapshot that goes
      // stale the moment the environment changed. The setup wizard fills
      // these in from the URL the first admin actually reached this app on.
      const rows = await this.listRows();
      const present = new Set(rows.map((r) => r.Key));
      const missing = KNOWN_SETTINGS.filter((s) => !present.has(s.key));
      if (missing.length) {
        // v2 records POST accepts an array for bulk insert.
        await this.api(
          'POST',
          `/api/v2/tables/${table.id}/records`,
          missing.map((s) => ({ Key: s.key, Value: '', Description: s.description }))
        );
      }
    } catch (err) {
      this.ids = null;
      throw this.asUnavailable(err);
    }
  }

  private async listRows(): Promise<NocoTableRow[]> {
    const { tableId } = await this.resolveIds();
    try {
      const out: NocoTableRow[] = [];
      let offset = 0;
      for (;;) {
        const page = await this.api<{ list: NocoTableRow[]; pageInfo?: { isLastPage?: boolean } }>(
          'GET',
          `/api/v2/tables/${tableId}/records?limit=200&offset=${offset}`
        );
        out.push(...page.list);
        if (page.list.length < 200 || page.pageInfo?.isLastPage !== false) break;
        offset += 200;
      }
      return out;
    } catch (err) {
      // The table ID may have gone stale (base restored, table recreated);
      // drop it so the next call re-detects rather than retrying a dead ID.
      this.ids = null;
      throw this.asUnavailable(err);
    }
  }

  /**
   * All settings as a map, with the environment overriding the store. Cached
   * briefly; empty values are omitted, so a blank row reads as "not set"
   * rather than as an empty string that would shadow the override.
   */
  async getAll(): Promise<Settings> {
    if (this.cache && Date.now() - this.cache.at < CACHE_TTL_MS) return this.cache.settings;
    const rows = await this.listRows();
    const settings: Settings = {};
    for (const r of rows) {
      if (r.Key && r.Value != null && String(r.Value).trim() !== '') {
        settings[r.Key] = String(r.Value).trim();
      }
    }
    Object.assign(settings, this.overrides);
    this.cache = { at: Date.now(), settings };
    return settings;
  }

  async get(key: string): Promise<string | undefined> {
    return (await this.getAll())[key];
  }

  /**
   * Rows including empty values and descriptions — for the admin UI. The
   * effective value is reported, so a key the environment pins shows what is
   * actually in force (tagged 'environment', and not editable) rather than
   * the store row it is shadowing.
   */
  async listForAdmin(): Promise<AdminSetting[]> {
    const rows = await this.listRows();
    const described = new Map(KNOWN_SETTINGS.map((s) => [s.key, s.description]));
    const items: AdminSetting[] = rows
      .filter((r) => r.Key)
      .map((r) => ({
        key: r.Key,
        value: this.isOverridden(r.Key)
          ? this.overrides[r.Key]
          : r.Value == null
            ? ''
            : String(r.Value),
        description: r.Description == null ? '' : String(r.Description),
        source: this.isOverridden(r.Key) ? ('environment' as const) : ('store' as const),
      }));

    // An override for a key the store has no row for yet (NocoDB seeded
    // before the key existed, or bootstrap has not run) is still in force —
    // show it rather than letting it act invisibly.
    const present = new Set(items.map((i) => i.key));
    for (const [key, value] of Object.entries(this.overrides)) {
      if (present.has(key)) continue;
      items.push({
        key,
        value,
        description: described.get(key) ?? '',
        source: 'environment',
      });
    }
    return items.sort((a, b) => a.key.localeCompare(b.key));
  }

  /** Write a key to the store. Refused when the environment pins it. */
  async set(key: string, value: string): Promise<void> {
    if (this.isOverridden(key)) throw new SettingOverriddenError(key);
    const { tableId } = await this.resolveIds();
    const rows = await this.listRows();
    const existing = rows.find((r) => r.Key === key);
    if (existing) {
      await this.api('PATCH', `/api/v2/tables/${tableId}/records`, [
        { Id: existing.Id, Value: value },
      ]);
    } else {
      const known = KNOWN_SETTINGS.find((s) => s.key === key);
      await this.api('POST', `/api/v2/tables/${tableId}/records`, {
        Key: key,
        Value: value,
        Description: known?.description ?? '',
      });
    }
    this.cache = null; // read-your-writes
  }

  /**
   * Force the next read to hit NocoDB, IDs included — this is what the
   * operator-facing retry does, so a base that was missing a moment ago is
   * re-detected rather than remembered as missing.
   */
  invalidate(): void {
    this.cache = null;
    this.ids = null;
  }
}
