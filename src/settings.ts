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
    key: 'ID_CLIENT_SECRET',
    description:
      'LEGACY (rollout only). Shared secret applications present at POST /api/token ' +
      'when ID_APP_AUTH_MODE is secret or dual. The POC default (cidr) trusts the ' +
      'ID_TRUSTED_APP_CIDRS IPv4 allowlist instead and ignores this. ' +
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
  for (const { key } of KNOWN_SETTINGS) {
    const raw = env[key];
    if (typeof raw === 'string' && raw.trim() !== '') overrides[key] = raw.trim();
  }
  return overrides;
}

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

const CACHE_TTL_MS = 30_000;

export class SettingsStore {
  private tableId: string | null = null;
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

  /** Cheap reachability/auth probe — throws when NocoDB cannot be used. */
  async ping(): Promise<void> {
    await this.api('GET', '/api/v2/meta/bases');
  }

  /**
   * Find (or create) the base and table, seeding every known key so the
   * admin never has to guess what goes in the table. Safe to call more than
   * once; each step is a no-op when the object already exists.
   */
  async bootstrap(): Promise<void> {
    const bases = await this.api<{ list: Array<{ id: string; title: string }> }>(
      'GET',
      '/api/v2/meta/bases'
    );
    let base = bases.list.find((b) => b.title === this.config.NOCODB_BASE_NAME);
    if (!base) {
      base = await this.api<{ id: string; title: string }>('POST', '/api/v2/meta/bases', {
        title: this.config.NOCODB_BASE_NAME,
      });
    }

    const tables = await this.api<{ list: Array<{ id: string; title: string }> }>(
      'GET',
      `/api/v2/meta/bases/${base.id}/tables`
    );
    let table = tables.list.find((t) => t.title === this.config.NOCODB_TABLE_NAME);
    if (!table) {
      table = await this.api<{ id: string; title: string }>(
        'POST',
        `/api/v2/meta/bases/${base.id}/tables`,
        {
          table_name: this.config.NOCODB_TABLE_NAME,
          title: this.config.NOCODB_TABLE_NAME,
          columns: [
            { column_name: 'id', title: 'Id', uidt: 'ID', pk: true },
            { column_name: 'key', title: 'Key', uidt: 'SingleLineText' },
            { column_name: 'value', title: 'Value', uidt: 'LongText' },
            { column_name: 'description', title: 'Description', uidt: 'LongText' },
          ],
        }
      );
    }
    this.tableId = table.id;

    // Seed missing keys so the full settings menu is visible. Values are
    // left EMPTY — a database being created for the first time is not the
    // place to invent a public URL or a domain, and an environment override
    // is not copied in either: it would be a snapshot that goes stale the
    // moment the environment changes. The setup wizard fills these in from
    // the URL the first admin actually reached this service on.
    const rows = await this.listRows();
    const present = new Set(rows.map((r) => r.Key));
    const missing = KNOWN_SETTINGS.filter((s) => !present.has(s.key));
    if (missing.length) {
      // v2 records POST accepts an array for bulk insert.
      await this.api(
        'POST',
        `/api/v2/tables/${this.tableId}/records`,
        missing.map((s) => ({ Key: s.key, Value: '', Description: s.description }))
      );
    }
  }

  private async resolveTableId(): Promise<string> {
    if (!this.tableId) await this.bootstrap();
    if (!this.tableId) throw new Error('NocoDB oAuthConfig table could not be resolved');
    return this.tableId;
  }

  private async listRows(): Promise<NocoTableRow[]> {
    const tableId = this.tableId ?? (await this.resolveTableId());
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

  /**
   * The effective settings when the store cannot be reached at all — the
   * environment alone. Enough for an instance whose configuration is pinned
   * to keep working while NocoDB is down or not yet installed.
   */
  fromEnvOnly(): Settings {
    return { ...this.overrides };
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
    const tableId = await this.resolveTableId();
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

  /** Force the next read to hit NocoDB. */
  invalidate(): void {
    this.cache = null;
  }
}
