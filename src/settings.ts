import { AppConfig } from './config';

/**
 * Settings live in NocoDB, not in the environment.
 *
 * The `oAuthConfig` table is a plain key/value store that a Super System Admin
 * can edit either through NocoDB itself at nocodb.<parent-domain>, or through
 * this app's /admin page. Every app under the parent domain reads the same
 * table with its own NocoDB API token, so one set of credentials serves
 * echo.X.TLD, aida.X.TLD, and whatever comes next.
 *
 * It lives in `AidaOffice`, the one base every Aida project shares. NocoDB link
 * fields resolve only within a base, so sharing one is what lets these settings
 * relate to the tables the other projects own. The base no longer says whose
 * data it is — the table title does, and `oAuthConfig` is this project's.
 *
 * On boot the table is created and seeded with every known key (empty
 * values) if it does not exist yet, so the admin sees the full menu of
 * settings rather than having to guess key names. Unknown keys are kept —
 * new applications may store their own settings here without this app
 * needing to learn about them.
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
      'Public base URL of this identity app, e.g. https://id.wisp.net. Used to build ' +
      'the OAuth callback URIs registered with each provider.',
  },
  {
    key: 'ID_CLIENT_SECRET',
    description:
      'Shared secret that applications present when exchanging a handoff code at ' +
      'POST /api/token. Generate with: openssl rand -hex 32',
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

  constructor(private config: AppConfig) {}

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
      // Creating the base on demand is what makes a genuine first boot work, so
      // it stays. But AidaOffice is shared now, and a mistyped NOCODB_BASE_NAME
      // would otherwise create a second empty base and quietly start writing to
      // it — a split-brain that looks like a working service until someone
      // wonders where the settings went. Creation is therefore loud: on a real
      // first boot this line is expected, and anywhere else it is the answer.
      console.warn(
        `[settings] NocoDB base "${this.config.NOCODB_BASE_NAME}" did not exist and was created. ` +
          `Expected on a first boot. Otherwise NOCODB_BASE_NAME is probably wrong — the Aida ` +
          `projects share one base, and settings written here will not be seen by the others. ` +
          `Bases present: ${bases.list.map((b) => b.title).join(', ') || '(none)'}.`
      );
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

    // Seed missing keys (empty values) so the full settings menu is visible.
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

  /** All settings as a map. Cached briefly; empty values are omitted. */
  async getAll(): Promise<Settings> {
    if (this.cache && Date.now() - this.cache.at < CACHE_TTL_MS) return this.cache.settings;
    const rows = await this.listRows();
    const settings: Settings = {};
    for (const r of rows) {
      if (r.Key && r.Value != null && String(r.Value).trim() !== '') {
        settings[r.Key] = String(r.Value).trim();
      }
    }
    this.cache = { at: Date.now(), settings };
    return settings;
  }

  async get(key: string): Promise<string | undefined> {
    return (await this.getAll())[key];
  }

  /** Rows including empty values and descriptions — for the admin UI. */
  async listForAdmin(): Promise<Array<{ key: string; value: string; description: string }>> {
    const rows = await this.listRows();
    return rows
      .filter((r) => r.Key)
      .map((r) => ({
        key: r.Key,
        value: r.Value == null ? '' : String(r.Value),
        description: r.Description == null ? '' : String(r.Description),
      }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }

  async set(key: string, value: string): Promise<void> {
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
