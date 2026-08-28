import { AppConfig } from "../config";
import { ApplicationRow, NewApplicationRow, RegistryBackend } from "./registry";

/**
 * NocoDB implementation of {@link RegistryBackend}.
 *
 * The tables live in the shared `AidaOffice` base alongside `oAuthConfig`.
 * This module finds or creates the two tables but **never creates the base**:
 * the settings store already owns that decision and warns when it happens, and
 * a registry that silently created a second base would publish this service's
 * key somewhere no peer reads.
 *
 * AidaControl's manifest owns these table definitions upstream. Creating them
 * here is what lets this service come up in either order; when the table
 * already exists the columns are used as found, and a missing expected column
 * is reported by name rather than silently read as undefined.
 */

export const APPLICATION_TABLE = "aida_application";
export const SETTING_TABLE = "aida_system_setting";

const APPLICATION_COLUMNS = [
  { column_name: "id", title: "Id", uidt: "ID", pk: true },
  {
    column_name: "application_name",
    title: "application_name",
    uidt: "SingleLineText",
  },
  { column_name: "environment", title: "environment", uidt: "SingleLineText" },
  { column_name: "public_key", title: "public_key", uidt: "LongText" },
  { column_name: "key_version", title: "key_version", uidt: "Number" },
  {
    column_name: "previous_public_key",
    title: "previous_public_key",
    uidt: "LongText",
  },
  {
    column_name: "previous_key_version",
    title: "previous_key_version",
    uidt: "Number",
  },
  {
    column_name: "previous_key_retired",
    title: "previous_key_retired",
    uidt: "Checkbox",
  },
  { column_name: "enabled", title: "enabled", uidt: "Checkbox" },
  { column_name: "last_seen_at", title: "last_seen_at", uidt: "DateTime" },
  { column_name: "notes", title: "notes", uidt: "LongText" },
];

const SETTING_COLUMNS = [
  { column_name: "id", title: "Id", uidt: "ID", pk: true },
  { column_name: "setting_key", title: "setting_key", uidt: "SingleLineText" },
  { column_name: "setting_value", title: "setting_value", uidt: "LongText" },
  { column_name: "description", title: "description", uidt: "LongText" },
];

// An operator may well have created the settings table by hand, or another
// project may have used the plainer column names. Reading is tolerant across
// the obvious spellings; writing uses whichever spelling the row already has.
const KEY_FIELDS = ["setting_key", "key", "Key"];
const VALUE_FIELDS = ["setting_value", "value", "Value"];

type Record_ = Record<string, unknown>;

function pick(
  row: Record_,
  candidates: string[],
): { field: string; value: unknown } | null {
  for (const field of candidates) {
    if (Object.prototype.hasOwnProperty.call(row, field))
      return { field, value: row[field] };
  }
  return null;
}

function asBool(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function asNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function asString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const s = String(value);
  return s === "" ? null : s;
}

export class NocoRegistryBackend implements RegistryBackend {
  private applicationTableId: string | null = null;
  private settingTableId: string | null = null;

  constructor(private config: AppConfig) {}

  private async api<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const resp = await fetch(`${this.config.NOCODB_BASE_URL}${path}`, {
      method,
      headers: {
        "xc-token": this.config.NOCODB_API_TOKEN,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(
        `NocoDB ${method} ${path} failed: ${resp.status} ${text.slice(0, 200)}`,
      );
    }
    return resp.json() as Promise<T>;
  }

  /** Find or create both tables. Safe to call repeatedly. */
  async bootstrap(): Promise<void> {
    const bases = await this.api<{
      list: Array<{ id: string; title: string }>;
    }>("GET", "/api/v2/meta/bases");
    const base = bases.list.find(
      (b) => b.title === this.config.NOCODB_BASE_NAME,
    );
    if (!base) {
      throw new Error(
        `NocoDB base "${this.config.NOCODB_BASE_NAME}" does not exist, so this service has ` +
          `nowhere to publish its public key. The settings store creates it on first boot — if ` +
          `that has not happened, NOCODB_BASE_NAME is probably wrong. Bases present: ` +
          `${bases.list.map((b) => b.title).join(", ") || "(none)"}.`,
      );
    }
    const tables = await this.api<{
      list: Array<{ id: string; title: string }>;
    }>("GET", `/api/v2/meta/bases/${base.id}/tables`);
    const ensure = async (
      title: string,
      columns: unknown[],
    ): Promise<string> => {
      const found = tables.list.find((t) => t.title === title);
      if (found) return found.id;
      const created = await this.api<{ id: string }>(
        "POST",
        `/api/v2/meta/bases/${base.id}/tables`,
        { table_name: title, title, columns },
      );
      return created.id;
    };
    this.applicationTableId = await ensure(
      APPLICATION_TABLE,
      APPLICATION_COLUMNS,
    );
    this.settingTableId = await ensure(SETTING_TABLE, SETTING_COLUMNS);
  }

  private async tableId(which: "application" | "setting"): Promise<string> {
    if (!this.applicationTableId || !this.settingTableId)
      await this.bootstrap();
    const id =
      which === "application" ? this.applicationTableId : this.settingTableId;
    if (!id) throw new Error(`NocoDB table for ${which} could not be resolved`);
    return id;
  }

  private async records(tableId: string): Promise<Record_[]> {
    const out: Record_[] = [];
    let offset = 0;
    for (;;) {
      const page = await this.api<{
        list: Record_[];
        pageInfo?: { isLastPage?: boolean };
      }>("GET", `/api/v2/tables/${tableId}/records?limit=200&offset=${offset}`);
      out.push(...page.list);
      if (page.list.length < 200 || page.pageInfo?.isLastPage !== false) break;
      offset += 200;
    }
    return out;
  }

  async listApplications(): Promise<ApplicationRow[]> {
    const tableId = await this.tableId("application");
    const rows = await this.records(tableId);
    if (
      rows.length &&
      !Object.prototype.hasOwnProperty.call(rows[0], "application_name")
    ) {
      throw new Error(
        `${APPLICATION_TABLE} in base "${this.config.NOCODB_BASE_NAME}" has no ` +
          `"application_name" column. Columns found: ${Object.keys(rows[0]).join(", ")}. The ` +
          `expected shape is documented in docs/service-auth.md.`,
      );
    }
    return rows.map((r) => ({
      Id: Number(r.Id),
      application_name: String(r.application_name ?? ""),
      environment: String(r.environment ?? ""),
      public_key: String(r.public_key ?? ""),
      key_version: asNumber(r.key_version) ?? 1,
      previous_public_key: asString(r.previous_public_key),
      previous_key_version: asNumber(r.previous_key_version),
      previous_key_retired: asBool(r.previous_key_retired),
      enabled: asBool(r.enabled),
      last_seen_at: asString(r.last_seen_at),
      notes: asString(r.notes),
    }));
  }

  async createApplication(row: NewApplicationRow): Promise<ApplicationRow> {
    const tableId = await this.tableId("application");
    const created = await this.api<Record_>(
      "POST",
      `/api/v2/tables/${tableId}/records`,
      row,
    );
    const id = Number((Array.isArray(created) ? created[0] : created)?.Id ?? 0);
    return { Id: id, ...row };
  }

  async updateApplication(
    id: number,
    patch: Partial<NewApplicationRow>,
  ): Promise<void> {
    const tableId = await this.tableId("application");
    await this.api("PATCH", `/api/v2/tables/${tableId}/records`, [
      { Id: id, ...patch },
    ]);
  }

  async getSetting(key: string): Promise<string | null> {
    const tableId = await this.tableId("setting");
    const rows = await this.records(tableId);
    for (const row of rows) {
      const k = pick(row, KEY_FIELDS);
      if (k && String(k.value) === key) {
        const v = pick(row, VALUE_FIELDS);
        return v ? asString(v.value) : null;
      }
    }
    return null;
  }

  async setSetting(key: string, value: string): Promise<void> {
    const tableId = await this.tableId("setting");
    const rows = await this.records(tableId);
    for (const row of rows) {
      const k = pick(row, KEY_FIELDS);
      if (k && String(k.value) === key) {
        const v = pick(row, VALUE_FIELDS);
        await this.api("PATCH", `/api/v2/tables/${tableId}/records`, [
          { Id: row.Id, [v?.field ?? "setting_value"]: value },
        ]);
        return;
      }
    }
    await this.api("POST", `/api/v2/tables/${tableId}/records`, {
      setting_key: key,
      setting_value: value,
    });
  }
}
