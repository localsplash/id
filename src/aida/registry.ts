/**
 * The application registry: `aida_application` and `aida_system_setting` in
 * the shared `AidaOffice` base.
 *
 * The registry is a directory, not a secret store. It holds which
 * applications exist, in which environment, whether they are enabled, and
 * their **public** keys. Nothing secret is written here — a read of this table
 * lets you verify signatures, never produce them.
 *
 * Identity is `(application_name, environment)` and never a hostname:
 * hostnames change with ingress, replicas share one identity, and a service
 * called through two names is still one application.
 *
 * The logic lives behind {@link RegistryBackend} so it can be exercised
 * against an in-memory double — these paths gate sign-in, and they should be
 * testable without a NocoDB or a real credential anywhere near them.
 */

export interface ApplicationRow {
  Id: number;
  application_name: string;
  environment: string;
  public_key: string;
  key_version: number;
  previous_public_key: string | null;
  previous_key_version: number | null;
  previous_key_retired: boolean;
  enabled: boolean;
  last_seen_at: string | null;
  notes: string | null;
}

export type NewApplicationRow = Omit<ApplicationRow, "Id">;

export interface RegistryBackend {
  listApplications(): Promise<ApplicationRow[]>;
  createApplication(row: NewApplicationRow): Promise<ApplicationRow>;
  updateApplication(
    id: number,
    patch: Partial<NewApplicationRow>,
  ): Promise<void>;
  getSetting(key: string): Promise<string | null>;
  setSetting(key: string, value: string): Promise<void>;
}

export const AUTO_ENROLL_KEY = "auto_enroll_applications";
export const EXPECTED_APPLICATIONS_KEY = "expected_applications";
export const DEFAULT_EXPECTED_APPLICATIONS = [
  "aida-control",
  "id",
  "aida-admin",
];

export type RegisterAction = "created" | "rotated" | "refreshed";

export interface RegisterResult {
  row: ApplicationRow;
  action: RegisterAction;
  /** True when this registration completed the expected set for the environment. */
  closedAutoEnroll: boolean;
}

export class EnrollmentClosedError extends Error {
  constructor(
    readonly application: string,
    readonly environment: string,
  ) {
    super(
      `no row in aida_application for (${application}, ${environment}) and ` +
        `${AUTO_ENROLL_KEY} is closed for this environment. Add the row by hand, or add ` +
        `"${application}" to ${EXPECTED_APPLICATIONS_KEY} to re-open enrolment.`,
    );
    this.name = "EnrollmentClosedError";
  }
}

/**
 * `auto_enroll_applications` is per-environment: staging finishing its
 * rollout must not close the door on production. A bare `true`/`false`
 * applies to every environment, which is the readable thing for an operator
 * to type by hand; the automatic close writes the per-environment object.
 */
export function autoEnrollOpen(
  raw: string | null,
  environment: string,
): boolean {
  if (raw === null || raw.trim() === "") return true; // absent = first boot
  const text = raw.trim();
  if (text === "true") return true;
  if (text === "false") return false;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (typeof parsed === "boolean") return parsed;
    if (parsed && typeof parsed === "object") {
      const value = (parsed as Record<string, unknown>)[environment];
      return value === undefined ? true : Boolean(value);
    }
  } catch {
    // Unparseable is treated as open: refusing to enrol on a typo would make
    // a malformed cell an outage, and the row is visible in NocoDB anyway.
  }
  return true;
}

export function withEnvironmentClosed(
  raw: string | null,
  environment: string,
): string {
  let map: Record<string, boolean> = {};
  const text = (raw ?? "").trim();
  // Already closed everywhere. Expanding this into a single-environment map
  // would silently re-open every other environment.
  if (text === "false") return "false";
  if (text && text !== "true" && text !== "false") {
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(
          parsed as Record<string, unknown>,
        )) {
          map[k] = Boolean(v);
        }
      }
    } catch {
      map = {};
    }
  } else if (text === "true" || text === "") {
    map = {};
  }
  map[environment] = false;
  return JSON.stringify(map);
}

export function parseExpectedApplications(raw: string | null): string[] {
  const text = (raw ?? "").trim();
  if (!text) return DEFAULT_EXPECTED_APPLICATIONS;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (Array.isArray(parsed))
      return parsed.map((v) => String(v)).filter(Boolean);
  } catch {
    // Fall through to a comma-separated list — an operator editing a NocoDB
    // cell should not have to remember JSON brackets.
  }
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export class AidaRegistry {
  private cache: { at: number; rows: ApplicationRow[] } | null = null;

  constructor(
    private backend: RegistryBackend,
    private cacheTtlMs = 30_000,
    private now: () => number = Date.now,
  ) {}

  invalidate(): void {
    this.cache = null;
  }

  private async rows(force = false): Promise<ApplicationRow[]> {
    if (!force && this.cache && this.now() - this.cache.at < this.cacheTtlMs) {
      return this.cache.rows;
    }
    const rows = await this.backend.listApplications();
    this.cache = { at: this.now(), rows };
    return rows;
  }

  async find(
    application: string,
    environment: string,
    force = false,
  ): Promise<ApplicationRow | null> {
    const rows = await this.rows(force);
    return (
      rows.find(
        (r) =>
          r.application_name === application && r.environment === environment,
      ) ?? null
    );
  }

  /**
   * Publish this service's public key and refresh its liveness.
   *
   * Idempotent by construction: the row is looked up by
   * `(application_name, environment)` and updated in place, so restarts do not
   * accumulate rows. An unchanged key is a `last_seen_at` touch and nothing
   * more.
   */
  async registerSelf(
    application: string,
    environment: string,
    publicKey: string,
  ): Promise<RegisterResult> {
    const existing = await this.find(application, environment, true);
    const stamp = new Date(this.now()).toISOString();
    let row: ApplicationRow;
    let action: RegisterAction;

    if (!existing) {
      const autoEnroll = await this.backend.getSetting(AUTO_ENROLL_KEY);
      if (!autoEnrollOpen(autoEnroll, environment)) {
        throw new EnrollmentClosedError(application, environment);
      }
      row = await this.backend.createApplication({
        application_name: application,
        environment,
        public_key: publicKey,
        key_version: 1,
        previous_public_key: null,
        previous_key_version: null,
        previous_key_retired: true,
        enabled: true,
        last_seen_at: stamp,
        notes: null,
      });
      action = "created";
    } else if (existing.public_key !== publicKey) {
      // A rotation. The outgoing key stays acceptable until someone retires
      // it, so peers that have not re-read the registry keep working through
      // the overlap instead of failing for one cache interval.
      const patch = {
        previous_public_key: existing.public_key,
        previous_key_version: existing.key_version,
        previous_key_retired: false,
        public_key: publicKey,
        key_version: existing.key_version + 1,
        last_seen_at: stamp,
      };
      await this.backend.updateApplication(existing.Id, patch);
      row = { ...existing, ...patch };
      action = "rotated";
    } else {
      await this.backend.updateApplication(existing.Id, {
        last_seen_at: stamp,
      });
      row = { ...existing, last_seen_at: stamp };
      action = "refreshed";
    }

    this.cache = null;
    const closedAutoEnroll = await this.maybeCloseEnrollment(environment);
    return { row, action, closedAutoEnroll };
  }

  /**
   * Close enrolment for this environment once every expected application has
   * registered and is enabled. The expected list does double duty: appending
   * a name re-opens the door for exactly as long as that service needs to
   * register itself, with no separate control to remember.
   */
  private async maybeCloseEnrollment(environment: string): Promise<boolean> {
    const current = await this.backend.getSetting(AUTO_ENROLL_KEY);
    if (!autoEnrollOpen(current, environment)) return false;
    const expected = parseExpectedApplications(
      await this.backend.getSetting(EXPECTED_APPLICATIONS_KEY),
    );
    if (expected.length === 0) return false;
    const rows = await this.rows(true);
    const satisfied = expected.every((name) =>
      rows.some(
        (r) =>
          r.application_name === name &&
          r.environment === environment &&
          r.enabled,
      ),
    );
    if (!satisfied) return false;
    await this.backend.setSetting(
      AUTO_ENROLL_KEY,
      withEnvironmentClosed(current, environment),
    );
    return true;
  }

  /** Expected applications that have not yet registered here. Surfaced on readiness. */
  async pendingApplications(environment: string): Promise<string[]> {
    const expected = parseExpectedApplications(
      await this.backend.getSetting(EXPECTED_APPLICATIONS_KEY),
    );
    const rows = await this.rows();
    return expected.filter(
      (name) =>
        !rows.some(
          (r) =>
            r.application_name === name &&
            r.environment === environment &&
            r.enabled,
        ),
    );
  }
}

/** Every public key currently acceptable for a row: the current one, plus an unretired previous. */
export function acceptedKeys(row: ApplicationRow): string[] {
  const keys = [row.public_key].filter(Boolean);
  if (row.previous_public_key && !row.previous_key_retired)
    keys.push(row.previous_public_key);
  return keys;
}

/**
 * In-memory backend. Used by the tests, and the readable statement of what a
 * backend has to do.
 */
export class InMemoryRegistryBackend implements RegistryBackend {
  private nextId = 1;
  rows: ApplicationRow[] = [];
  settings = new Map<string, string>();

  async listApplications(): Promise<ApplicationRow[]> {
    return this.rows.map((r) => ({ ...r }));
  }

  async createApplication(row: NewApplicationRow): Promise<ApplicationRow> {
    const created = { Id: this.nextId++, ...row };
    this.rows.push(created);
    return { ...created };
  }

  async updateApplication(
    id: number,
    patch: Partial<NewApplicationRow>,
  ): Promise<void> {
    const row = this.rows.find((r) => r.Id === id);
    if (row) Object.assign(row, patch);
  }

  async getSetting(key: string): Promise<string | null> {
    return this.settings.get(key) ?? null;
  }

  async setSetting(key: string, value: string): Promise<void> {
    this.settings.set(key, value);
  }
}
