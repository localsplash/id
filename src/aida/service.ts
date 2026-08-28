import type { Request, RequestHandler, Response } from "express";
import { ServiceKey } from "./keys";
import {
  AidaRegistry,
  ApplicationRow,
  EnrollmentClosedError,
  RegisterResult,
  acceptedKeys,
} from "./registry";
import {
  HEADERS,
  RejectionReason,
  newNonce,
  readCredentials,
  signRequest,
  timestampIsFresh,
  verifySignature,
} from "./signing";

/**
 * Ties the service key, the registry and the replay store together: publishes
 * this application's public key, signs outbound calls, and verifies inbound
 * ones.
 *
 * `id` is on the authentication path, so two behaviours here are deliberate
 * and differ from the other Aida services:
 *
 *  - a registry that cannot be reached at startup leaves this service
 *    **unready** rather than started-and-failing at the first call, so a
 *    rollout stops instead of half-working;
 *  - readiness carries the failure category and the row to inspect, because
 *    "why is sign-in failing" has to be answerable from `/readyz` during an
 *    incident rather than from a log dive.
 */

export interface NonceStore {
  /** Records the nonce; false when it has been seen before. */
  consume(nonce: string, expiresAt: Date): Promise<boolean>;
}

export class InMemoryNonceStore implements NonceStore {
  private seen = new Map<string, number>();
  async consume(nonce: string, expiresAt: Date): Promise<boolean> {
    const now = Date.now();
    for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, expiresAt.getTime());
    return true;
  }
}

export type ReadinessReason =
  "registry_unreachable" | "enrollment_closed" | "disabled" | "not_registered";

export interface ServiceStatus {
  ready: boolean;
  application: string;
  environment: string;
  keyVersion: number | null;
  keySource: "environment" | "ephemeral";
  reason?: ReadinessReason;
  detail?: string;
  /** Where to look in NocoDB when this is unhappy. */
  row: {
    base: string;
    table: string;
    application_name: string;
    environment: string;
  };
  /** Expected applications that have not registered yet — enrolment stays open for them. */
  pendingApplications?: string[];
  checkedAt: string;
}

export interface VerifiedCaller {
  application: string;
  environment: string;
  keyVersion: number | null;
}

export type VerifyOutcome =
  | { ok: true; caller: VerifiedCaller }
  | {
      ok: false;
      reason: RejectionReason | "registry_unreachable";
      detail: string;
    };

export interface Logger {
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  error(obj: unknown, msg?: string): void;
}

export interface AidaServiceOptions {
  key: ServiceKey;
  registry: AidaRegistry;
  nonces: NonceStore;
  application: string;
  environment: string;
  baseName: string;
  applicationTable: string;
  logger: Logger;
  now?: () => number;
}

export class AidaService {
  private status: ServiceStatus;
  private keyVersion = 1;

  constructor(private opts: AidaServiceOptions) {
    this.status = {
      ready: false,
      application: opts.application,
      environment: opts.environment,
      keyVersion: null,
      keySource: opts.key.ephemeral ? "ephemeral" : "environment",
      reason: "not_registered",
      detail: "startup registration has not run yet",
      row: this.rowRef(),
      checkedAt: new Date(this.now()).toISOString(),
    };
  }

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  private rowRef(): ServiceStatus["row"] {
    return {
      base: this.opts.baseName,
      table: this.opts.applicationTable,
      application_name: this.opts.application,
      environment: this.opts.environment,
    };
  }

  getStatus(): ServiceStatus {
    return { ...this.status, row: this.rowRef() };
  }

  /**
   * Publish the public key and refresh liveness. Called at startup and on a
   * ticker: the repeat is what keeps `last_seen_at` meaningful and what lets
   * a service that booted against an unreachable registry become ready later
   * without a restart.
   */
  async register(): Promise<ServiceStatus> {
    const { application, environment, key, registry, logger } = this.opts;
    const base: Pick<
      ServiceStatus,
      "application" | "environment" | "keySource" | "row"
    > = {
      application,
      environment,
      keySource: key.ephemeral ? "ephemeral" : "environment",
      row: this.rowRef(),
    };
    try {
      const result: RegisterResult = await registry.registerSelf(
        application,
        environment,
        key.publicKey,
      );
      this.keyVersion = result.row.key_version;
      const pending = await registry
        .pendingApplications(environment)
        .catch(() => []);
      if (!result.row.enabled) {
        this.status = {
          ...base,
          ready: false,
          keyVersion: result.row.key_version,
          reason: "disabled",
          detail:
            "this application is registered but its `enabled` box is unticked, so peers will " +
            "refuse its calls. Tick it in NocoDB.",
          pendingApplications: pending,
          checkedAt: new Date(this.now()).toISOString(),
        };
        logger.error(
          { ...this.rowRef(), reason: "disabled" },
          "[aida] service registration disabled",
        );
        return this.getStatus();
      }
      this.status = {
        ...base,
        ready: true,
        keyVersion: result.row.key_version,
        pendingApplications: pending,
        checkedAt: new Date(this.now()).toISOString(),
      };
      if (result.action !== "refreshed") {
        logger.info(
          {
            ...this.rowRef(),
            action: result.action,
            key_version: result.row.key_version,
          },
          `[aida] service key ${result.action === "created" ? "published" : "rotated"}`,
        );
      }
      if (result.closedAutoEnroll) {
        logger.info(
          { ...this.rowRef() },
          "[aida] every expected application has registered — auto-enrolment closed for this environment",
        );
      }
      return this.getStatus();
    } catch (err) {
      const closed = err instanceof EnrollmentClosedError;
      this.status = {
        ...base,
        ready: false,
        keyVersion: null,
        reason: closed ? "enrollment_closed" : "registry_unreachable",
        // /readyz is unauthenticated, so the body carries the category and the
        // row — both already public in docs/service-auth.md — and not raw
        // backend error text, which would echo whatever NocoDB said to anyone
        // who asked. The underlying message goes to the log line below.
        detail: closed
          ? "this application has no row and auto-enrolment is closed for this environment; " +
            "add the row, or add this name to expected_applications"
          : "the application registry could not be read; the underlying error is in the service log",
        checkedAt: new Date(this.now()).toISOString(),
      };
      logger.error(
        {
          ...this.rowRef(),
          reason: this.status.reason,
          err: (err as Error).message,
        },
        "[aida] service registration failed",
      );
      return this.getStatus();
    }
  }

  /** Sign and send a request to another Aida service. */
  async signedFetch(
    url: string,
    init: {
      method?: string;
      body?: string | Buffer;
      headers?: Record<string, string>;
    } = {},
  ): Promise<globalThis.Response> {
    const method = (init.method ?? "GET").toUpperCase();
    const target = new URL(url);
    const body =
      init.body === undefined ? Buffer.alloc(0) : Buffer.from(init.body);
    const headers = signRequest(this.opts.key.privateKey, this.keyVersion, {
      method,
      path: `${target.pathname}${target.search}`,
      body,
      timestamp: Math.floor(this.now() / 1000),
      nonce: newNonce(),
      application: this.opts.application,
      environment: this.opts.environment,
    });
    return fetch(url, {
      method,
      headers: { ...init.headers, ...headers },
      body: method === "GET" || method === "HEAD" ? undefined : body,
    });
  }

  /**
   * Verify an inbound signed request.
   *
   * The nonce is consumed last, once everything else has passed: a request
   * that fails its signature must not be able to burn a nonce the legitimate
   * caller is about to use.
   */
  async verify(
    headers: Record<string, string | string[] | undefined>,
    method: string,
    path: string,
    body: Buffer,
  ): Promise<VerifyOutcome> {
    const reject = (
      reason: RejectionReason | "registry_unreachable",
      detail: string,
      caller?: { application: string; environment: string },
    ): VerifyOutcome => {
      this.opts.logger.warn(
        {
          reason,
          presented: caller ?? null,
          inspect: {
            base: this.opts.baseName,
            table: this.opts.applicationTable,
            application_name: caller?.application ?? null,
            environment: caller?.environment ?? null,
          },
          detail,
        },
        "[aida] inbound service call refused",
      );
      return { ok: false, reason, detail };
    };

    const presented = readCredentials(headers);
    if (!presented) {
      return reject(
        "malformed",
        `missing or malformed Aida signature headers (${Object.values(HEADERS).join(", ")})`,
      );
    }
    const who = {
      application: presented.application,
      environment: presented.environment,
    };

    if (!timestampIsFresh(presented.timestamp, this.now())) {
      return reject(
        "stale_timestamp",
        `presented timestamp ${presented.timestamp} is outside the accepted window; check clock skew`,
        who,
      );
    }

    let row: ApplicationRow | null;
    try {
      row = await this.opts.registry.find(
        presented.application,
        presented.environment,
      );
      // A peer that has only just enrolled will not be in the cached copy, so
      // one forced re-read stands between a fresh enrolment and a rejection.
      if (!row) {
        row = await this.opts.registry.find(
          presented.application,
          presented.environment,
          true,
        );
      }
    } catch (err) {
      return reject("registry_unreachable", (err as Error).message, who);
    }
    if (!row) {
      return reject(
        "unknown_application",
        "no row for the presented (application, environment)",
        who,
      );
    }
    if (!row.enabled) {
      return reject(
        "disabled",
        "the row exists but `enabled` is unticked",
        who,
      );
    }

    let verified = verifySignature(
      acceptedKeys(row),
      presented,
      method,
      path,
      body,
    );
    if (!verified) {
      // The peer may have rotated since this copy of the row was cached. One
      // forced re-read is what lets a peer's rotation take effect here without
      // a restart or a wait for the cache to lapse.
      const fresh = await this.opts.registry
        .find(presented.application, presented.environment, true)
        .catch(() => null);
      if (fresh && fresh.public_key !== row.public_key) {
        verified = verifySignature(
          acceptedKeys(fresh),
          presented,
          method,
          path,
          body,
        );
      }
    }
    if (!verified) {
      return reject(
        "key_mismatch",
        "the signature did not verify against any unretired public key on the row",
        who,
      );
    }

    // A replay-store outage fails open: everything else has already passed, so
    // the exposure is a replay inside the freshness window, against the
    // alternative of taking sign-in down for everyone. Deliberate, and logged
    // so it is never a silent downgrade.
    const fresh = await this.opts.nonces
      .consume(presented.nonce, new Date(this.now() + 600_000))
      .catch((err: Error) => {
        this.opts.logger.error(
          { presented: who, err: err.message },
          "[aida] replay store unavailable — accepting the request without replay protection",
        );
        return true;
      });
    if (!fresh) {
      return reject("replayed_nonce", "this nonce has already been used", who);
    }

    return {
      ok: true,
      caller: {
        application: presented.application,
        environment: presented.environment,
        keyVersion: presented.keyVersion,
      },
    };
  }

  /**
   * Guard for `/internal/*` routes. The response says only that the call was
   * refused: telling a caller which check failed would hand it a probing
   * oracle. The category is in the log line above, with the row to inspect.
   */
  requireSignedCaller(): RequestHandler {
    return (req: Request, res: Response, next) => {
      const body: Buffer = Buffer.isBuffer(
        (req as { rawBody?: Buffer }).rawBody,
      )
        ? ((req as { rawBody?: Buffer }).rawBody as Buffer)
        : Buffer.alloc(0);
      void this.verify(req.headers, req.method, req.originalUrl, body).then(
        (outcome) => {
          if (!outcome.ok) {
            const code = outcome.reason === "registry_unreachable" ? 503 : 401;
            res
              .status(code)
              .json({ error: code === 503 ? "unavailable" : "unauthorized" });
            return;
          }
          (req as { aidaCaller?: VerifiedCaller }).aidaCaller = outcome.caller;
          next();
        },
      );
    };
  }
}
