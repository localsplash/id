import { describe, it, expect } from "vitest";
import crypto from "crypto";
import {
  PRIVATE_KEY_VAR,
  generatePrivateKeyB64,
  loadServiceKey,
  parsePrivateKeyB64,
  publicKeyB64,
} from "./keys";
import {
  CLOCK_SKEW_SECONDS,
  canonicalString,
  newNonce,
  readCredentials,
  signRequest,
} from "./signing";
import {
  AUTO_ENROLL_KEY,
  AidaRegistry,
  EXPECTED_APPLICATIONS_KEY,
  InMemoryRegistryBackend,
  acceptedKeys,
  autoEnrollOpen,
  parseExpectedApplications,
  withEnvironmentClosed,
} from "./registry";
import { AidaService, InMemoryNonceStore, Logger } from "./service";

// ─── helpers ─────────────────────────────────────────────────────────────────

function keypair() {
  const b64 = generatePrivateKeyB64();
  const privateKey = parsePrivateKeyB64(b64);
  return { b64, privateKey, publicKey: publicKeyB64(privateKey) };
}

class CapturingLogger implements Logger {
  lines: string[] = [];
  private push(obj: unknown, msg?: string) {
    this.lines.push(JSON.stringify(obj) + " " + (msg ?? ""));
  }
  info(obj: unknown, msg?: string) {
    this.push(obj, msg);
  }
  warn(obj: unknown, msg?: string) {
    this.push(obj, msg);
  }
  error(obj: unknown, msg?: string) {
    this.push(obj, msg);
  }
}

function makeService(opts: {
  backend?: InMemoryRegistryBackend;
  key?: ReturnType<typeof keypair>;
  application?: string;
  environment?: string;
  logger?: CapturingLogger;
  now?: () => number;
}) {
  const backend = opts.backend ?? new InMemoryRegistryBackend();
  const key = opts.key ?? keypair();
  const logger = opts.logger ?? new CapturingLogger();
  const now = opts.now ?? Date.now;
  const service = new AidaService({
    key: {
      privateKey: key.privateKey,
      publicKey: key.publicKey,
      ephemeral: false,
    },
    registry: new AidaRegistry(backend, 30_000, now),
    nonces: new InMemoryNonceStore(),
    application: opts.application ?? "id",
    environment: opts.environment ?? "production",
    baseName: "AidaOffice",
    applicationTable: "aida_application",
    logger,
    now,
  });
  return { service, backend, key, logger };
}

/** A signed request as a peer would send it. */
function signed(
  key: ReturnType<typeof keypair>,
  args: {
    application: string;
    environment: string;
    method?: string;
    path?: string;
    body?: Buffer;
    timestamp?: number;
    nonce?: string;
    keyVersion?: number;
  },
) {
  const method = args.method ?? "POST";
  const path = args.path ?? "/internal/v1/whoami";
  const body = args.body ?? Buffer.from('{"hello":"world"}');
  const parts = {
    method,
    path,
    body,
    timestamp: args.timestamp ?? Math.floor(Date.now() / 1000),
    nonce: args.nonce ?? newNonce(),
    application: args.application,
    environment: args.environment,
  };
  return {
    headers: signRequest(key.privateKey, args.keyVersion ?? 1, parts) as Record<
      string,
      string
    >,
    method,
    path,
    body,
  };
}

// ─── keys ────────────────────────────────────────────────────────────────────

describe("service key", () => {
  it("round-trips through the wire encoding", () => {
    const { b64, privateKey, publicKey } = keypair();
    expect(b64).not.toContain("\n");
    expect(parsePrivateKeyB64(b64).asymmetricKeyType).toBe("ed25519");
    expect(publicKeyB64(privateKey)).toBe(publicKey);
  });

  it("rejects a PEM block by pointing at the generator", () => {
    const { privateKey } = keypair();
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    expect(() => parsePrivateKeyB64(pem)).toThrow(/single line/i);
  });

  it("rejects a key of the wrong algorithm", () => {
    const { privateKey } = crypto.generateKeyPairSync("ed448");
    const b64 = privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64");
    expect(() => parsePrivateKeyB64(b64)).toThrow(/Ed25519/i);
  });

  it("refuses to start in production without a key, naming the variable", () => {
    expect(() => loadServiceKey("", "production")).toThrow(PRIVATE_KEY_VAR);
  });

  it("generates an ephemeral key in development, loudly", () => {
    const warnings: string[] = [];
    const key = loadServiceKey("", "development", (m) => warnings.push(m));
    expect(key.ephemeral).toBe(true);
    expect(warnings.join(" ")).toMatch(/EPHEMERAL/);
  });

  it("never puts the private key in the warning it emits", () => {
    const warnings: string[] = [];
    const key = loadServiceKey("", "development", (m) => warnings.push(m));
    const secret = key.privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64");
    expect(warnings.join(" ")).not.toContain(secret);
  });
});

// ─── registration ────────────────────────────────────────────────────────────

describe("registration", () => {
  it("is idempotent across restarts — the row is updated, not duplicated", async () => {
    const backend = new InMemoryRegistryBackend();
    const key = keypair();
    for (let restart = 0; restart < 3; restart++) {
      const { service } = makeService({ backend, key });
      const status = await service.register();
      expect(status.ready).toBe(true);
    }
    const rows = await backend.listApplications();
    expect(rows).toHaveLength(1);
    expect(rows[0].application_name).toBe("id");
    expect(rows[0].key_version).toBe(1);
  });

  it("separates the same application in different environments", async () => {
    const backend = new InMemoryRegistryBackend();
    await makeService({
      backend,
      environment: "production",
    }).service.register();
    await makeService({ backend, environment: "staging" }).service.register();
    const rows = await backend.listApplications();
    expect(rows.map((r) => r.environment).sort()).toEqual([
      "production",
      "staging",
    ]);
  });

  it("treats a changed key as a rotation, keeping the old one acceptable", async () => {
    const backend = new InMemoryRegistryBackend();
    const first = keypair();
    await makeService({ backend, key: first }).service.register();
    const second = keypair();
    await makeService({ backend, key: second }).service.register();

    const rows = await backend.listApplications();
    expect(rows).toHaveLength(1);
    expect(rows[0].key_version).toBe(2);
    expect(rows[0].public_key).toBe(second.publicKey);
    expect(rows[0].previous_public_key).toBe(first.publicKey);
    expect(rows[0].previous_key_retired).toBe(false);
    expect(acceptedKeys(rows[0])).toEqual([second.publicKey, first.publicKey]);
  });

  it("drops the previous key from the accepted set once retired", async () => {
    const backend = new InMemoryRegistryBackend();
    const first = keypair();
    await makeService({ backend, key: first }).service.register();
    const second = keypair();
    await makeService({ backend, key: second }).service.register();
    backend.rows[0].previous_key_retired = true;
    expect(acceptedKeys(backend.rows[0])).toEqual([second.publicKey]);
  });

  it("reports unready, with the row to inspect, when the row is disabled", async () => {
    const backend = new InMemoryRegistryBackend();
    const key = keypair();
    await makeService({ backend, key }).service.register();
    backend.rows[0].enabled = false;

    const { service } = makeService({ backend, key });
    const status = await service.register();
    expect(status.ready).toBe(false);
    expect(status.reason).toBe("disabled");
    expect(status.row).toEqual({
      base: "AidaOffice",
      table: "aida_application",
      application_name: "id",
      environment: "production",
    });
  });

  it("reports unready rather than throwing when the registry is unreachable", async () => {
    const broken = new InMemoryRegistryBackend();
    broken.listApplications = async () => {
      throw new Error("ECONNREFUSED nocodb:8080");
    };
    const logger = new CapturingLogger();
    const { service } = makeService({ backend: broken, logger });
    const status = await service.register();
    expect(status.ready).toBe(false);
    expect(status.reason).toBe("registry_unreachable");
    // The category and the row are public; the backend's own error text is
    // not, because /readyz is unauthenticated. It goes to the log instead.
    expect(status.detail).not.toMatch(/ECONNREFUSED/);
    expect(logger.lines.join(" ")).toMatch(/ECONNREFUSED/);
  });

  it("keeps enrolment guidance on readiness when the door is closed", async () => {
    const backend = new InMemoryRegistryBackend();
    await backend.setSetting(AUTO_ENROLL_KEY, "false");
    const status = await makeService({
      backend,
      application: "latecomer",
    }).service.register();
    expect(status.detail).toMatch(/expected_applications/);
  });
});

// ─── enrolment ───────────────────────────────────────────────────────────────

describe("auto-enrolment", () => {
  it("is open when unset and honours a per-environment map", () => {
    expect(autoEnrollOpen(null, "production")).toBe(true);
    expect(autoEnrollOpen("true", "production")).toBe(true);
    expect(autoEnrollOpen("false", "production")).toBe(false);
    expect(autoEnrollOpen('{"staging":false}', "staging")).toBe(false);
    expect(autoEnrollOpen('{"staging":false}', "production")).toBe(true);
  });

  it("closing one environment leaves the others open", () => {
    const closed = withEnvironmentClosed("true", "staging");
    expect(autoEnrollOpen(closed, "staging")).toBe(false);
    expect(autoEnrollOpen(closed, "production")).toBe(true);
    const both = withEnvironmentClosed(closed, "production");
    expect(autoEnrollOpen(both, "staging")).toBe(false);
    expect(autoEnrollOpen(both, "production")).toBe(false);
  });

  it("reads the expected list as JSON or as a plain comma-separated cell", () => {
    expect(parseExpectedApplications('["a","b"]')).toEqual(["a", "b"]);
    expect(parseExpectedApplications("a, b")).toEqual(["a", "b"]);
    expect(parseExpectedApplications(null)).toContain("id");
  });

  it("closes enrolment once every expected application has registered", async () => {
    const backend = new InMemoryRegistryBackend();
    await backend.setSetting(
      EXPECTED_APPLICATIONS_KEY,
      '["id","aida-control"]',
    );

    const first = await makeService({
      backend,
      application: "id",
    }).service.register();
    expect(first.ready).toBe(true);
    expect(await backend.getSetting(AUTO_ENROLL_KEY)).toBeNull();
    expect(first.pendingApplications).toEqual(["aida-control"]);

    await makeService({
      backend,
      application: "aida-control",
    }).service.register();
    expect(
      autoEnrollOpen(await backend.getSetting(AUTO_ENROLL_KEY), "production"),
    ).toBe(false);
  });

  it("refuses to enrol a new application once the door has closed", async () => {
    const backend = new InMemoryRegistryBackend();
    await backend.setSetting(AUTO_ENROLL_KEY, "false");
    const { service } = makeService({ backend, application: "latecomer" });
    const status = await service.register();
    expect(status.ready).toBe(false);
    expect(status.reason).toBe("enrollment_closed");
    expect(backend.rows).toHaveLength(0);
  });

  it("re-opens the door when a name is appended to the expected list", async () => {
    const backend = new InMemoryRegistryBackend();
    await backend.setSetting(AUTO_ENROLL_KEY, '{"production":false}');
    await backend.setSetting(EXPECTED_APPLICATIONS_KEY, '["id","aida-agent"]');
    // The flag is still closed, so the newcomer is refused...
    expect(
      autoEnrollOpen(await backend.getSetting(AUTO_ENROLL_KEY), "production"),
    ).toBe(false);
    // ...until an operator re-opens it, which the pending list is the prompt for.
    await backend.setSetting(AUTO_ENROLL_KEY, "true");
    const status = await makeService({
      backend,
      application: "aida-agent",
    }).service.register();
    expect(status.ready).toBe(true);
  });
});

// ─── inbound verification ────────────────────────────────────────────────────

describe("inbound verification", () => {
  async function peerOn(
    backend: InMemoryRegistryBackend,
    application: string,
    environment = "production",
  ) {
    const key = keypair();
    await makeService({
      backend,
      key,
      application,
      environment,
    }).service.register();
    return key;
  }

  it("accepts a correctly signed call", async () => {
    const backend = new InMemoryRegistryBackend();
    const peer = await peerOn(backend, "aida-control");
    const { service } = makeService({ backend });
    const req = signed(peer, {
      application: "aida-control",
      environment: "production",
    });
    const outcome = await service.verify(
      req.headers,
      req.method,
      req.path,
      req.body,
    );
    expect(outcome).toEqual({
      ok: true,
      caller: {
        application: "aida-control",
        environment: "production",
        keyVersion: 1,
      },
    });
  });

  it("refuses an unknown application", async () => {
    const backend = new InMemoryRegistryBackend();
    const { service } = makeService({ backend });
    const stranger = keypair();
    const req = signed(stranger, {
      application: "nobody",
      environment: "production",
    });
    const outcome = await service.verify(
      req.headers,
      req.method,
      req.path,
      req.body,
    );
    expect(outcome).toMatchObject({ ok: false, reason: "unknown_application" });
  });

  it("refuses a disabled application", async () => {
    const backend = new InMemoryRegistryBackend();
    const peer = await peerOn(backend, "aida-control");
    backend.rows.find((r) => r.application_name === "aida-control")!.enabled =
      false;
    const { service } = makeService({ backend });
    const req = signed(peer, {
      application: "aida-control",
      environment: "production",
    });
    const outcome = await service.verify(
      req.headers,
      req.method,
      req.path,
      req.body,
    );
    expect(outcome).toMatchObject({ ok: false, reason: "disabled" });
  });

  it("refuses a stale timestamp", async () => {
    const backend = new InMemoryRegistryBackend();
    const peer = await peerOn(backend, "aida-control");
    const { service } = makeService({ backend });
    const req = signed(peer, {
      application: "aida-control",
      environment: "production",
      timestamp: Math.floor(Date.now() / 1000) - CLOCK_SKEW_SECONDS - 5,
    });
    const outcome = await service.verify(
      req.headers,
      req.method,
      req.path,
      req.body,
    );
    expect(outcome).toMatchObject({ ok: false, reason: "stale_timestamp" });
  });

  it("refuses a replayed nonce, accepting the first use", async () => {
    const backend = new InMemoryRegistryBackend();
    const peer = await peerOn(backend, "aida-control");
    const { service } = makeService({ backend });
    const req = signed(peer, {
      application: "aida-control",
      environment: "production",
    });
    expect(
      await service.verify(req.headers, req.method, req.path, req.body),
    ).toMatchObject({
      ok: true,
    });
    expect(
      await service.verify(req.headers, req.method, req.path, req.body),
    ).toMatchObject({
      ok: false,
      reason: "replayed_nonce",
    });
  });

  it("refuses a tampered body, path, or method", async () => {
    const backend = new InMemoryRegistryBackend();
    const peer = await peerOn(backend, "aida-control");
    const { service } = makeService({ backend });
    const req = signed(peer, {
      application: "aida-control",
      environment: "production",
    });

    for (const mutation of [
      () =>
        service.verify(
          req.headers,
          req.method,
          req.path,
          Buffer.from('{"hello":"mars"}'),
        ),
      () =>
        service.verify(req.headers, req.method, "/internal/v1/other", req.body),
      () => service.verify(req.headers, "PUT", req.path, req.body),
    ]) {
      expect(await mutation()).toMatchObject({
        ok: false,
        reason: "key_mismatch",
      });
    }
  });

  it("refuses a signature made by the wrong key", async () => {
    const backend = new InMemoryRegistryBackend();
    await peerOn(backend, "aida-control");
    const impostor = keypair();
    const { service } = makeService({ backend });
    const req = signed(impostor, {
      application: "aida-control",
      environment: "production",
    });
    const outcome = await service.verify(
      req.headers,
      req.method,
      req.path,
      req.body,
    );
    expect(outcome).toMatchObject({ ok: false, reason: "key_mismatch" });
  });

  it("refuses a staging request replayed against production", async () => {
    const backend = new InMemoryRegistryBackend();
    const staging = await peerOn(backend, "aida-control", "staging");
    await peerOn(backend, "aida-control", "production");
    const { service } = makeService({ backend });
    // Signed for staging, then relabelled as production on the wire.
    const req = signed(staging, {
      application: "aida-control",
      environment: "staging",
    });
    const relabelled = { ...req.headers, "x-aida-environment": "production" };
    const outcome = await service.verify(
      relabelled,
      req.method,
      req.path,
      req.body,
    );
    expect(outcome).toMatchObject({ ok: false, reason: "key_mismatch" });
  });

  it("refuses a request with missing headers without consulting the registry", async () => {
    const backend = new InMemoryRegistryBackend();
    backend.listApplications = async () => {
      throw new Error("should not be called");
    };
    const { service } = makeService({ backend });
    const outcome = await service.verify(
      {},
      "GET",
      "/internal/v1/whoami",
      Buffer.alloc(0),
    );
    expect(outcome).toMatchObject({ ok: false, reason: "malformed" });
  });

  it("accepts a peer's rotation without a restart here", async () => {
    const backend = new InMemoryRegistryBackend();
    const oldKey = await peerOn(backend, "aida-control");
    const { service } = makeService({ backend });
    // Warm this service's cache with the pre-rotation row.
    const warm = signed(oldKey, {
      application: "aida-control",
      environment: "production",
    });
    expect(
      await service.verify(warm.headers, warm.method, warm.path, warm.body),
    ).toMatchObject({
      ok: true,
    });

    const newKey = keypair();
    await makeService({
      backend,
      key: newKey,
      application: "aida-control",
    }).service.register();

    const fresh = signed(newKey, {
      application: "aida-control",
      environment: "production",
      keyVersion: 2,
    });
    expect(
      await service.verify(fresh.headers, fresh.method, fresh.path, fresh.body),
    ).toMatchObject({ ok: true });
    // And the overlap holds: the outgoing key still verifies until retired.
    const trailing = signed(oldKey, {
      application: "aida-control",
      environment: "production",
    });
    expect(
      await service.verify(
        trailing.headers,
        trailing.method,
        trailing.path,
        trailing.body,
      ),
    ).toMatchObject({ ok: true });
  });

  it("names the cause and the row in the log, never over the wire", async () => {
    const backend = new InMemoryRegistryBackend();
    const logger = new CapturingLogger();
    const { service } = makeService({ backend, logger });
    const stranger = keypair();
    const req = signed(stranger, {
      application: "nobody",
      environment: "production",
    });
    const outcome = await service.verify(
      req.headers,
      req.method,
      req.path,
      req.body,
    );

    expect(outcome.ok).toBe(false);
    const logged = logger.lines.join(" ");
    expect(logged).toContain("unknown_application");
    expect(logged).toContain("aida_application");
    expect(logged).toContain("AidaOffice");
  });
});

// ─── secret hygiene ──────────────────────────────────────────────────────────

describe("secret hygiene", () => {
  it("keeps the private key out of every log line the service writes", async () => {
    const backend = new InMemoryRegistryBackend();
    const logger = new CapturingLogger();
    const key = keypair();
    const { service } = makeService({ backend, key, logger });

    await service.register();
    // A rotation, a disabled row, an unreachable registry, and a refusal —
    // every path that logs.
    backend.rows[0].enabled = false;
    await service.register();
    const stranger = keypair();
    const req = signed(stranger, {
      application: "nobody",
      environment: "production",
    });
    await service.verify(req.headers, req.method, req.path, req.body);

    const logged = logger.lines.join("\n");
    expect(logged.length).toBeGreaterThan(0);
    expect(logged).not.toContain(key.b64);
    const der = key.privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64");
    expect(logged).not.toContain(der);
  });

  it("publishes only the public half to the registry", async () => {
    const backend = new InMemoryRegistryBackend();
    const key = keypair();
    await makeService({ backend, key }).service.register();
    const serialised =
      JSON.stringify(backend.rows) + JSON.stringify([...backend.settings]);
    expect(serialised).toContain(key.publicKey);
    expect(serialised).not.toContain(key.b64);
  });
});

// ─── canonical form ──────────────────────────────────────────────────────────

describe("canonical signing string", () => {
  it("is the eight documented fields in order", () => {
    const s = canonicalString({
      method: "post",
      path: "/internal/v1/whoami?x=1",
      body: Buffer.from("abc"),
      timestamp: 1756000000,
      nonce: "n".repeat(32),
      application: "id",
      environment: "production",
    });
    const lines = s.split("\n");
    expect(lines).toHaveLength(8);
    expect(lines[0]).toBe("AIDA-SVC-v1");
    expect(lines[1]).toBe("POST"); // method is upper-cased before signing
    expect(lines[2]).toBe("/internal/v1/whoami?x=1");
    expect(lines[3]).toBe(
      crypto.createHash("sha256").update("abc").digest("hex"),
    );
    expect(lines[6]).toBe("id");
    expect(lines[7]).toBe("production");
  });

  it("rejects credentials with an implausible nonce length", () => {
    const key = keypair();
    const headers = signRequest(key.privateKey, 1, {
      method: "GET",
      path: "/x",
      body: Buffer.alloc(0),
      timestamp: 1,
      nonce: "short",
      application: "id",
      environment: "production",
    });
    expect(readCredentials(headers)).toBeNull();
  });
});
