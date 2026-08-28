import crypto from "crypto";
import { publicKeyFromB64 } from "./keys";

/**
 * The wire format for Aida service-to-service authentication.
 *
 * The design (AidaInfrastructureSetupInstructions#10) fixes the algorithm
 * (Ed25519), the key encoding, and what the signature has to cover — method,
 * path, body hash, timestamp and nonce. It does not name the headers or fix
 * the byte order they are signed in, and no peer has implemented its side
 * yet, so this module defines both. `docs/service-auth.md` is the written
 * contract; a peer that follows it will interoperate with this service.
 *
 * The canonical string is eight newline-separated fields:
 *
 *     AIDA-SVC-v1
 *     POST
 *     /internal/v1/whoami?x=1
 *     <lowercase hex sha256 of the raw request body>
 *     <unix seconds>
 *     <nonce>
 *     <application_name>
 *     <environment>
 *
 * Every field is also sent as a header, so the verifier rebuilds the string
 * from the request rather than trusting a caller-supplied blob. The leading
 * version tag keeps a v2 signature from ever verifying as a v1 one. The
 * trailing application and environment are inside the signature so a request
 * captured in staging cannot be replayed against production, where the same
 * application name is a different row with a different key.
 */

export const PROTOCOL_VERSION = "AIDA-SVC-v1";

export const HEADERS = {
  application: "x-aida-application",
  environment: "x-aida-environment",
  keyVersion: "x-aida-key-version",
  timestamp: "x-aida-timestamp",
  nonce: "x-aida-nonce",
  signature: "x-aida-signature",
} as const;

/** Requests are refused outside this window either side of the callee's clock. */
export const CLOCK_SKEW_SECONDS = 300;

/**
 * Rejection categories. These are distinct causes with distinct fixes, so
 * they are distinguished in logs and on readiness — and deliberately not over
 * the wire, where naming the failed check hands a caller a probing oracle.
 */
export type RejectionReason =
  | "malformed"
  | "unknown_application"
  | "disabled"
  | "key_mismatch"
  | "stale_timestamp"
  | "replayed_nonce";

export interface SignatureParts {
  method: string;
  /** Path with query string, exactly as it appears on the request line. */
  path: string;
  body: Buffer;
  timestamp: number;
  nonce: string;
  application: string;
  environment: string;
}

export function bodyHash(body: Buffer): string {
  return crypto.createHash("sha256").update(body).digest("hex");
}

export function canonicalString(parts: SignatureParts): string {
  return [
    PROTOCOL_VERSION,
    parts.method.toUpperCase(),
    parts.path,
    bodyHash(parts.body),
    String(parts.timestamp),
    parts.nonce,
    parts.application,
    parts.environment,
  ].join("\n");
}

export function newNonce(): string {
  return crypto.randomBytes(16).toString("hex");
}

/** The headers to attach to an outbound request. */
export function signRequest(
  privateKey: crypto.KeyObject,
  keyVersion: number,
  parts: SignatureParts,
): Record<string, string> {
  const signature = crypto
    .sign(null, Buffer.from(canonicalString(parts), "utf8"), privateKey)
    .toString("base64");
  return {
    [HEADERS.application]: parts.application,
    [HEADERS.environment]: parts.environment,
    [HEADERS.keyVersion]: String(keyVersion),
    [HEADERS.timestamp]: String(parts.timestamp),
    [HEADERS.nonce]: parts.nonce,
    [HEADERS.signature]: signature,
  };
}

export interface PresentedCredentials {
  application: string;
  environment: string;
  keyVersion: number | null;
  timestamp: number;
  nonce: string;
  signature: string;
}

/**
 * Pull the six headers off a request. Returns null when any is missing or
 * malformed — nothing here consults the registry, so a garbage request costs
 * no round trip.
 */
export function readCredentials(
  headers: Record<string, string | string[] | undefined>,
): PresentedCredentials | null {
  const one = (name: string): string => {
    const v = headers[name];
    return (Array.isArray(v) ? v[0] : v) ?? "";
  };
  const application = one(HEADERS.application).trim();
  const environment = one(HEADERS.environment).trim();
  const rawTimestamp = one(HEADERS.timestamp).trim();
  const nonce = one(HEADERS.nonce).trim();
  const signature = one(HEADERS.signature).trim();
  const rawVersion = one(HEADERS.keyVersion).trim();
  if (!application || !environment || !nonce || !signature || !rawTimestamp)
    return null;
  // An absent timestamp header must read as malformed, not as a stale one:
  // Number('') is 0, which is a perfectly valid integer and would send the
  // operator looking for clock skew that is not there.
  const timestamp = Number(rawTimestamp);
  if (!Number.isInteger(timestamp)) return null;
  // Bounded so a nonce cannot be used to grow the replay table without limit.
  if (nonce.length < 16 || nonce.length > 128) return null;
  const keyVersion = rawVersion === "" ? null : Number(rawVersion);
  if (keyVersion !== null && !Number.isInteger(keyVersion)) return null;
  return { application, environment, keyVersion, timestamp, nonce, signature };
}

export function timestampIsFresh(timestamp: number, now = Date.now()): boolean {
  return Math.abs(Math.floor(now / 1000) - timestamp) <= CLOCK_SKEW_SECONDS;
}

/**
 * True when the signature verifies against any one of the caller's accepted
 * public keys. Trying every unretired key — rather than only the one named by
 * the key-version header — is what lets a peer rotate without a restart here:
 * during the overlap both its old and new keys are on the row, and a caller
 * that has not yet picked up the new one still verifies.
 */
export function verifySignature(
  acceptedPublicKeys: string[],
  presented: PresentedCredentials,
  method: string,
  path: string,
  body: Buffer,
): boolean {
  const message = Buffer.from(
    canonicalString({
      method,
      path,
      body,
      timestamp: presented.timestamp,
      nonce: presented.nonce,
      application: presented.application,
      environment: presented.environment,
    }),
    "utf8",
  );
  let signature: Buffer;
  try {
    signature = Buffer.from(presented.signature, "base64");
  } catch {
    return false;
  }
  if (signature.length !== 64) return false;
  for (const b64 of acceptedPublicKeys) {
    try {
      if (crypto.verify(null, message, publicKeyFromB64(b64), signature))
        return true;
    } catch {
      // A malformed key on the row must not stop the others from being tried.
    }
  }
  return false;
}
