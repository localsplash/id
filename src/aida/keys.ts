import crypto from "crypto";

/**
 * The service key: an Ed25519 keypair identifying this application to its
 * peers.
 *
 * The private half arrives in `AIDA_APP_PRIVATE_KEY` as base64 of the PKCS#8
 * DER — one line, no PEM newlines. This service never generates or persists a
 * private key outside development: a key file does not survive a container
 * rebuild without a volume, and a volume that has to be right in every
 * environment forever fails silently when it is not. On the authentication
 * path that failure presents as intermittent sign-in trouble that looks like
 * a flake. Reading it from the environment turns it into a startup error.
 *
 * The public half is derived here and published to `aida_application`. It is
 * the only half the registry ever sees.
 *
 * This key has nothing to do with user sessions. A session is an opaque
 * random token in `id_tbl_Session`, checked by row lookup; no session value
 * is derived from, signed by, or verified against this keypair. Changing
 * AIDA_APP_PRIVATE_KEY therefore signs nobody out — see docs/service-auth.md.
 */

export const PRIVATE_KEY_VAR = "AIDA_APP_PRIVATE_KEY";

export interface ServiceKey {
  /** Signs outbound requests. Never logged, never sent anywhere. */
  privateKey: crypto.KeyObject;
  /** base64 SPKI DER — the form published to `aida_application.public_key`. */
  publicKey: string;
  /** True when generated on the spot because none was supplied (dev only). */
  ephemeral: boolean;
}

/** A fresh private key in the wire format, for the keygen command. */
export function generatePrivateKeyB64(): string {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  return privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
}

/** base64 SPKI DER of the public half. */
export function publicKeyB64(privateKey: crypto.KeyObject): string {
  return crypto
    .createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })
    .toString("base64");
}

/** Inverse of {@link publicKeyB64}, for verifying a peer's signature. */
export function publicKeyFromB64(b64: string): crypto.KeyObject {
  return crypto.createPublicKey({
    key: Buffer.from(b64, "base64"),
    format: "der",
    type: "spki",
  });
}

export function parsePrivateKeyB64(value: string): crypto.KeyObject {
  const trimmed = value.trim();
  if (trimmed.includes("-----BEGIN")) {
    throw new Error(
      `${PRIVATE_KEY_VAR} looks like a PEM block. It must be base64 of the PKCS#8 DER on a ` +
        `single line, with no header, footer, or newlines. Run \`npm run keygen\` to produce one.`,
    );
  }
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey({
      key: Buffer.from(trimmed, "base64"),
      format: "der",
      type: "pkcs8",
    });
  } catch (err) {
    throw new Error(
      `${PRIVATE_KEY_VAR} could not be parsed as base64 PKCS#8 DER: ${(err as Error).message}. ` +
        `Run \`npm run keygen\` to produce a valid value.`,
    );
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(
      `${PRIVATE_KEY_VAR} is an ${key.asymmetricKeyType ?? "unknown"} key; Aida service ` +
        `authentication uses Ed25519. Run \`npm run keygen\`.`,
    );
  }
  return key;
}

/**
 * Resolve the service key at startup.
 *
 * Absent in production is a startup failure naming the variable — never an
 * improvised key on the auth path. Absent in development generates an
 * ephemeral one and says so loudly, because that key changes on every restart
 * and peers holding the previous one will refuse this service's calls.
 */
export function loadServiceKey(
  raw: string | undefined,
  nodeEnv: string,
  warn: (msg: string) => void = console.warn,
): ServiceKey {
  const value = (raw ?? "").trim();
  if (value) {
    const privateKey = parsePrivateKeyB64(value);
    return {
      privateKey,
      publicKey: publicKeyB64(privateKey),
      ephemeral: false,
    };
  }
  if (nodeEnv === "production") {
    throw new Error(
      `${PRIVATE_KEY_VAR} is not set. It is required in production: this service must ` +
        `authenticate to other Aida services and will not start with an improvised key. ` +
        `Generate one with \`npm run keygen\` and put it in the environment.`,
    );
  }
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  warn(
    `[aida] ${PRIVATE_KEY_VAR} is not set — generated an EPHEMERAL service key because ` +
      `NODE_ENV is "${nodeEnv}". This key changes on every restart, so peers that cached the ` +
      `previous one will reject this service until they re-read the registry. Never do this in ` +
      `production; run \`npm run keygen\` and set the variable.`,
  );
  return { privateKey, publicKey: publicKeyB64(privateKey), ephemeral: true };
}
