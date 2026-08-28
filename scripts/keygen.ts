/**
 * Print a fresh AIDA_APP_PRIVATE_KEY.
 *
 * Exists so nobody has to improvise an `openssl` incantation and so three
 * services do not each arrive at a different encoding. The output is base64 of
 * the PKCS#8 DER on one line, which is what the environment variable takes.
 *
 *   npm run keygen
 */
import {
  generatePrivateKeyB64,
  parsePrivateKeyB64,
  publicKeyB64,
} from "../src/aida/keys";

const key = generatePrivateKeyB64();
const pub = publicKeyB64(parsePrivateKeyB64(key));

process.stdout.write(
  [
    "# Ed25519 service key for Aida service-to-service authentication.",
    "# Put the line below in this deployment’s environment. Treat it as a secret:",
    "# it is this service’s identity to its peers. Do not commit it.",
    `AIDA_APP_PRIVATE_KEY=${key}`,
    "",
    "# The matching public key, for reference. This service publishes it to",
    "# aida_application on startup; you do not need to copy it anywhere.",
    `# public_key=${pub}`,
    "",
  ].join("\n"),
);
