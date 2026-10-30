import { readFile } from "node:fs/promises";
import { X509Certificate } from "node:crypto";
import type { ConnectionOptions, PeerCertificate } from "node:tls";
import { ConfigError } from "./config.js";

export const CERT_CHANGED_MESSAGE =
  "Bridge certificate changed. Re-export it from Bridge and run: proton-mcp pin-cert <file>";

/** Error returned from checkServerIdentity when the presented cert is not the pinned one. */
export class CertPinError extends Error {
  code = "BRIDGE_CERT_CHANGED";
  constructor() {
    super(CERT_CHANGED_MESSAGE);
    this.name = "CertPinError";
  }
}

/**
 * TLS options that trust only the pinned Bridge certificate: it is the sole CA, chain
 * verification stays on, and the peer's SHA-256 fingerprint must equal the pinned one.
 */
export async function tlsOptions(pemPath: string): Promise<ConnectionOptions> {
  let pem: string;
  try {
    pem = await readFile(pemPath, "utf8");
  } catch {
    throw new ConfigError(`Pinned Bridge certificate not found at ${pemPath}. Export it from Bridge and run: proton-mcp pin-cert <file>`);
  }
  let pinned: string;
  try {
    pinned = new X509Certificate(pem).fingerprint256;
  } catch {
    throw new ConfigError(`Pinned Bridge certificate at ${pemPath} is not a valid PEM certificate.`);
  }
  return {
    ca: pem,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    checkServerIdentity: (_host: string, cert: PeerCertificate): Error | undefined =>
      typeof cert?.fingerprint256 === "string" && cert.fingerprint256 === pinned ? undefined : new CertPinError(),
  };
}

/**
 * Runtime guard: refuse TLS options that are not pinned (no CA, verification off, or no identity
 * check), and return a copy whose identity check also reports pin failures to `onPinFailure`.
 */
export function guardPinnedTls(tls: ConnectionOptions, onPinFailure: () => void): ConnectionOptions {
  const check = tls.checkServerIdentity;
  if (tls.rejectUnauthorized !== true || typeof check !== "function" || !tls.ca) {
    throw new ConfigError("Refusing unpinned TLS options (ca, rejectUnauthorized and checkServerIdentity are required).");
  }
  return {
    ...tls,
    checkServerIdentity: (host: string, cert: PeerCertificate) => {
      const err = check(host, cert);
      if (err) onPinFailure();
      return err;
    },
  };
}
