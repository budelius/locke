/**
 * AES-256-GCM encryption/decryption with PBKDF2-SHA256 KDF.
 *
 * Handles hex/base64 key encoding auto-detection for backward compatibility.
 */

import {
  createDecipheriv,
  createCipheriv,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import {
  DecryptionError,
  InvalidConfigError,
  InvalidKeyError,
} from "./errors.js";

const REQUIRED_KEY_LENGTH = 32;
const KDF_ITERATIONS = 100_000;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const CURRENT_VERSION = 2;

const HEX_64_RE = /^[0-9a-fA-F]{64}$/;
const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Auto-detect hex vs base64 encoding for binary payload fields.
 *
 * Older Locke encrypted configs used hex encoding; current configs use
 * base64. We accept both for backward compatibility.
 */
function decodeField(value: string): Buffer {
  if (HEX_RE.test(value) && value.length % 2 === 0) {
    return Buffer.from(value, "hex");
  }
  return Buffer.from(value, "base64");
}

export function decodeKey(keyInput: string): Buffer {
  if (HEX_64_RE.test(keyInput)) {
    return Buffer.from(keyInput, "hex");
  }

  try {
    const buf = Buffer.from(keyInput, "base64");
    if (buf.length === REQUIRED_KEY_LENGTH) {
      return buf;
    }
  } catch {
    // fall through
  }

  throw new InvalidKeyError(REQUIRED_KEY_LENGTH, keyInput.length);
}

function deriveKey(
  passphrase: Buffer,
  salt: Buffer,
  iterations = KDF_ITERATIONS,
): Buffer {
  return pbkdf2Sync(passphrase, salt, iterations, REQUIRED_KEY_LENGTH, "sha256");
}

export interface EncryptedConfig {
  version: number;
  algorithm: string;
  kdf: string;
  kdfIterations: number;
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export function decryptConfig(
  encrypted: EncryptedConfig,
  key: string | Buffer,
): Record<string, unknown> {
  const requiredFields = [
    "algorithm",
    "kdf",
    "salt",
    "iv",
    "authTag",
    "ciphertext",
  ] as const;
  for (const field of requiredFields) {
    if (!(field in encrypted)) {
      throw new InvalidConfigError(`missing field '${field}'`);
    }
  }

  if (encrypted.version !== CURRENT_VERSION) {
    console.warn(
      `Encrypted config version ${encrypted.version} (expected ${CURRENT_VERSION}). Attempting best-effort decryption.`,
    );
  }

  if (encrypted.algorithm !== "aes-256-gcm") {
    throw new InvalidConfigError(
      `unsupported algorithm '${encrypted.algorithm}'`,
    );
  }

  if (encrypted.kdf !== "pbkdf2") {
    throw new InvalidConfigError(`unsupported KDF '${encrypted.kdf}'`);
  }

  const keyBytes =
    typeof key === "string" ? decodeKey(key) : key;
  if (keyBytes.length !== REQUIRED_KEY_LENGTH) {
    throw new InvalidKeyError(REQUIRED_KEY_LENGTH, keyBytes.length);
  }

  const salt = decodeField(encrypted.salt);
  const iv = decodeField(encrypted.iv);
  const authTag = decodeField(encrypted.authTag);
  const ciphertext = decodeField(encrypted.ciphertext);
  const iterations = encrypted.kdfIterations ?? KDF_ITERATIONS;

  const derivedKey = deriveKey(keyBytes, salt, iterations);

  try {
    const decipher = createDecipheriv("aes-256-gcm", derivedKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString("utf8"));
  } catch (err) {
    throw new DecryptionError(
      "<encrypted config>",
      "authentication tag verification failed",
    );
  }
}

export function encryptConfig(
  plaintext: Record<string, unknown>,
  key: string | Buffer,
): EncryptedConfig {
  const keyBytes =
    typeof key === "string" ? decodeKey(key) : key;
  if (keyBytes.length !== REQUIRED_KEY_LENGTH) {
    throw new InvalidKeyError(REQUIRED_KEY_LENGTH, keyBytes.length);
  }

  const salt = randomBytes(32);
  const iv = randomBytes(IV_LENGTH);
  const derivedKey = deriveKey(keyBytes, salt, KDF_ITERATIONS);

  const plaintextStr = JSON.stringify(plaintext, Object.keys(plaintext).sort());
  const cipher = createCipheriv("aes-256-gcm", derivedKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintextStr, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    version: CURRENT_VERSION,
    algorithm: "aes-256-gcm",
    kdf: "pbkdf2",
    kdfIterations: KDF_ITERATIONS,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
  };
}
