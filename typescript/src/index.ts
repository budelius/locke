/**
 * Locke — Unified credentials framework.
 */

import { readFile } from "node:fs/promises";
import { decryptConfig, encryptConfig } from "./crypto.js";
import type { EncryptedConfig } from "./crypto.js";
import {
  BiometricDeniedError,
  BiometricUnavailableError,
  CollisionError,
  CredentialNotFoundError,
  DecryptionError,
  InvalidConfigError,
  InvalidKeyError,
  KeystoreUnavailableError,
  LockeError,
  SecretNotFoundError,
  VaultAuthError,
} from "./errors.js";
import { flattenConfig } from "./flatten.js";
import { parseJsonc, stripJsonc } from "./jsonc.js";
import {
  biometricEnabled,
  deleteCredential,
  findLegacyCredentials,
  getCredential,
  invalidateBioSession,
  migrateCredential,
  resetBioCache,
  setCredential,
  SERVICE_NAME,
} from "./keystore.js";
import { resolveCredential } from "./pipeline.js";
import {
  getVaultSecret,
  getVaultSecretPair,
  isPlaceholder,
  PLACEHOLDER_VALUE,
  setVaultSecret,
  setVaultSecretPair,
  VaultClient,
} from "./vault.js";
import type { CredentialPair } from "./vault.js";

export {
  biometricEnabled,
  BiometricDeniedError,
  BiometricUnavailableError,
  CollisionError,
  CredentialNotFoundError,
  decryptConfig,
  DecryptionError,
  deleteCredential,
  encryptConfig,
  findLegacyCredentials,
  flattenConfig,
  getCredential,
  getVaultSecret,
  getVaultSecretPair,
  invalidateBioSession,
  InvalidConfigError,
  InvalidKeyError,
  isPlaceholder,
  KeystoreUnavailableError,
  LockeError,
  migrateCredential,
  parseJsonc,
  PLACEHOLDER_VALUE,
  resetBioCache,
  resolveCredential,
  SecretNotFoundError,
  SERVICE_NAME,
  setCredential,
  setVaultSecret,
  setVaultSecretPair,
  stripJsonc,
  VaultAuthError,
  VaultClient,
};

export type { CredentialPair };

export async function loadConfig(
  configPath: string,
  keyName = "LOCKE_ENCRYPTION_KEY",
): Promise<Record<string, string>> {
  const raw = await readFile(configPath, "utf8");
  const encrypted = parseJsonc(raw) as EncryptedConfig;

  const credential = await resolveCredential(keyName);
  const plaintext = decryptConfig(encrypted, credential.value);
  return flattenConfig(plaintext as Record<string, unknown>);
}
