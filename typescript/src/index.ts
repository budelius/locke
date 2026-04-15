/**
 * Locke — Unified credentials framework.
 */

import { readFile } from "node:fs/promises";
import { decryptConfig, encryptConfig } from "./crypto.js";
import type { EncryptedConfig } from "./crypto.js";
import { flattenConfig } from "./flatten.js";
import { resolveCredential } from "./pipeline.js";
import { getVaultSecret } from "./vault.js";

export {
  decryptConfig,
  encryptConfig,
  flattenConfig,
  getVaultSecret,
  resolveCredential,
};

export async function loadConfig(
  configPath: string,
  keyName = "LOCKE_ENCRYPTION_KEY",
): Promise<Record<string, string>> {
  const raw = await readFile(configPath, "utf8");
  const encrypted: EncryptedConfig = JSON.parse(raw);

  const credential = await resolveCredential(keyName);
  const plaintext = decryptConfig(encrypted, credential.value);
  return flattenConfig(plaintext as Record<string, unknown>);
}
