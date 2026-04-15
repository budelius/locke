/**
 * OS keystore access with biometric gating.
 *
 * Provides platform-native credential storage via the `keytar` library:
 * - Windows: Credential Manager (with optional Windows Hello gating)
 * - macOS: Keychain (with optional Touch ID gating)
 * - Linux: Secret Service (D-Bus) — no biometric support
 *
 * Biometric gating is controlled by LOCKE_USE_BIOMETRIC environment variable.
 */

import keytar from "keytar";
import { KeystoreUnavailableError } from "./errors.js";

const SERVICE_NAME = "locke";
const SERVICE_NAME_BIOMETRIC = "locke-bio";

function biometricEnabled(): boolean {
  const flag = (process.env.LOCKE_USE_BIOMETRIC ?? "true").toLowerCase().trim();
  return !["false", "0", "no"].includes(flag);
}

function effectiveService(): string {
  if (biometricEnabled() && process.platform !== "linux") {
    return SERVICE_NAME_BIOMETRIC;
  }
  return SERVICE_NAME;
}

export async function getCredential(name: string): Promise<string | null> {
  const service = effectiveService();
  try {
    let value = await keytar.getPassword(service, name);
    // Fallback to non-biometric service
    if (value === null && service !== SERVICE_NAME) {
      value = await keytar.getPassword(SERVICE_NAME, name);
    }
    return value;
  } catch (err) {
    throw new KeystoreUnavailableError(process.platform, "keytar");
  }
}

export async function setCredential(
  name: string,
  value: string,
): Promise<void> {
  const service = effectiveService();
  try {
    await keytar.setPassword(service, name, value);
  } catch (err) {
    throw new KeystoreUnavailableError(process.platform, "keytar");
  }
}

export async function deleteCredential(name: string): Promise<void> {
  const service = effectiveService();
  try {
    await keytar.deletePassword(service, name);
    if (service !== SERVICE_NAME) {
      await keytar.deletePassword(SERVICE_NAME, name).catch(() => {});
    }
  } catch (err) {
    throw new KeystoreUnavailableError(process.platform, "keytar");
  }
}
