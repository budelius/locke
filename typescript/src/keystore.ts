/**
 * OS keystore access with biometric gating.
 *
 * Provides platform-native credential storage via the `keytar` library:
 * - Windows: Credential Manager + Windows Hello (UserConsentVerifier)
 * - macOS: Keychain (Touch ID gating not yet implemented — passes through)
 * - Linux: Secret Service (D-Bus) — no biometric support
 *
 * Biometric gating is controlled by the `LOCKE_USE_BIOMETRIC` env var
 * (default `true`). When enabled on Windows in an interactive shell, every
 * credential read triggers a Windows Hello prompt (fingerprint / face / PIN)
 * via the WinRT `UserConsentVerifier` API. Node has no native WinRT bindings,
 * so the prompt is driven through a PowerShell subprocess. Verification is
 * cached for `LOCKE_BIO_CACHE_TTL` seconds (default 300) to avoid repeated
 * prompts within a session, and a persistent session file under
 * `%LOCALAPPDATA%\locke\` (Windows) or `~/.locke/` extends the cache across
 * process invocations (`LOCKE_BIO_SESSION_TTL`, default 7 days).
 *
 * Set `LOCKE_USE_BIOMETRIC=false` to bypass biometric prompts entirely.
 *
 * This mirrors the Python reference implementation in `python/locke/keystore.py`.
 */

import {
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, userInfo } from "node:os";
import { join } from "node:path";

import keytar from "keytar";
import {
  BiometricDeniedError,
  BiometricUnavailableError,
  KeystoreUnavailableError,
} from "./errors.js";

export const SERVICE_NAME = "locke";

// ---------------------------------------------------------------------------
// Biometric configuration
// ---------------------------------------------------------------------------

const BIO_CACHE_TTL_DEFAULT = 300; // seconds
const BIO_SESSION_TTL_DEFAULT = 604800; // 7 days in seconds
const BIO_SESSION_FILE = "bio_session.json";

let bioVerifiedAt: number | null = null; // seconds since epoch (Date.now()/1000)

/** Check whether biometric gating is enabled (LOCKE_USE_BIOMETRIC). */
export function biometricEnabled(): boolean {
  const flag = (process.env.LOCKE_USE_BIOMETRIC ?? "true").toLowerCase().trim();
  return !["false", "0", "no"].includes(flag);
}

function bioCacheTtl(): number {
  const raw = process.env.LOCKE_BIO_CACHE_TTL;
  if (raw === undefined) return BIO_CACHE_TTL_DEFAULT;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : BIO_CACHE_TTL_DEFAULT;
}

function bioSessionTtl(): number {
  const raw = process.env.LOCKE_BIO_SESSION_TTL;
  if (raw === undefined) return BIO_SESSION_TTL_DEFAULT;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : BIO_SESSION_TTL_DEFAULT;
}

function bioCacheValid(): boolean {
  if (bioVerifiedAt === null) return false;
  return Date.now() / 1000 - bioVerifiedAt < bioCacheTtl();
}

/** Invalidate the in-memory biometric verification cache (useful for testing). */
export function resetBioCache(): void {
  bioVerifiedAt = null;
}

// ---------------------------------------------------------------------------
// Persistent biometric session (survives across process invocations)
// ---------------------------------------------------------------------------

interface BioSession {
  verified_at: number;
  machine_id: string;
  username: string;
  hmac: string;
}

/** Directory for the persistent session file (created if missing). */
function getBioSessionDir(): string {
  let dir: string;
  if (process.platform === "win32") {
    const base = process.env.LOCALAPPDATA ?? "";
    dir = base ? join(base, "locke") : join(homedir(), ".locke");
  } else {
    dir = join(homedir(), ".locke");
  }
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Return a stable machine identifier.
 *
 * On Windows reads `MachineGuid` from the registry via a `reg query`
 * subprocess (Node has no native registry API). Returns `"unknown"` on other
 * platforms or on any failure.
 */
export function getMachineId(): string {
  if (process.platform !== "win32") return "unknown";
  try {
    const out = execFileSync(
      "reg",
      [
        "query",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
        "/v",
        "MachineGuid",
      ],
      { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] },
    );
    // Output line looks like: "    MachineGuid    REG_SZ    <guid>"
    const match = out.match(/MachineGuid\s+REG_SZ\s+(\S+)/);
    if (match) return match[1];
    return "unknown";
  } catch {
    return "unknown";
  }
}

/** Return the current OS username. */
export function getUsername(): string {
  try {
    return userInfo().username;
  } catch {
    return (
      process.env.USERNAME ?? process.env.USER ?? "unknown"
    );
  }
}

/**
 * Format a numeric timestamp to match Python's `str(float)` so the session
 * HMAC is byte-for-byte compatible with the Python reference implementation.
 *
 * Python always renders a float with a decimal point (e.g. `1700000000.0`),
 * whereas JS `String(1700000000)` drops it. Append `.0` for whole numbers.
 */
function formatVerifiedAt(verifiedAt: number): string {
  const s = String(verifiedAt);
  return Number.isInteger(verifiedAt) && !s.includes(".") ? `${s}.0` : s;
}

/**
 * Compute HMAC-SHA256 over the session payload.
 *
 * The machine GUID is used as the HMAC key — this prevents casual tampering
 * but is not a cryptographic secret. The real security boundary is Windows
 * Hello itself; the session file is a convenience cache (same threat model as
 * `sudo` timestamp files). Mirrors Python `_compute_session_hmac`.
 */
export function computeSessionHmac(
  verifiedAt: number,
  machineId: string,
  username: string,
): string {
  const msg = `${formatVerifiedAt(verifiedAt)}|${machineId}|${username}`;
  return createHmac("sha256", Buffer.from(machineId, "utf8"))
    .update(Buffer.from(msg, "utf8"))
    .digest("hex");
}

/** Write a persistent biometric session file after successful verification. */
export function writeBioSession(): void {
  try {
    const dir = getBioSessionDir();
    const machineId = getMachineId();
    const username = getUsername();
    const verifiedAt = Date.now() / 1000;
    const payload: BioSession = {
      verified_at: verifiedAt,
      machine_id: machineId,
      username,
      hmac: computeSessionHmac(verifiedAt, machineId, username),
    };
    const target = join(dir, BIO_SESSION_FILE);
    // Atomic write: temp file in the same directory, then rename.
    const tmp = join(dir, `${BIO_SESSION_FILE}.${process.pid}.tmp`);
    try {
      writeFileSync(tmp, JSON.stringify(payload), { encoding: "utf8" });
      renameSync(tmp, target);
    } catch (err) {
      try {
        unlinkSync(tmp);
      } catch {
        /* ignore */
      }
      throw err;
    }
  } catch {
    // Best-effort — failure to persist the session is non-fatal.
  }
}

/**
 * Check the persistent biometric session file.
 *
 * Returns true if the session exists, is not expired, matches the current
 * machine and user, and its HMAC is intact. Returns false on any error.
 * Mirrors Python `_read_bio_session`.
 */
export function readBioSession(): boolean {
  try {
    const target = join(getBioSessionDir(), BIO_SESSION_FILE);
    if (!existsSync(target)) return false;
    const data = JSON.parse(readFileSync(target, "utf8")) as BioSession;

    const verifiedAt = Number(data.verified_at);
    const machineId = String(data.machine_id);
    const username = String(data.username);
    const storedHmac = String(data.hmac);

    if (machineId !== getMachineId()) return false;
    if (username !== getUsername()) return false;

    const expected = computeSessionHmac(verifiedAt, machineId, username);
    const a = Buffer.from(storedHmac, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length || !timingSafeEqual(a, b)) return false;

    const age = Date.now() / 1000 - verifiedAt;
    if (age < 0 || age >= bioSessionTtl()) return false;

    return true;
  } catch {
    return false;
  }
}

/**
 * Delete the persistent biometric session file and reset the in-memory cache.
 *
 * Returns true if a session file was removed, false otherwise.
 */
export function invalidateBioSession(): boolean {
  resetBioCache();
  try {
    const target = join(getBioSessionDir(), BIO_SESSION_FILE);
    if (existsSync(target)) {
      rmSync(target);
      return true;
    }
  } catch {
    /* ignore */
  }
  return false;
}

// ---------------------------------------------------------------------------
// Interactivity detection
// ---------------------------------------------------------------------------

/**
 * Detect whether the current process has an interactive console.
 *
 * Returns false when stdin is not a TTY (background services, CI runners,
 * piped input). On Windows we additionally require a console window when that
 * can be determined; best-effort — if a TTY is present we treat it as
 * sufficient since Node cannot reliably query `GetConsoleWindow()` without
 * native bindings. Mirrors Python `_is_interactive`.
 */
export function isInteractive(): boolean {
  if (!process.stdin.isTTY) return false;
  // On Windows a TTY implies an attached console window in practice; without
  // native Win32 access we cannot do better, so a TTY is treated as enough.
  return true;
}

// ---------------------------------------------------------------------------
// Windows Hello verification (via PowerShell subprocess)
// ---------------------------------------------------------------------------

// PowerShell script that invokes the WinRT UserConsentVerifier. Node has no
// native WinRT bindings, so we shell out. The script:
//   1. Checks availability via CheckAvailabilityAsync.
//   2. If available, calls RequestVerificationAsync (shows the Hello dialog).
//   3. Prints a single status token we can parse: AVAILABLE_* / RESULT_*.
//
// NOTE: This live-prompt path requires a real interactive Windows session
// with Windows Hello configured. It cannot be exercised by the unit tests in
// this repo (no biometric hardware / no interactive console in CI). The
// DEGRADATION paths (disabled, non-interactive, valid session/cache,
// non-Windows) are all unit-tested instead.
const WINDOWS_HELLO_PS = `
$ErrorActionPreference = 'Stop'
try {
  [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1'
  })[0]

  function Await($op, $resultType) {
    $task = $asTaskGeneric.MakeGenericMethod($resultType).Invoke($null, @($op))
    $task.Wait(120000) | Out-Null
    return $task.Result
  }

  $availType = [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]
  $avail = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) $availType
  if ($avail -ne $availType::Available) {
    Write-Output "AVAILABLE_NO:$avail"
    exit 0
  }

  $resType = [Windows.Security.Credentials.UI.UserConsentVerificationResult]
  $res = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($env:LOCKE_HELLO_MESSAGE)) $resType
  if ($res -eq $resType::Verified) { Write-Output "RESULT_VERIFIED" }
  elseif ($res -eq $resType::Canceled) { Write-Output "RESULT_CANCELED" }
  else { Write-Output "RESULT_DENIED:$res" }
} catch {
  Write-Output "ERROR:$($_.Exception.Message)"
}
`;

/**
 * Trigger a Windows Hello prompt and return true if the user verified.
 *
 * Calls the WinRT `UserConsentVerifier` API through a PowerShell subprocess.
 * Honors the in-memory cache and persistent session first (no prompt when
 * either is valid). On non-Windows or non-interactive shells, returns true
 * (ungated) with a warning where appropriate — matching the Python reference.
 *
 * Throws {@link BiometricDeniedError} if the user cancels/denies and
 * {@link BiometricUnavailableError} if Windows Hello is not set up.
 */
export function verifyWindowsHello(
  message = "Locke: Verify your identity to access credentials",
): boolean {
  if (bioCacheValid()) return true;

  if (readBioSession()) {
    bioVerifiedAt = Date.now() / 1000; // warm the in-memory cache
    return true;
  }

  if (process.platform !== "win32") return true;

  if (!isInteractive()) {
    console.warn(
      "Non-interactive shell detected — skipping Windows Hello prompt. " +
        "Keystore access proceeds without biometric gate.",
    );
    return true;
  }

  let output: string;
  try {
    output = execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        WINDOWS_HELLO_PS,
      ],
      {
        encoding: "utf8",
        timeout: 130000,
        env: { ...process.env, LOCKE_HELLO_MESSAGE: message },
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
  } catch (err) {
    throw new BiometricUnavailableError(
      `Windows Hello subprocess failed: ${(err as Error).message}`,
    );
  }

  const token = output.trim().split(/\r?\n/).pop() ?? "";

  if (token === "RESULT_VERIFIED") {
    bioVerifiedAt = Date.now() / 1000;
    writeBioSession();
    return true;
  }
  if (token === "RESULT_CANCELED") {
    throw new BiometricDeniedError("cancelled by user");
  }
  if (token.startsWith("RESULT_DENIED")) {
    throw new BiometricDeniedError(`verification denied (${token})`);
  }
  if (token.startsWith("AVAILABLE_NO")) {
    throw new BiometricUnavailableError(`Windows Hello not available (${token})`);
  }
  throw new BiometricUnavailableError(`unexpected verifier output (${token})`);
}

/**
 * Gate access behind biometric verification when enabled.
 *
 * No-op when biometric is disabled, on Linux, or when the cache/session is
 * valid. In non-interactive shells, skips the prompt with a warning (handled
 * inside {@link verifyWindowsHello}). On macOS, Touch ID gating is not yet
 * implemented and passes through. Mirrors Python `_require_biometric`.
 */
export function requireBiometric(): void {
  if (!biometricEnabled()) return;
  if (process.platform === "linux") return;
  if (process.platform === "win32") {
    verifyWindowsHello();
  } else if (process.platform === "darwin") {
    // macOS Touch ID — not yet implemented, pass through.
    console.debug?.("macOS Touch ID gating not yet implemented");
  }
}

// ---------------------------------------------------------------------------
// Legacy credential naming (migration support)
// ---------------------------------------------------------------------------
// Older credential-management tools stored secrets using the project name as
// the service/target and a short credential name as the username. Locke
// unifies under service="locke" with UPPER_SNAKE_CASE names. The patterns
// below describe legacy naming conventions Locke can still read so users can
// migrate without losing credentials.

const LEGACY_KEY_SUFFIX = "_CONFIG_ENCRYPTION_KEY";

const LEGACY_VAULT_PASSWORD_PATTERNS: Array<[string, string]> = [
  ["locke-bio", "LOCKE_VAULT_PASSWORD"],
];

/** Return legacy (target, username) pairs to try for a Locke credential name. */
export function legacyLookupsFor(name: string): Array<[string, string]> {
  if (name === "LOCKE_VAULT_PASSWORD") {
    return [...LEGACY_VAULT_PASSWORD_PATTERNS];
  }
  if (name.endsWith(LEGACY_KEY_SUFFIX)) {
    const project = name.slice(0, name.length - LEGACY_KEY_SUFFIX.length).toLowerCase();
    return [
      [project, "config-encryption-key"],
      [project, "config_encryption_key"],
      [`config-encryption-key@${project}`, "config-encryption-key"],
    ];
  }
  return [];
}

/**
 * Best-effort legacy lookup via keytar.
 *
 * NOTE: The Python reference also reads bare-target credentials directly via
 * the Win32 `CredRead` API. Pure Node (keytar) cannot read a credential by a
 * bare target name that does not follow keytar's `{service}/{account}`
 * convention, so this falls back to `keytar.getPassword(target, username)`
 * and `keytar.findCredentials(target)`. Credentials stored under bare Win32
 * target names by other tools may therefore not be reachable from Node — a
 * known limitation relative to the Python implementation.
 */
async function legacyLookup(name: string): Promise<string | null> {
  for (const [target, username] of legacyLookupsFor(name)) {
    let value: string | null = null;
    try {
      value = await keytar.getPassword(target, username);
    } catch {
      value = null;
    }
    if (value === null) {
      try {
        const creds = await keytar.findCredentials(target);
        const hit = creds.find((c) => c.account === username) ?? creds[0];
        if (hit) value = hit.password;
      } catch {
        /* ignore */
      }
    }
    if (value !== null) {
      console.warn(
        `Credential '${name}' found under legacy name (target='${target}'). ` +
          "Run 'locke keystore migrate' to update to the new naming.",
      );
      return value;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Credential CRUD
// ---------------------------------------------------------------------------

/**
 * Retrieve a credential from the OS keystore.
 *
 * Triggers biometric verification first (when enabled). Tries the canonical
 * `locke` service, then falls back to legacy naming patterns.
 */
export async function getCredential(name: string): Promise<string | null> {
  requireBiometric();
  try {
    const value = await keytar.getPassword(SERVICE_NAME, name);
    if (value !== null) return value;
  } catch {
    throw new KeystoreUnavailableError(process.platform, "keytar");
  }
  return legacyLookup(name);
}

/** Store a credential in the OS keystore (biometric-gated). */
export async function setCredential(name: string, value: string): Promise<void> {
  requireBiometric();
  try {
    await keytar.setPassword(SERVICE_NAME, name, value);
  } catch {
    throw new KeystoreUnavailableError(process.platform, "keytar");
  }
}

/** Remove a credential from the OS keystore (biometric-gated). */
export async function deleteCredential(name: string): Promise<void> {
  requireBiometric();
  try {
    await keytar.deletePassword(SERVICE_NAME, name);
  } catch {
    throw new KeystoreUnavailableError(process.platform, "keytar");
  }
}

// ---------------------------------------------------------------------------
// Legacy credential migration
// ---------------------------------------------------------------------------

export interface LegacyCredential {
  lockeName: string;
  legacyTarget: string;
  legacyUsername: string;
  alreadyMigrated: boolean;
}

/** Scan for credentials stored under legacy naming conventions. */
export async function findLegacyCredentials(
  names?: string[] | null,
): Promise<LegacyCredential[]> {
  const candidates = names ?? ["LOCKE_VAULT_PASSWORD"];
  const found: LegacyCredential[] = [];

  for (const name of candidates) {
    for (const [target, username] of legacyLookupsFor(name)) {
      let value: string | null = null;
      try {
        value = await keytar.getPassword(target, username);
      } catch {
        value = null;
      }
      if (value === null) {
        try {
          const creds = await keytar.findCredentials(target);
          const hit = creds.find((c) => c.account === username) ?? creds[0];
          if (hit) value = hit.password;
        } catch {
          /* ignore */
        }
      }
      if (value !== null) {
        let current: string | null = null;
        try {
          current = await keytar.getPassword(SERVICE_NAME, name);
        } catch {
          current = null;
        }
        found.push({
          lockeName: name,
          legacyTarget: target,
          legacyUsername: username,
          alreadyMigrated: current !== null,
        });
      }
    }
  }
  return found;
}

/**
 * Copy a legacy credential into the Locke namespace.
 *
 * Returns the legacy source description (e.g. `"target='myproject'"`) on
 * success, or null if no legacy credential was found.
 */
export async function migrateCredential(
  name: string,
  opts: { deleteLegacy?: boolean } = {},
): Promise<string | null> {
  requireBiometric();
  for (const [target, username] of legacyLookupsFor(name)) {
    let value: string | null = null;
    try {
      value = await keytar.getPassword(target, username);
    } catch {
      value = null;
    }
    if (value === null) {
      try {
        const creds = await keytar.findCredentials(target);
        const hit = creds.find((c) => c.account === username) ?? creds[0];
        if (hit) value = hit.password;
      } catch {
        /* ignore */
      }
    }
    if (value !== null) {
      await keytar.setPassword(SERVICE_NAME, name, value);
      const source = `target='${target}'`;
      if (opts.deleteLegacy) {
        try {
          await keytar.deletePassword(target, username);
        } catch {
          console.warn(`Could not delete legacy credential ${source}`);
        }
      }
      return source;
    }
  }
  return null;
}
