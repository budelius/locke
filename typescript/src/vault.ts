/**
 * Vaultwarden/Bitwarden API client.
 *
 * Connects to Vaultwarden via Bitwarden-compatible API v1.
 * Secret path convention: {project}/{tenant_slug}/{secret_name}
 *
 * Bitwarden encrypts all vault data client-side. After authentication the
 * server returns an encrypted symmetric key which must be decrypted locally
 * using the master key derived from the user's password. All cipher fields
 * (name, login password, notes, …) are then decrypted with that symmetric
 * key. Encrypted strings use the format `{type}.{iv}|{ct}|{mac}` where
 * type 2 = AES-256-CBC + HMAC-SHA256.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { SecretNotFoundError, VaultAuthError } from "./errors.js";
import { resolveCredential } from "./pipeline.js";

// Vaultwarden connection env vars
const VAULT_URL_VAR = "LOCKE_VAULT_URL";
const VAULT_USERNAME_VAR = "LOCKE_VAULT_USERNAME";
const VAULT_PASSWORD_CREDENTIAL = "LOCKE_VAULT_PASSWORD";

const KDF_ITERATIONS = 600_000;

/** Locke-owned placeholder convention for intentionally unfilled vault secrets. */
export const PLACEHOLDER_VALUE = "FILL_ME";
const PLACEHOLDER_VALUES = new Set([PLACEHOLDER_VALUE]);

/** Return true when *value* is a Locke vault placeholder. */
export function isPlaceholder(value: string | null | undefined): boolean {
  return value != null && PLACEHOLDER_VALUES.has(value.trim());
}

/**
 * A username + password retrieved from a single vault entry.
 *
 * Bitwarden login ciphers natively carry both a `username` and a `password`
 * field. Storing a credential as one entry (rather than two separate
 * secrets) keeps the pair together and lets callers fetch both in a single
 * round-trip via {@link VaultClient.getSecretPair}.
 *
 * `username` is `null` when the entry has no username set; `password` is the
 * empty string when only a username is stored.
 */
export interface CredentialPair {
  username: string | null;
  password: string;
}

interface CipherMetadata {
  username: string | null;
  uri: string | null;
  notes: string | null;
}

interface CipherIndex {
  names: Record<string, string>;
  folders: Record<string, string>;
  values: Record<string, string>;
  metadata: Record<string, CipherMetadata>;
}

// ---------------------------------------------------------------------------
// Bitwarden client-side crypto helpers
// ---------------------------------------------------------------------------

/** HKDF-Expand (RFC 5869) using HMAC-SHA256. PRK is used directly (no extract). */
export function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = 32; // SHA-256 output
  const n = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0);
  let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    t = createHmac("sha256", prk)
      .update(Buffer.concat([t, info, Buffer.from([i])]))
      .digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, length);
}

/** Derive the 32-byte master key from password + email. */
export function makeMasterKey(
  password: string,
  email: string,
  kdfIterations: number = KDF_ITERATIONS,
): Buffer {
  return pbkdf2Sync(
    Buffer.from(password, "utf8"),
    Buffer.from(email.toLowerCase(), "utf8"),
    kdfIterations,
    32,
    "sha256",
  );
}

/**
 * Stretch master key into (encKey, macKey) via HKDF-Expand.
 *
 * Returns two 32-byte keys used to decrypt the encrypted symmetric key
 * returned by the Bitwarden identity endpoint.
 */
export function stretchMasterKey(masterKey: Buffer): {
  encKey: Buffer;
  macKey: Buffer;
} {
  return {
    encKey: hkdfExpand(masterKey, Buffer.from("enc", "utf8"), 32),
    macKey: hkdfExpand(masterKey, Buffer.from("mac", "utf8"), 32),
  };
}

/**
 * Encrypt a plaintext string into Bitwarden `2.iv|ct|mac` format.
 *
 * Type 2 = AES-256-CBC + HMAC-SHA256. Inverse of
 * {@link decryptEncryptedString}.
 */
export function encryptString(
  plaintext: string,
  encKey: Buffer,
  macKey: Buffer,
): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", encKey, iv); // PKCS7 padding on by default
  const ct = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf8")),
    cipher.final(),
  ]);
  const mac = createHmac("sha256", macKey)
    .update(Buffer.concat([iv, ct]))
    .digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

/**
 * Decrypt a Bitwarden encrypted string (`2.iv|ct|mac` format).
 *
 * Type 2 = AES-256-CBC + HMAC-SHA256.
 */
export function decryptEncryptedString(
  encString: string,
  encKey: Buffer,
  macKey: Buffer,
): Buffer {
  if (!encString) return Buffer.alloc(0);

  const dotIndex = encString.indexOf(".");
  if (dotIndex === -1) {
    throw new Error("invalid encrypted string format: no type prefix");
  }
  const encType = parseInt(encString.slice(0, dotIndex), 10);
  if (encType !== 2) {
    throw new Error(`unsupported encryption type ${encType} (expected 2)`);
  }

  const segments = encString.slice(dotIndex + 1).split("|");
  if (segments.length !== 3) {
    throw new Error(`expected 3 segments (iv|ct|mac), got ${segments.length}`);
  }

  const iv = Buffer.from(segments[0], "base64");
  const ct = Buffer.from(segments[1], "base64");
  const mac = Buffer.from(segments[2], "base64");

  const expectedMac = createHmac("sha256", macKey)
    .update(Buffer.concat([iv, ct]))
    .digest();
  if (mac.length !== expectedMac.length || !timingSafeEqual(mac, expectedMac)) {
    throw new Error("HMAC verification failed");
  }

  const decipher = createDecipheriv("aes-256-cbc", encKey, iv);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/**
 * Decrypt the user's symmetric key from the login response `Key` field.
 *
 * Returns `[encKey, macKey]` — the 64-byte symmetric key split in half.
 */
export function decryptSymmetricKey(
  encryptedKey: string,
  masterKey: Buffer,
): [Buffer, Buffer] {
  const { encKey: stretchedEnc, macKey: stretchedMac } =
    stretchMasterKey(masterKey);
  const raw = decryptEncryptedString(encryptedKey, stretchedEnc, stretchedMac);
  if (raw.length !== 64) {
    throw new Error(`decrypted symmetric key is ${raw.length} bytes (expected 64)`);
  }
  return [raw.subarray(0, 32), raw.subarray(32)];
}

/**
 * Pre-hash master password the way Bitwarden expects.
 *
 * 1. PBKDF2-SHA256(password, lowercase(email), 600_000 iterations) → master key
 * 2. PBKDF2-SHA256(master_key, password, 1 iteration) → hashed password
 * 3. Base64-encode the result
 */
export function hashPassword(password: string, email: string): string {
  const masterKey = makeMasterKey(password, email);
  const hashed = pbkdf2Sync(
    masterKey,
    Buffer.from(password, "utf8"),
    1,
    32,
    "sha256",
  );
  return hashed.toString("base64");
}

/** Decrypt an optional Bitwarden cipher field to a UTF-8 string. */
function decryptCipherString(
  encString: string | null | undefined,
  encKey: Buffer,
  macKey: Buffer,
): string | null {
  if (!encString) return null;
  try {
    return decryptEncryptedString(encString, encKey, macKey).toString("utf8");
  } catch {
    return null;
  }
}

interface SyncData {
  ciphers?: Array<{
    id: string;
    name?: string;
    notes?: string;
    login?: {
      username?: string;
      password?: string;
      uris?: Array<{ uri?: string; match?: unknown }>;
    };
  }>;
  folders?: Array<{ id: string; name?: string }>;
}

/** Bitwarden-compatible API client for Vaultwarden. */
export class VaultClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private encKey: Buffer;
  private macKey: Buffer;
  // path -> plaintext value, populated on first sync().
  private secrets: Record<string, string> | null = null;
  // path -> {username, uri, notes}, populated on first sync().
  private metadata: Record<string, CipherMetadata> | null = null;
  // Overridable in tests via _setTestState.
  private cipherIndexFn: () => Promise<CipherIndex> = () =>
    this.cipherIndexLive();
  private writeFn:
    | ((payload: Record<string, unknown>, cipherId: string | undefined) => Promise<void>)
    | null = null;

  constructor(
    baseUrl: string,
    accessToken: string,
    encKey: Buffer,
    macKey: Buffer,
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.headers = { Authorization: `Bearer ${accessToken}` };
    this.encKey = encKey;
    this.macKey = macKey;
  }

  /**
   * Test-only hook: inject the in-memory caches and optionally stub the
   * write/index helpers so unit tests can exercise get/set logic without a
   * live Vaultwarden server (mirrors the Python tests' monkeypatching).
   */
  _setTestState(state: {
    secrets?: Record<string, string> | null;
    metadata?: Record<string, CipherMetadata> | null;
    cipherIndex?: () => Promise<CipherIndex>;
    write?: (
      payload: Record<string, unknown>,
      cipherId: string | undefined,
    ) => Promise<void>;
  }): void {
    if ("secrets" in state) this.secrets = state.secrets ?? null;
    if ("metadata" in state) this.metadata = state.metadata ?? null;
    if (state.cipherIndex) this.cipherIndexFn = state.cipherIndex;
    if (state.write) this.writeFn = state.write;
  }

  /** Create an authenticated vault client using pipeline-resolved credentials. */
  static async connect(): Promise<VaultClient> {
    const baseUrl = process.env[VAULT_URL_VAR];
    if (!baseUrl) {
      throw new VaultAuthError(
        "unknown",
        `environment variable ${VAULT_URL_VAR} is not set`,
      );
    }

    const username = process.env[VAULT_USERNAME_VAR];
    if (!username) {
      throw new VaultAuthError(
        baseUrl,
        `environment variable ${VAULT_USERNAME_VAR} is not set`,
      );
    }

    const passwordCred = await resolveCredential(VAULT_PASSWORD_CREDENTIAL);
    return VaultClient.connectWith(baseUrl, username, passwordCred.value);
  }

  /** Create an authenticated vault client using explicit credentials. */
  static async connectWith(
    baseUrl: string,
    username: string,
    password: string,
  ): Promise<VaultClient> {
    if (!baseUrl) {
      throw new VaultAuthError("unknown", "empty baseUrl passed to connectWith()");
    }
    if (!username) {
      throw new VaultAuthError(baseUrl, "empty username passed to connectWith()");
    }

    const [token, encryptedKey] = await VaultClient.authenticate(
      baseUrl,
      username,
      password,
    );

    const masterKey = makeMasterKey(password, username);
    const [encKey, macKey] = decryptSymmetricKey(encryptedKey, masterKey);

    return new VaultClient(baseUrl, token, encKey, macKey);
  }

  /**
   * Authenticate with Bitwarden/Vaultwarden identity endpoint.
   *
   * Returns `[accessToken, encryptedKey]` where *encryptedKey* is the user's
   * encrypted symmetric key (`Key` field in the response).
   */
  private static async authenticate(
    baseUrl: string,
    username: string,
    password: string,
  ): Promise<[string, string]> {
    const identityUrl = `${baseUrl.replace(/\/+$/, "")}/identity/connect/token`;
    const hashedPassword = hashPassword(password, username);

    const body = new URLSearchParams({
      grant_type: "password",
      username,
      password: hashedPassword,
      scope: "api offline_access",
      client_id: "cli",
      deviceType: "9",
      deviceIdentifier: "locke-client",
      deviceName: "locke",
    });

    let response: Response;
    try {
      response = await fetch(identityUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });
    } catch (exc) {
      throw new VaultAuthError(
        baseUrl,
        `cannot reach server (${(exc as Error).message})`,
      );
    }

    if (!response.ok) {
      const status = response.status;
      let detail: string;
      if (status === 400) {
        detail = "invalid credentials (wrong username or password)";
      } else if (status === 401) {
        detail = "unauthorized (bad password or expired token)";
      } else if (status === 404) {
        detail = `identity endpoint not found at ${identityUrl}`;
      } else {
        detail = `HTTP ${status}`;
      }
      throw new VaultAuthError(baseUrl, detail);
    }

    const data = (await response.json()) as {
      access_token: string;
      Key?: string;
    };
    const accessToken = data.access_token;
    const encryptedKey = data.Key ?? "";
    if (!encryptedKey) {
      throw new VaultAuthError(
        baseUrl,
        "server did not return an encrypted symmetric key (Key field)",
      );
    }
    return [accessToken, encryptedKey];
  }

  /** Encrypt a plaintext string using this client's symmetric key. */
  private encrypt(plaintext: string | null | undefined): string | null {
    if (!plaintext) return null;
    return encryptString(plaintext, this.encKey, this.macKey);
  }

  /** Decrypt a Bitwarden encrypted field using this client's symmetric key. */
  private decrypt(encString: string | null | undefined): string | null {
    return decryptCipherString(encString, this.encKey, this.macKey);
  }

  /** Return raw `/api/sync` data from Vaultwarden. */
  private async syncData(): Promise<SyncData> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/api/sync`, {
        headers: this.headers,
      });
    } catch (exc) {
      throw new VaultAuthError(
        this.baseUrl,
        `sync failed: ${(exc as Error).message}`,
      );
    }
    if (!response.ok) {
      throw new VaultAuthError(
        this.baseUrl,
        `sync failed with HTTP ${response.status} (token may be expired)`,
      );
    }
    return (await response.json()) as SyncData;
  }

  /** Dispatch to the (possibly test-stubbed) cipher index source. */
  private async cipherIndex(): Promise<CipherIndex> {
    return this.cipherIndexFn();
  }

  /** Return decrypted lookup maps for ciphers and folders (live server). */
  private async cipherIndexLive(): Promise<CipherIndex> {
    const data = await this.syncData();

    const names: Record<string, string> = {};
    const values: Record<string, string> = {};
    const metadata: Record<string, CipherMetadata> = {};
    for (const cipher of data.ciphers ?? []) {
      const name = this.decrypt(cipher.name);
      if (!name) continue;
      names[name] = cipher.id;
      const login = cipher.login ?? {};
      const username = this.decrypt(login.username);
      let uri: string | null = null;
      const uris = login.uris ?? [];
      if (uris.length > 0) {
        uri = this.decrypt(uris[0]?.uri);
      }
      const notes = this.decrypt(cipher.notes);
      const value = this.decrypt(login.password) ?? notes;
      if (value !== null) {
        if (isPlaceholder(value)) {
          console.warn(`Vault secret ${name} is still a placeholder`);
        }
        values[name] = value;
      }
      metadata[name] = { username, uri, notes };
    }

    const folders: Record<string, string> = {};
    for (const folder of data.folders ?? []) {
      const name = this.decrypt(folder.name);
      if (name) folders[name] = folder.id;
    }

    return { names, folders, values, metadata };
  }

  /**
   * Fetch and decrypt every cipher in one `/api/sync` round-trip.
   *
   * Bulk-decrypts all logins/notes into a `{plaintextName: value}` map,
   * caches it on the instance, and returns it. Subsequent calls return the
   * cached map unless *forceRefresh* is set.
   */
  async sync(forceRefresh = false): Promise<Record<string, string>> {
    if (this.secrets !== null && !forceRefresh) {
      return this.secrets;
    }
    const index = await this.cipherIndex();
    this.secrets = index.values;
    this.metadata = index.metadata;
    return this.secrets;
  }

  /** Return cached secrets whose plaintext name starts with *prefix*. */
  async listSecrets(prefix = ""): Promise<Record<string, string>> {
    if (this.secrets === null) {
      await this.sync();
    }
    const secrets = this.secrets as Record<string, string>;
    if (!prefix) return { ...secrets };
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(secrets)) {
      if (k.startsWith(prefix)) out[k] = v;
    }
    return out;
  }

  /** Return an existing or newly-created folder id. */
  private async resolveFolderId(
    folderName: string | null,
    index: CipherIndex,
  ): Promise<string | null> {
    if (!folderName) return null;
    const existing = index.folders[folderName];
    if (existing) return existing;

    const response = await fetch(`${this.baseUrl}/api/folders`, {
      method: "POST",
      headers: { ...this.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ name: this.encrypt(folderName) }),
    });
    if (!response.ok) {
      throw new VaultAuthError(
        this.baseUrl,
        `folder creation failed with HTTP ${response.status}`,
      );
    }
    const folderId = ((await response.json()) as { id: string }).id;
    index.folders[folderName] = folderId;
    return folderId;
  }

  /** Build an encrypted Bitwarden login cipher payload. */
  private buildCipherPayload(
    path: string,
    value: string,
    folderId: string | null,
    username: string | null = null,
    uri: string | null = null,
    notes: string | null = null,
  ): Record<string, unknown> {
    const encryptedUri = this.encrypt(uri);
    const uris = encryptedUri ? [{ match: null, uri: encryptedUri }] : [];
    return {
      type: 1,
      name: this.encrypt(path),
      folderId,
      login: {
        username: this.encrypt(username),
        password: this.encrypt(value),
        uris,
      },
      notes: this.encrypt(notes),
      favorite: false,
      reprompt: 0,
    };
  }

  /**
   * Create or update a Vaultwarden secret by path.
   *
   * Returns `"created"` or `"updated"`.
   */
  async setSecret(
    path: string,
    value: string | null | undefined = undefined,
    opts: {
      folder?: string | null;
      username?: string | null;
      uri?: string | null;
      notes?: string | null;
    } = {},
  ): Promise<"created" | "updated"> {
    if (!path) throw new Error("path must not be empty");

    const folder = opts.folder;
    const username = opts.username;
    const uri = opts.uri;
    const notes = opts.notes;

    let resolvedValue: string;
    if (value === null || value === undefined || value === "") {
      resolvedValue = PLACEHOLDER_VALUE;
      console.warn(`Vault secret ${path} written with placeholder value`);
    } else {
      resolvedValue = value;
      if (isPlaceholder(value)) {
        console.warn(`Vault secret ${path} written with placeholder value`);
      }
    }

    const index = await this.cipherIndex();
    const folderName =
      folder === undefined
        ? path.includes("/")
          ? path.slice(0, path.lastIndexOf("/"))
          : ""
        : folder;
    const folderId = await this.resolveFolderId(folderName ?? null, index);
    const cipherId = index.names[path];

    let action: "created" | "updated";
    let payload: Record<string, unknown>;
    if (cipherId) {
      const current = index.metadata[path] ?? {
        username: null,
        uri: null,
        notes: null,
      };
      payload = this.buildCipherPayload(
        path,
        resolvedValue,
        folderId,
        username !== undefined ? username : current.username,
        uri !== undefined ? uri : current.uri,
        notes !== undefined ? notes : current.notes,
      );
      action = "updated";
    } else {
      payload = this.buildCipherPayload(
        path,
        resolvedValue,
        folderId,
        username ?? null,
        uri ?? null,
        notes ?? null,
      );
      action = "created";
    }

    await this.write(payload, cipherId);

    if (this.secrets !== null) {
      this.secrets[path] = resolvedValue;
    }
    if (this.metadata !== null) {
      const current = this.metadata[path] ?? {
        username: null,
        uri: null,
        notes: null,
      };
      this.metadata[path] = {
        username: username !== undefined ? username : current.username,
        uri: uri !== undefined ? uri : current.uri,
        notes: notes !== undefined ? notes : current.notes,
      };
    }
    return action;
  }

  /** POST/PUT a cipher payload to the live server (or test stub). */
  private async write(
    payload: Record<string, unknown>,
    cipherId: string | undefined,
  ): Promise<void> {
    if (this.writeFn) {
      await this.writeFn(payload, cipherId);
      return;
    }
    const url = cipherId
      ? `${this.baseUrl}/api/ciphers/${cipherId}`
      : `${this.baseUrl}/api/ciphers`;
    const response = await fetch(url, {
      method: cipherId ? "PUT" : "POST",
      headers: { ...this.headers, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new VaultAuthError(
        this.baseUrl,
        `write failed with HTTP ${response.status}`,
      );
    }
  }

  /**
   * Retrieve a secret by path (`{project}/{tenant}/{name}`).
   *
   * Reads from the in-memory snapshot populated by {@link sync} (called
   * automatically on first access). Throws {@link SecretNotFoundError} if the
   * path is not in the vault.
   */
  async getSecret(path: string): Promise<string> {
    if (this.secrets === null) {
      await this.sync();
    }
    const secrets = this.secrets as Record<string, string>;
    if (!(path in secrets)) {
      throw new SecretNotFoundError(path);
    }
    const value = secrets[path];
    if (isPlaceholder(value)) {
      console.warn(`Vault secret ${path} is still a placeholder`);
    }
    return value;
  }

  /**
   * Retrieve a username + password stored in a single vault entry.
   *
   * Reads one login cipher and returns both its `username` and `password`
   * fields. Throws {@link SecretNotFoundError} if no cipher with *path*
   * exists.
   */
  async getSecretPair(path: string): Promise<CredentialPair> {
    if (this.secrets === null || this.metadata === null) {
      await this.sync();
    }
    const secrets = this.secrets as Record<string, string>;
    const metadata = this.metadata as Record<string, CipherMetadata>;
    const meta = metadata[path];
    if (meta === undefined && !(path in secrets)) {
      throw new SecretNotFoundError(path);
    }
    const password = secrets[path] ?? "";
    if (isPlaceholder(password)) {
      console.warn(`Vault secret ${path} is still a placeholder`);
    }
    const username = meta?.username ?? null;
    return { username, password };
  }

  /**
   * Create or update a single vault entry holding a username + password.
   *
   * Convenience wrapper around {@link setSecret}. Returns `"created"` or
   * `"updated"`.
   */
  async setSecretPair(
    path: string,
    username: string | null,
    password: string | null | undefined = undefined,
    opts: { folder?: string | null; uri?: string | null; notes?: string | null } = {},
  ): Promise<"created" | "updated"> {
    return this.setSecret(path, password, {
      folder: opts.folder,
      username,
      uri: opts.uri,
      notes: opts.notes,
    });
  }
}

/** Retrieve a secret from Vaultwarden by path. */
export async function getVaultSecret(path: string): Promise<string> {
  const client = await VaultClient.connect();
  return client.getSecret(path);
}

/** Create or update a Vaultwarden secret by path. Returns `"created"`/`"updated"`. */
export async function setVaultSecret(
  path: string,
  value?: string | null,
  opts: {
    folder?: string | null;
    username?: string | null;
    uri?: string | null;
    notes?: string | null;
  } = {},
): Promise<"created" | "updated"> {
  const client = await VaultClient.connect();
  return client.setSecret(path, value, opts);
}

/** Retrieve a username + password stored in a single Vaultwarden entry. */
export async function getVaultSecretPair(path: string): Promise<CredentialPair> {
  const client = await VaultClient.connect();
  return client.getSecretPair(path);
}

/**
 * Create or update a single Vaultwarden entry holding a username + password.
 *
 * Returns `"created"` or `"updated"`.
 */
export async function setVaultSecretPair(
  path: string,
  username: string | null,
  password?: string | null,
  opts: { folder?: string | null; uri?: string | null; notes?: string | null } = {},
): Promise<"created" | "updated"> {
  const client = await VaultClient.connect();
  return client.setSecretPair(path, username, password, opts);
}
