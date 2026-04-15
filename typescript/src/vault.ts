/**
 * Vaultwarden/Bitwarden API client.
 *
 * Connects to Vaultwarden via Bitwarden-compatible API v1.
 * Secret path convention: {project}/{tenant_slug}/{secret_name}
 */

import { VaultAuthError, SecretNotFoundError } from "./errors.js";
import { resolveCredential } from "./pipeline.js";

const VAULT_URL_VAR = "LOCKE_VAULT_URL";
const VAULT_USERNAME_VAR = "LOCKE_VAULT_USERNAME";
const VAULT_PASSWORD_CREDENTIAL = "LOCKE_VAULT_PASSWORD";

class VaultClient {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor(baseUrl: string, accessToken: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.headers = { Authorization: `Bearer ${accessToken}` };
  }

  static async connect(): Promise<VaultClient> {
    const baseUrl = process.env[VAULT_URL_VAR];
    if (!baseUrl)
      throw new VaultAuthError(
        "unknown",
        `environment variable ${VAULT_URL_VAR} is not set`,
      );

    const username = process.env[VAULT_USERNAME_VAR];
    if (!username)
      throw new VaultAuthError(
        baseUrl,
        `environment variable ${VAULT_USERNAME_VAR} is not set`,
      );

    const passwordCred = await resolveCredential(VAULT_PASSWORD_CREDENTIAL);
    const token = await VaultClient.authenticate(
      baseUrl,
      username,
      passwordCred.value,
    );
    return new VaultClient(baseUrl, token);
  }

  private static async authenticate(
    baseUrl: string,
    username: string,
    password: string,
  ): Promise<string> {
    const identityUrl = `${baseUrl.replace(/\/+$/, "")}/identity/connect/token`;

    const body = new URLSearchParams({
      grant_type: "password",
      username,
      password,
      scope: "api",
      client_id: "cli",
      deviceType: "9",
      deviceIdentifier: "locke-client",
      deviceName: "locke",
    });

    const response = await fetch(identityUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!response.ok) {
      const status = response.status;
      let detail: string;
      if (status === 400)
        detail = "invalid credentials (wrong username or password)";
      else if (status === 401)
        detail = "unauthorized (bad password or expired token)";
      else if (status === 404)
        detail = `identity endpoint not found at ${identityUrl}`;
      else detail = `HTTP ${status}`;
      throw new VaultAuthError(baseUrl, detail);
    }

    const data = (await response.json()) as { access_token: string };
    return data.access_token;
  }

  async getSecret(path: string): Promise<string> {
    const response = await fetch(`${this.baseUrl}/api/sync`, {
      headers: this.headers,
    });

    if (!response.ok) {
      throw new VaultAuthError(
        this.baseUrl,
        `sync failed with HTTP ${response.status} (token may be expired)`,
      );
    }

    const syncData = (await response.json()) as {
      ciphers: Array<{
        name: string;
        login?: { password?: string };
        notes?: string;
      }>;
    };

    for (const cipher of syncData.ciphers ?? []) {
      if (cipher.name === path) {
        if (cipher.login?.password) return cipher.login.password;
        if (cipher.notes) return cipher.notes;
      }
    }

    throw new SecretNotFoundError(path);
  }
}

export async function getVaultSecret(path: string): Promise<string> {
  const client = await VaultClient.connect();
  return client.getSecret(path);
}
