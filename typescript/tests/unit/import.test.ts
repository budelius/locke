import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  azureSecretNames,
  detectGcpType,
  envToSecretName,
  exportBitwardenJson,
  gcpEntryFromOauth,
  gcpEntryFromSa,
  mask,
  type ImportSecret,
} from "../../src/cli/vault_import.js";

describe("envToSecretName", () => {
  it("converts SCREAMING_SNAKE_CASE to kebab-case", () => {
    expect(envToSecretName("BUNNY_API_KEY")).toBe("bunny-api-key");
    expect(envToSecretName("HETZNER_S3_ACCESS_KEY")).toBe("hetzner-s3-access-key");
    expect(envToSecretName("TOKEN")).toBe("token");
  });
});

describe("mask", () => {
  it("returns **** for short values (<= 8 chars)", () => {
    expect(mask("")).toBe("****");
    expect(mask("12345678")).toBe("****");
  });

  it("shows first 4 + ... + last 4 for longer values", () => {
    expect(mask("123456789")).toBe("1234...6789");
    expect(mask("sk_live_abcdef")).toBe("sk_l...cdef");
  });
});

describe("azureSecretNames indexing", () => {
  it("index 1 uses base names", () => {
    expect(azureSecretNames(1)).toEqual([
      "azure-tenant-id",
      "azure-client-id",
      "azure-client-secret",
      "azure-user-principal-name",
    ]);
  });

  it("index 2 inserts the index after 'azure-'", () => {
    expect(azureSecretNames(2)).toEqual([
      "azure-2-tenant-id",
      "azure-2-client-id",
      "azure-2-client-secret",
      "azure-2-user-principal-name",
    ]);
  });

  it("index 3 inserts the index after 'azure-'", () => {
    expect(azureSecretNames(3)).toEqual([
      "azure-3-tenant-id",
      "azure-3-client-id",
      "azure-3-client-secret",
      "azure-3-user-principal-name",
    ]);
  });
});

describe("detectGcpType", () => {
  it("detects service_account", () => {
    expect(detectGcpType({ type: "service_account" })).toBe("service_account");
  });

  it("detects oauth_client (web)", () => {
    expect(detectGcpType({ web: { client_id: "x" } })).toBe("oauth_client");
  });

  it("detects oauth_client (installed)", () => {
    expect(detectGcpType({ installed: { client_id: "x" } })).toBe("oauth_client");
  });

  it("returns null for unrecognised files", () => {
    expect(detectGcpType({ something: "else" })).toBeNull();
  });
});

describe("gcpEntryFromSa", () => {
  it("builds the expected entry shape", () => {
    const data = {
      type: "service_account",
      project_id: "my-gcp-project",
      client_email: "svc@my-gcp-project.iam.gserviceaccount.com",
      token_uri: "https://oauth2.googleapis.com/token",
      private_key: "KEY",
    };
    const entry = gcpEntryFromSa(data, "myapp", "acme");

    expect(entry.name).toBe("myapp/acme/gcp-sa-svc");
    expect(entry.folder).toBe("myapp/acme");
    expect(entry.username).toBe("svc@my-gcp-project.iam.gserviceaccount.com");
    expect(entry.uri).toBe("https://oauth2.googleapis.com/token");
    expect(entry.notes).toContain("GCP service account key for svc@");
    expect(entry.notes).toContain("project: my-gcp-project");
    // value is the full JSON (pretty-printed, 2-space indent)
    expect(JSON.parse(entry.value)).toEqual(data);
    expect(entry.value).toBe(JSON.stringify(data, null, 2));
  });
});

describe("gcpEntryFromOauth", () => {
  it("builds the expected entry shape from a 'web' wrapper", () => {
    const data = {
      web: {
        client_id: "client-123.apps.googleusercontent.com",
        project_id: "my-oauth-project",
        token_uri: "https://oauth2.googleapis.com/token",
        client_secret: "SECRET",
      },
    };
    const entry = gcpEntryFromOauth(data, "myapp", "acme");

    expect(entry.name).toBe("myapp/acme/gcp-oauth-my-oauth-project");
    expect(entry.folder).toBe("myapp/acme");
    expect(entry.username).toBe("client-123.apps.googleusercontent.com");
    expect(entry.uri).toBe("https://oauth2.googleapis.com/token");
    expect(entry.notes).toContain("GCP OAuth web client");
    expect(entry.notes).toContain("project: my-oauth-project");
    expect(JSON.parse(entry.value)).toEqual(data);
  });

  it("handles an 'installed' wrapper", () => {
    const data = {
      installed: {
        client_id: "cid",
        project_id: "proj",
        token_uri: "https://t",
      },
    };
    const entry = gcpEntryFromOauth(data, "myapp", "acme");
    expect(entry.name).toBe("myapp/acme/gcp-oauth-proj");
    expect(entry.notes).toContain("GCP OAuth installed client");
  });
});

describe("exportBitwardenJson", () => {
  let dir: string;

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("writes the Bitwarden-compatible structure", () => {
    dir = mkdtempSync(join(tmpdir(), "locke-export-"));
    const path = join(dir, "out.json");

    const secrets: ImportSecret[] = [
      {
        name: "myapp/acme/azure-tenant-id",
        folder: "myapp/acme",
        value: "tenant-value",
        username: null,
        uri: null,
        notes: null,
      },
      {
        name: "myapp/acme/gcp-sa-svc",
        folder: "myapp/acme",
        value: '{"type":"service_account"}',
        username: "svc@example.com",
        uri: "https://oauth2.googleapis.com/token",
        notes: "a note",
      },
      {
        name: "other/folder/key",
        folder: "other/folder",
        value: "v2",
      },
    ];

    const result = exportBitwardenJson(secrets, path);
    expect(result.items).toBe(3);
    expect(result.folders).toBe(2);

    const raw = readFileSync(path, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    const obj = JSON.parse(raw);

    expect(obj.encrypted).toBe(false);
    expect(obj.folders).toEqual([
      { id: "1", name: "myapp/acme" },
      { id: "2", name: "other/folder" },
    ]);

    expect(obj.items).toHaveLength(3);

    const first = obj.items[0];
    expect(first.type).toBe(1);
    expect(first.name).toBe("myapp/acme/azure-tenant-id");
    expect(first.folderId).toBe(0);
    expect(first.login.username).toBe("");
    expect(first.login.password).toBe("tenant-value");
    expect(first.login.uris).toEqual([]);
    expect(first.notes).toBeNull();
    expect(first.favorite).toBe(false);
    expect(first.reprompt).toBe(0);

    const second = obj.items[1];
    expect(second.folderId).toBe(0);
    expect(second.login.username).toBe("svc@example.com");
    expect(second.login.uris).toEqual([
      { match: null, uri: "https://oauth2.googleapis.com/token" },
    ]);
    expect(second.notes).toBe("a note");

    const third = obj.items[2];
    expect(third.folderId).toBe(1);
  });
});
