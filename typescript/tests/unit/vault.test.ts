import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SecretNotFoundError } from "../../src/errors.js";
import {
  CredentialPair,
  PLACEHOLDER_VALUE,
  VaultClient,
  decryptEncryptedString,
  decryptSymmetricKey,
  encryptString,
  hashPassword,
  isPlaceholder,
  makeMasterKey,
  stretchMasterKey,
} from "../../src/vault.js";

interface CipherVectors {
  master_key_derivation: {
    password: string;
    email: string;
    iterations: number;
    expected_master_key_hex: string;
  };
  stretch_master_key: {
    master_key_hex: string;
    expected_enc_key_hex: string;
    expected_mac_key_hex: string;
  };
  decrypt_cipher_string: {
    enc_key_hex: string;
    mac_key_hex: string;
    cipher_string: string;
    expected_plaintext: string;
  };
  decrypt_symmetric_key: {
    master_key_hex: string;
    encrypted_key: string;
    expected_enc_key_hex: string;
    expected_mac_key_hex: string;
  };
  roundtrip: {
    enc_key_hex: string;
    mac_key_hex: string;
    plaintext: string;
  };
}

const vectorsPath = fileURLToPath(
  new URL("../../../test-vectors/vault-cipher.json", import.meta.url),
);
const vectors: CipherVectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

const hex = (s: string) => Buffer.from(s, "hex");

describe("Bitwarden crypto (shared test vectors)", () => {
  it("makeMasterKey matches vector", () => {
    const v = vectors.master_key_derivation;
    const mk = makeMasterKey(v.password, v.email, v.iterations);
    expect(mk.toString("hex")).toBe(v.expected_master_key_hex);
  });

  it("stretchMasterKey matches enc/mac vectors", () => {
    const v = vectors.stretch_master_key;
    const { encKey, macKey } = stretchMasterKey(hex(v.master_key_hex));
    expect(encKey.toString("hex")).toBe(v.expected_enc_key_hex);
    expect(macKey.toString("hex")).toBe(v.expected_mac_key_hex);
  });

  it("decryptEncryptedString matches expected plaintext", () => {
    const v = vectors.decrypt_cipher_string;
    const out = decryptEncryptedString(
      v.cipher_string,
      hex(v.enc_key_hex),
      hex(v.mac_key_hex),
    );
    expect(out.toString("utf8")).toBe(v.expected_plaintext);
  });

  it("decryptSymmetricKey splits into enc/mac matching vectors", () => {
    const v = vectors.decrypt_symmetric_key;
    const [encKey, macKey] = decryptSymmetricKey(
      v.encrypted_key,
      hex(v.master_key_hex),
    );
    expect(encKey.toString("hex")).toBe(v.expected_enc_key_hex);
    expect(macKey.toString("hex")).toBe(v.expected_mac_key_hex);
  });

  it("encrypt -> decrypt roundtrip preserves plaintext", () => {
    const v = vectors.roundtrip;
    const encKey = hex(v.enc_key_hex);
    const macKey = hex(v.mac_key_hex);
    const enc = encryptString(v.plaintext, encKey, macKey);
    expect(enc.startsWith("2.")).toBe(true);
    const back = decryptEncryptedString(enc, encKey, macKey).toString("utf8");
    expect(back).toBe(v.plaintext);
  });

  it("decryptEncryptedString rejects a tampered MAC", () => {
    const v = vectors.decrypt_cipher_string;
    const tampered = v.cipher_string.slice(0, -2) + "AA";
    expect(() =>
      decryptEncryptedString(tampered, hex(v.enc_key_hex), hex(v.mac_key_hex)),
    ).toThrow();
  });

  it("hashPassword is deterministic base64", () => {
    const h1 = hashPassword("pw", "User@Example.com");
    const h2 = hashPassword("pw", "user@example.com");
    expect(h1).toBe(h2); // email lowercased
    expect(Buffer.from(h1, "base64").length).toBe(32);
  });
});

function newClient(): VaultClient {
  return new VaultClient(
    "https://vault.example",
    "token",
    Buffer.alloc(32, "e"),
    Buffer.alloc(32, "m"),
  );
}

describe("placeholder helpers", () => {
  it("PLACEHOLDER_VALUE and isPlaceholder", () => {
    expect(PLACEHOLDER_VALUE).toBe("FILL_ME");
    expect(isPlaceholder("FILL_ME")).toBe(true);
    expect(isPlaceholder("  FILL_ME  ")).toBe(true);
    expect(isPlaceholder("real-secret")).toBe(false);
    expect(isPlaceholder(null)).toBe(false);
  });
});

describe("VaultClient get/set with injected caches", () => {
  afterEach(() => vi.restoreAllMocks());

  it("getSecret warns for placeholder", async () => {
    const client = newClient();
    client._setTestState({ secrets: { "proj/dev/api_key": PLACEHOLDER_VALUE } });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(await client.getSecret("proj/dev/api_key")).toBe(PLACEHOLDER_VALUE);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("still a placeholder"),
    );
  });

  it("setSecret empty value writes placeholder", async () => {
    const client = newClient();
    let captured: Record<string, unknown> = {};
    client._setTestState({
      secrets: {},
      metadata: {},
      cipherIndex: async () => ({
        names: {},
        folders: { "proj/dev": "folder-id" },
        values: {},
        metadata: {},
      }),
      write: async (payload) => {
        captured = payload;
      },
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const action = await client.setSecret("proj/dev/api_key", "");

    expect(action).toBe("created");
    // password field is the encrypted placeholder; decode/decrypt it back.
    const login = captured.login as { password: string };
    const back = decryptEncryptedString(
      login.password,
      Buffer.alloc(32, "e"),
      Buffer.alloc(32, "m"),
    ).toString("utf8");
    expect(back).toBe(PLACEHOLDER_VALUE);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("written with placeholder"),
    );
  });

  it("getSecretPair returns both fields", async () => {
    const client = newClient();
    client._setTestState({
      secrets: { "proj/dev/db_login": "s3cret" },
      metadata: {
        "proj/dev/db_login": { username: "admin", uri: null, notes: null },
      },
    });

    const pair: CredentialPair = await client.getSecretPair("proj/dev/db_login");
    expect(pair.username).toBe("admin");
    expect(pair.password).toBe("s3cret");
  });

  it("getSecretPair returns null username when unset", async () => {
    const client = newClient();
    client._setTestState({
      secrets: { "proj/dev/api_key": "value" },
      metadata: {
        "proj/dev/api_key": { username: null, uri: null, notes: null },
      },
    });

    const pair = await client.getSecretPair("proj/dev/api_key");
    expect(pair.username).toBeNull();
    expect(pair.password).toBe("value");
  });

  it("getSecretPair throws for unknown path", async () => {
    const client = newClient();
    client._setTestState({ secrets: {}, metadata: {} });
    await expect(client.getSecretPair("proj/dev/missing")).rejects.toThrow(
      SecretNotFoundError,
    );
  });

  it("setSecretPair writes username + password and refreshes caches", async () => {
    const client = newClient();
    client._setTestState({
      secrets: {},
      metadata: {},
      cipherIndex: async () => ({
        names: {},
        folders: { "proj/dev": "fid" },
        values: {},
        metadata: {},
      }),
      write: async () => {},
    });

    const action = await client.setSecretPair(
      "proj/dev/db_login",
      "admin",
      "s3cret",
    );
    expect(action).toBe("created");

    const pair = await client.getSecretPair("proj/dev/db_login");
    expect(pair.username).toBe("admin");
    expect(pair.password).toBe("s3cret");
  });
});
