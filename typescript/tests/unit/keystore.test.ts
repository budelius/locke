import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// keytar is a native module; mock it so the keystore module can be imported
// and exercised in any environment.
vi.mock("keytar", () => ({
  default: {
    getPassword: vi.fn(async () => null),
    setPassword: vi.fn(async () => {}),
    deletePassword: vi.fn(async () => {}),
    findCredentials: vi.fn(async () => []),
  },
}));

import {
  biometricEnabled,
  computeSessionHmac,
  getMachineId,
  getUsername,
  isInteractive,
  readBioSession,
  requireBiometric,
  resetBioCache,
  writeBioSession,
} from "../../src/keystore.js";

const ORIG_ENV = { ...process.env };

function setEnv(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

afterEach(() => {
  // Restore environment.
  for (const k of Object.keys(process.env)) {
    if (!(k in ORIG_ENV)) delete process.env[k];
  }
  Object.assign(process.env, ORIG_ENV);
  resetBioCache();
  vi.restoreAllMocks();
});

describe("biometricEnabled parsing", () => {
  it("defaults to true when unset", () => {
    delete process.env.LOCKE_USE_BIOMETRIC;
    expect(biometricEnabled()).toBe(true);
  });

  it.each(["false", "0", "no", "FALSE", "No", " 0 "])(
    "is disabled for %j",
    (val) => {
      process.env.LOCKE_USE_BIOMETRIC = val;
      expect(biometricEnabled()).toBe(false);
    },
  );

  it.each(["true", "1", "yes", "anything"])("is enabled for %j", (val) => {
    process.env.LOCKE_USE_BIOMETRIC = val;
    expect(biometricEnabled()).toBe(true);
  });
});

describe("computeSessionHmac", () => {
  it("matches a known precomputed value", () => {
    // Precomputed with both Node and Python (byte-for-byte identical):
    //   msg = "1700000000.5|test-machine-guid|tester"
    //   key = "test-machine-guid"
    const hmac = computeSessionHmac(1700000000.5, "test-machine-guid", "tester");
    expect(hmac).toBe(
      "462f149216c5789be1faa10ce0091458bfca80d28050f9b03d737d9a53fd86cb",
    );
  });

  it("formats whole-number timestamps like Python str(float)", () => {
    // verified_at as an integer must serialize with a trailing .0 so the
    // message matches Python's f"{verified_at}" rendering of a float.
    const a = computeSessionHmac(1700000000, "m", "u");
    const b = computeSessionHmac(1700000000.0, "m", "u");
    expect(a).toBe(b);
    // Different from a hypothetical no-".0" rendering:
    expect(a).not.toBe(computeSessionHmacRaw("1700000000", "m", "u"));
    expect(a).toBe(computeSessionHmacRaw("1700000000.0", "m", "u"));
  });
});

// Helper mirroring the internal message format for the assertion above.
function computeSessionHmacRaw(ts: string, machineId: string, username: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createHmac } = require("node:crypto");
  const msg = `${ts}|${machineId}|${username}`;
  return createHmac("sha256", Buffer.from(machineId, "utf8"))
    .update(Buffer.from(msg, "utf8"))
    .digest("hex");
}

describe("readBioSession", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "locke-bio-"));
    // Point the session dir at our temp dir on all platforms.
    // On non-Windows the dir is ~/.locke; on Windows it is %LOCALAPPDATA%/locke.
    // We override HOME/USERPROFILE and LOCALAPPDATA so getBioSessionDir resolves here.
    setEnv("HOME", dir);
    setEnv("USERPROFILE", dir);
    setEnv("LOCALAPPDATA", dir);
    resetBioCache();
  });

  afterEach(() => {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  function sessionPath(): string {
    // Mirror getBioSessionDir(): win32 => LOCALAPPDATA/locke, else HOME/.locke
    const base =
      process.platform === "win32"
        ? join(dir, "locke")
        : join(dir, ".locke");
    return join(base, "bio_session.json");
  }

  function writeSession(payload: Record<string, unknown>): void {
    // writeBioSession() creates the directory; reuse it to ensure it exists.
    writeBioSession();
    writeFileSync(sessionPath(), JSON.stringify(payload), "utf8");
  }

  it("accepts a valid freshly written session", () => {
    writeBioSession();
    expect(readBioSession()).toBe(true);
  });

  it("rejects a tampered HMAC", () => {
    const machineId = getMachineId();
    const username = getUsername();
    const verifiedAt = Date.now() / 1000;
    writeSession({
      verified_at: verifiedAt,
      machine_id: machineId,
      username,
      hmac: "00".repeat(32),
    });
    expect(readBioSession()).toBe(false);
  });

  it("rejects a wrong machine id", () => {
    const username = getUsername();
    const verifiedAt = Date.now() / 1000;
    const machineId = "some-other-machine";
    writeSession({
      verified_at: verifiedAt,
      machine_id: machineId,
      username,
      hmac: computeSessionHmac(verifiedAt, machineId, username),
    });
    expect(readBioSession()).toBe(false);
  });

  it("rejects an expired session", () => {
    const machineId = getMachineId();
    const username = getUsername();
    // verified_at far in the past; default TTL is 7 days.
    const verifiedAt = Date.now() / 1000 - 8 * 86400;
    writeSession({
      verified_at: verifiedAt,
      machine_id: machineId,
      username,
      hmac: computeSessionHmac(verifiedAt, machineId, username),
    });
    expect(readBioSession()).toBe(false);
  });

  it("returns false when no session file exists", () => {
    const p = sessionPath();
    if (existsSync(p)) rmSync(p);
    expect(readBioSession()).toBe(false);
  });

  it("write produces a parseable payload with all fields", () => {
    writeBioSession();
    const data = JSON.parse(readFileSync(sessionPath(), "utf8"));
    expect(data).toHaveProperty("verified_at");
    expect(data).toHaveProperty("machine_id");
    expect(data).toHaveProperty("username");
    expect(data).toHaveProperty("hmac");
  });
});

describe("requireBiometric degradation paths", () => {
  it("is a no-op when biometric is disabled", () => {
    process.env.LOCKE_USE_BIOMETRIC = "false";
    expect(() => requireBiometric()).not.toThrow();
  });

  it("is a no-op on Linux even when enabled", () => {
    process.env.LOCKE_USE_BIOMETRIC = "true";
    const orig = process.platform;
    Object.defineProperty(process, "platform", { value: "linux" });
    try {
      expect(() => requireBiometric()).not.toThrow();
    } finally {
      Object.defineProperty(process, "platform", { value: orig });
    }
  });

  it("is a no-op (warns) when non-interactive on Windows", () => {
    process.env.LOCKE_USE_BIOMETRIC = "true";
    // Isolate the session dir to an empty temp dir so no real persistent
    // session on this machine short-circuits the non-interactive path.
    const emptyDir = mkdtempSync(join(tmpdir(), "locke-bio-empty-"));
    setEnv("HOME", emptyDir);
    setEnv("USERPROFILE", emptyDir);
    setEnv("LOCALAPPDATA", emptyDir);
    resetBioCache();

    const origPlatform = process.platform;
    const origTty = process.stdin.isTTY;
    Object.defineProperty(process, "platform", { value: "win32" });
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() => requireBiometric()).not.toThrow();
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining("Non-interactive shell detected"),
      );
    } finally {
      Object.defineProperty(process, "platform", { value: origPlatform });
      Object.defineProperty(process.stdin, "isTTY", {
        value: origTty,
        configurable: true,
      });
      try {
        rmSync(emptyDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    }
  });

  it("passes through on macOS (Touch ID not implemented)", () => {
    process.env.LOCKE_USE_BIOMETRIC = "true";
    const orig = process.platform;
    Object.defineProperty(process, "platform", { value: "darwin" });
    try {
      expect(() => requireBiometric()).not.toThrow();
    } finally {
      Object.defineProperty(process, "platform", { value: orig });
    }
  });
});

describe("isInteractive", () => {
  const origTty = process.stdin.isTTY;

  afterEach(() => {
    Object.defineProperty(process.stdin, "isTTY", {
      value: origTty,
      configurable: true,
    });
  });

  it("is false when stdin is not a TTY", () => {
    Object.defineProperty(process.stdin, "isTTY", {
      value: false,
      configurable: true,
    });
    expect(isInteractive()).toBe(false);
  });

  it("is true when stdin is a TTY", () => {
    Object.defineProperty(process.stdin, "isTTY", {
      value: true,
      configurable: true,
    });
    expect(isInteractive()).toBe(true);
  });
});
