/**
 * Credential resolution pipeline.
 *
 * Evaluates backends in priority order:
 * 1. OS Keystore
 * 2. Environment variable
 * 3. GitLab CLI (glab)
 * 4. .env file fallback (dev/staging only)
 */

import { detectEnvironment, isProduction } from "./env.js";
import { CredentialNotFoundError } from "./errors.js";
import { getCredential as keystoreGet } from "./keystore.js";

export interface Credential {
  name: string;
  value: string;
  source: "keystore" | "env_var" | "gitlab_cli" | "dotenv";
  resolvedAt: Date;
}

type Resolver = (name: string) => Promise<string | null>;

async function resolveFromKeystore(name: string): Promise<string | null> {
  try {
    return await keystoreGet(name);
  } catch {
    return null;
  }
}

async function resolveFromEnv(name: string): Promise<string | null> {
  return process.env[name] ?? null;
}

async function resolveFromGlab(name: string): Promise<string | null> {
  const { execFileSync } = await import("node:child_process");
  const { existsSync } = await import("node:fs");

  // Check if glab is available
  try {
    execFileSync("glab", ["version"], { stdio: "pipe", timeout: 5000 });
  } catch {
    return null;
  }

  // Try glab variable get
  try {
    const result = execFileSync("glab", ["variable", "get", name], {
      stdio: "pipe",
      timeout: 10000,
      encoding: "utf8",
    });
    if (result.trim()) return result.trim();
  } catch {
    // fall through
  }

  // For auth tokens, try glab auth token
  if (name.toUpperCase().includes("TOKEN") || name.toUpperCase().includes("GLAB")) {
    try {
      const result = execFileSync("glab", ["auth", "token"], {
        stdio: "pipe",
        timeout: 10000,
        encoding: "utf8",
      });
      if (result.trim()) return result.trim();
    } catch {
      // fall through
    }
  }

  return null;
}

async function resolveFromDotenv(name: string): Promise<string | null> {
  const { readFileSync, existsSync } = await import("node:fs");
  const { join } = await import("node:path");

  const dotenvPath = join(process.cwd(), ".env");
  if (!existsSync(dotenvPath)) return null;

  try {
    const content = readFileSync(dotenvPath, "utf8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
      const eqIndex = trimmed.indexOf("=");
      const key = trimmed.slice(0, eqIndex).trim();
      let value = trimmed.slice(eqIndex + 1).trim();
      // Remove surrounding quotes
      if (value.length >= 2 && value[0] === value[value.length - 1] && (value[0] === '"' || value[0] === "'")) {
        value = value.slice(1, -1);
      }
      if (key === name) {
        console.warn(`Credential '${name}' resolved from .env file (fallback). Consider storing in OS keystore instead.`);
        return value;
      }
    }
  } catch {
    // fall through
  }

  return null;
}

const BACKENDS: Array<{ name: string; resolver: Resolver }> = [
  { name: "keystore", resolver: resolveFromKeystore },
  { name: "env_var", resolver: resolveFromEnv },
  { name: "gitlab_cli", resolver: resolveFromGlab },
  { name: "dotenv", resolver: resolveFromDotenv },
];

export async function resolveCredential(name: string): Promise<Credential> {
  const backendsSearched: string[] = [];

  for (const { name: backendName, resolver } of BACKENDS) {
    if (backendName === "dotenv" && isProduction()) {
      continue;
    }

    backendsSearched.push(backendName);
    const value = await resolver(name);

    if (value !== null) {
      return {
        name,
        value,
        source: backendName as Credential["source"],
        resolvedAt: new Date(),
      };
    }
  }

  throw new CredentialNotFoundError(name, backendsSearched);
}
