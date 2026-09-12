#!/usr/bin/env node
/**
 * Locke CLI entrypoint.
 *
 * Thin wrapper around library functions — no business logic here.
 */

import { createRequire } from "node:module";

import { Command } from "commander";

import { loadConfig } from "../index.js";
import {
  getVaultSecret,
  getVaultSecretPair,
  setVaultSecret,
  setVaultSecretPair,
} from "../vault.js";
import { buildVaultImportCommand } from "./vault_import.js";
import { buildKeystoreCommand } from "./keystore.js";

const require = createRequire(import.meta.url);
const { version } = require("../../package.json") as { version: string };

const program = new Command();

program
  .name("locke")
  .description("Locke — Unified credentials framework.")
  .version(version);

program
  .command("env")
  .description("Decrypt, flatten, and output config as environment variables.")
  .argument("<config_path>", "Path to encrypted config file")
  .option("--key-name <name>", "Credential name for the encryption key", "LOCKE_ENCRYPTION_KEY")
  .option("--format <format>", "Output format: shell | json | dotenv", "shell")
  .action(async (configPath: string, opts: { keyName: string; format: string }) => {
    try {
      const flat = await loadConfig(configPath, opts.keyName);
      const keys = Object.keys(flat).sort();
      if (opts.format === "json") {
        process.stdout.write(JSON.stringify(flat, keys, 2) + "\n");
      } else if (opts.format === "dotenv") {
        for (const key of keys) process.stdout.write(`${key}=${flat[key]}\n`);
      } else {
        for (const key of keys) {
          process.stdout.write(`export ${key}=${shellQuote(flat[key])}\n`);
        }
      }
    } catch (exc) {
      process.stderr.write(`Error: ${(exc as Error).message}\n`);
      process.exitCode = 1;
    }
  });

const vault = program.command("vault").description("Manage Vaultwarden secrets.");

vault
  .command("get")
  .description("Retrieve a secret from Vaultwarden by path.")
  .argument("<path>")
  .option("--vault-url <url>", "Override vault URL")
  .option(
    "--field <field>",
    "Which field(s) to print: password | username | both",
    "password",
  )
  .action(
    async (
      path: string,
      opts: { vaultUrl?: string; field: string },
    ) => {
      if (opts.vaultUrl) process.env.LOCKE_VAULT_URL = opts.vaultUrl;
      try {
        if (opts.field === "password") {
          process.stdout.write(`${await getVaultSecret(path)}\n`);
        } else {
          const pair = await getVaultSecretPair(path);
          if (opts.field === "username") {
            process.stdout.write(`${pair.username ?? ""}\n`);
          } else {
            process.stdout.write(`${pair.username ?? ""}:${pair.password}\n`);
          }
        }
      } catch (exc) {
        process.stderr.write(`Error: ${(exc as Error).message}\n`);
        process.exitCode = 1;
      }
    },
  );

vault
  .command("set")
  .description("Create or update a Vaultwarden entry.")
  .argument("<path>")
  .option("--vault-url <url>", "Override vault URL")
  .option("--username <username>", "Username field of the entry")
  .option("--password <password>", "Password field of the entry")
  .option("--folder <folder>", "Vault folder (default: derived from the path prefix)")
  .action(
    async (
      path: string,
      opts: {
        vaultUrl?: string;
        username?: string;
        password?: string;
        folder?: string;
      },
    ) => {
      if (opts.vaultUrl) process.env.LOCKE_VAULT_URL = opts.vaultUrl;
      try {
        let action: string;
        if (opts.username !== undefined) {
          action = await setVaultSecretPair(path, opts.username, opts.password, {
            folder: opts.folder,
          });
        } else {
          action = await setVaultSecret(path, opts.password, {
            folder: opts.folder,
          });
        }
        process.stderr.write(`${action}: ${path}\n`);
      } catch (exc) {
        process.stderr.write(`Error: ${(exc as Error).message}\n`);
        process.exitCode = 1;
      }
    },
  );

vault.addCommand(buildVaultImportCommand());

program.addCommand(buildKeystoreCommand());

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:=-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

program.parseAsync(process.argv);
