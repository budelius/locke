/**
 * `locke vault import` — push secrets to Vaultwarden via API.
 *
 * Mirrors the Python reference `python/locke/cli/vault_import.py`. Uses the
 * Bitwarden-compatible API to create or update secrets directly (no duplicates
 * on repeated imports).
 *
 * Subcommands:
 *   csv <file>                       — import a Bitwarden CSV export
 *   azure --tenant <slug> [...]      — Azure tenant credentials
 *   kv --folder <path> [...]         — arbitrary key-value secrets
 *   gcp <files...> --tenant <slug>   — GCP service-account / OAuth files
 *
 * Shared options: --dry-run, --export-json <path>, --env-file <path>.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";

import { parseJsonc } from "../jsonc.js";
import { parseCsvDict } from "../csv.js";
import { VaultClient } from "../vault.js";

// ── Types ────────────────────────────────────────────────────────────────────

export interface ImportSecret {
  name: string;
  folder: string;
  value: string;
  username?: string | null;
  uri?: string | null;
  notes?: string | null;
  type?: string;
}

interface CommonOpts {
  dryRun?: boolean;
  exportJson?: string;
  envFile?: string;
}

// ── Azure field definitions ──────────────────────────────────────────────────

const AZURE_FIELDS: Array<[string, string, string]> = [
  ["azure-tenant-id", "AZURE_TENANT_ID", "Azure AD tenant ID"],
  ["azure-client-id", "AZURE_CLIENT_ID", "Azure AD app client ID"],
  ["azure-client-secret", "AZURE_CLIENT_SECRET", "Azure AD app client secret"],
  ["azure-user-principal-name", "AZURE_USER_PRINCIPAL_NAME", "User principal name"],
];

/**
 * Return Vaultwarden secret names for the given Azure account index.
 *
 * Index 1 (default):  azure-tenant-id, azure-client-id, ...
 * Index 2+:           azure-2-tenant-id, azure-2-client-id, ...
 */
export function azureSecretNames(index: number): string[] {
  const baseNames = AZURE_FIELDS.map((f) => f[0]);
  if (index === 1) return baseNames;
  const prefix = `azure-${index}-`;
  return baseNames.map((name) => prefix + name.slice(name.indexOf("-") + 1));
}

/**
 * Convert SCREAMING_SNAKE_CASE env var to kebab-case secret name.
 *
 * BUNNY_API_KEY -> bunny-api-key
 * HETZNER_S3_ACCESS_KEY -> hetzner-s3-access-key
 */
export function envToSecretName(envKey: string): string {
  return envKey.toLowerCase().replace(/_/g, "-");
}

/** Mask a value: 4 chars + ... + 4 chars; "****" when <= 8 chars. */
export function mask(value: string): string {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

// ── GCP detection / entry building ───────────────────────────────────────────

const GCP_SA_TYPE = "service_account";
const GCP_OAUTH_KEYS = ["web", "installed"];

/** Detect GCP credential file type: 'service_account', 'oauth_client', or null. */
export function detectGcpType(
  data: Record<string, unknown>,
): "service_account" | "oauth_client" | null {
  if (data.type === GCP_SA_TYPE) return "service_account";
  if (GCP_OAUTH_KEYS.some((k) => k in data)) return "oauth_client";
  return null;
}

/** Build a vault entry from a GCP service-account key file. */
export function gcpEntryFromSa(
  data: Record<string, unknown>,
  project: string,
  tenant: string,
): ImportSecret {
  const clientEmail = (data.client_email as string) ?? "";
  const accountName = clientEmail.includes("@")
    ? clientEmail.split("@")[0]
    : "unknown";
  const gcpProject = (data.project_id as string) ?? "unknown";

  return {
    name: `${project}/${tenant}/gcp-sa-${accountName}`,
    folder: `${project}/${tenant}`,
    value: JSON.stringify(data, null, 2),
    username: clientEmail,
    uri: (data.token_uri as string) ?? null,
    notes: `GCP service account key for ${clientEmail} (project: ${gcpProject})`,
  };
}

/** Build a vault entry from a GCP OAuth client-secret file. */
export function gcpEntryFromOauth(
  data: Record<string, unknown>,
  project: string,
  tenant: string,
): ImportSecret {
  const wrapperKey = GCP_OAUTH_KEYS.find((k) => k in data);
  const inner = (wrapperKey
    ? (data[wrapperKey] as Record<string, unknown>)
    : data) as Record<string, unknown>;
  const clientId = (inner.client_id as string) ?? "unknown";
  const gcpProject = (inner.project_id as string) ?? "unknown";

  return {
    name: `${project}/${tenant}/gcp-oauth-${gcpProject}`,
    folder: `${project}/${tenant}`,
    value: JSON.stringify(data, null, 2),
    username: clientId,
    uri: (inner.token_uri as string) ?? null,
    notes: `GCP OAuth ${wrapperKey ?? "unknown"} client (project: ${gcpProject})`,
  };
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/** Load a .env file into process.env (best-effort, no override). */
export function loadDotenv(path: string): void {
  if (!existsSync(path)) return;
  const content = readFileSync(path, "utf8");
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const eq = line.indexOf("=");
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      value.length >= 2 &&
      value[0] === value[value.length - 1] &&
      (value[0] === '"' || value[0] === "'")
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

/**
 * Export secrets as Bitwarden-compatible JSON.
 *
 * Produces `{ encrypted: false, folders, items }` identical in shape to the
 * Python `_export_bitwarden_json` / `_export_bitwarden_json_full` output.
 */
export function exportBitwardenJson(
  secrets: ImportSecret[],
  path: string,
): { items: number; folders: number } {
  const foldersSeen: Record<string, number> = {};
  const folders: Array<{ name: string }> = [];
  const items: Array<Record<string, unknown>> = [];

  for (const s of secrets) {
    const folder = s.folder ?? "";
    if (folder && !(folder in foldersSeen)) {
      foldersSeen[folder] = folders.length;
      folders.push({ name: folder });
    }

    const uris = s.uri ? [{ match: null, uri: s.uri }] : [];
    items.push({
      type: 1,
      name: s.name,
      folderId: folder in foldersSeen ? foldersSeen[folder] : null,
      login: {
        username: s.username ?? "",
        password: s.value ?? "",
        uris,
      },
      notes: s.notes ?? null,
      favorite: false,
      reprompt: 0,
    });
  }

  const exportObj = {
    encrypted: false,
    folders: folders.map((f, i) => ({ id: String(i + 1), name: f.name })),
    items,
  };

  writeFileSync(path, JSON.stringify(exportObj, null, 2) + "\n", {
    encoding: "utf8",
  });

  return { items: items.length, folders: folders.length };
}

/** Connect, sync, and create/update each secret via the API (no duplicates). */
async function importViaApi(secrets: ImportSecret[]): Promise<void> {
  process.stderr.write("Connecting to Vaultwarden...\n");
  let client: VaultClient;
  try {
    client = await VaultClient.connect();
  } catch (exc) {
    process.stderr.write(`Error connecting to vault: ${(exc as Error).message}\n`);
    process.exitCode = 1;
    return;
  }

  process.stderr.write("Syncing vault to check for existing secrets...\n");
  await client.sync();

  let created = 0;
  let updated = 0;
  for (const s of secrets) {
    const action = await client.setSecret(s.name, s.value, {
      folder: s.folder || null,
      username: s.username ?? null,
      uri: s.uri ?? null,
      notes: s.notes ?? null,
    });
    if (action === "updated") {
      process.stdout.write(`  [UPD] ${s.name}\n`);
      updated += 1;
    } else {
      process.stdout.write(`  [NEW] ${s.name}\n`);
      created += 1;
    }
  }

  process.stdout.write(`\nDone: ${created} created, ${updated} updated.\n`);
}

/** Dispatch to export, dry-run, or API import. */
async function runImport(
  secrets: ImportSecret[],
  opts: CommonOpts,
): Promise<void> {
  if (secrets.length === 0) {
    process.stderr.write("No secrets to import. Exiting.\n");
    process.exitCode = 1;
    return;
  }

  if (opts.exportJson) {
    const { items, folders } = exportBitwardenJson(secrets, opts.exportJson);
    process.stdout.write(`Bitwarden JSON written to: ${opts.exportJson}\n`);
    process.stdout.write(`  ${items} item(s), ${folders} folder(s)\n`);
    process.stdout.write(`\n  DELETE this file after import: rm ${opts.exportJson}\n`);
    return;
  }

  if (opts.dryRun) {
    process.stdout.write(
      "Dry run — no changes made. Secrets that would be imported:\n",
    );
    for (const s of secrets) process.stdout.write(`  ${s.name}\n`);
    return;
  }

  await importViaApi(secrets);
}

// ── Subcommand actions ───────────────────────────────────────────────────────

async function csvAction(csvFile: string, opts: CommonOpts): Promise<void> {
  loadDotenv(opts.envFile || ".env");

  if (!existsSync(csvFile)) {
    process.stderr.write(`CSV file not found: ${csvFile}\n`);
    process.exitCode = 1;
    return;
  }

  const rows = parseCsvDict(readFileSync(csvFile, "utf8"));
  if (rows.length === 0) {
    process.stderr.write("CSV file is empty.\n");
    process.exitCode = 1;
    return;
  }

  process.stdout.write(`\nParsed ${rows.length} entry/entries from ${csvFile}\n`);
  process.stdout.write("=".repeat(60) + "\n");

  const secrets: ImportSecret[] = [];
  for (const row of rows) {
    const name = (row.name ?? "").trim();
    const folder = (row.folder ?? "").trim();
    const password = (row.login_password ?? "").trim();
    const username = (row.login_username ?? "").trim();
    const uri = (row.login_uri ?? "").trim();
    const notes = (row.notes ?? "").trim();
    const itemType = (row.type ?? "login").trim();

    if (!name) {
      process.stdout.write("  [SKIP] row with empty name\n");
      continue;
    }

    const display = password ? mask(password) : "(no password)";
    process.stdout.write(`  [OK]   ${name} = ${display}\n`);

    secrets.push({
      name,
      folder,
      value: password,
      username,
      uri,
      notes: notes || null,
      type: itemType,
    });
  }

  process.stdout.write("\n");

  if (secrets.length === 0) {
    process.stderr.write("No secrets to import.\n");
    process.exitCode = 1;
    return;
  }

  await runImport(secrets, opts);
}

interface AzureOpts extends CommonOpts {
  tenant: string;
  project: string;
  accountIndex: number;
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
  azureUserPrincipalName?: string;
}

async function azureAction(opts: AzureOpts): Promise<void> {
  loadDotenv(opts.envFile || ".env");

  const cliOverrides: Record<string, string | undefined> = {
    AZURE_TENANT_ID: opts.azureTenantId,
    AZURE_CLIENT_ID: opts.azureClientId,
    AZURE_CLIENT_SECRET: opts.azureClientSecret,
    AZURE_USER_PRINCIPAL_NAME: opts.azureUserPrincipalName,
  };

  const secretNames = azureSecretNames(opts.accountIndex);
  const folder = `${opts.project}/${opts.tenant}`;

  const label =
    opts.accountIndex > 1 ? `account #${opts.accountIndex}` : "default account";
  process.stdout.write(
    `\nAzure credentials for tenant '${opts.tenant}' (${label})\n`,
  );
  process.stdout.write("=".repeat(60) + "\n");

  const secrets: ImportSecret[] = [];
  const missing: string[] = [];

  for (let i = 0; i < AZURE_FIELDS.length; i++) {
    const envVar = AZURE_FIELDS[i][1];
    const secretName = secretNames[i];
    const itemName = `${opts.project}/${opts.tenant}/${secretName}`;

    let value = cliOverrides[envVar];
    if (!value && opts.accountIndex <= 1) {
      value = process.env[envVar] ?? "";
    }

    if (value) {
      process.stdout.write(
        `  [OK]   ${itemName} = ${mask(value)} (${value.length} chars)\n`,
      );
      secrets.push({ name: itemName, folder, value });
    } else {
      process.stdout.write(`  [MISS] ${itemName} (not set)\n`);
      missing.push(secretName);
    }
  }

  process.stdout.write("\n");

  if (missing.length > 0) {
    process.stdout.write(
      `WARNING: ${missing.length} secret(s) missing: ${missing.join(", ")}\n`,
    );
    if (opts.accountIndex > 1) {
      process.stdout.write(
        "For additional accounts, pass values via --azure-* flags.\n",
      );
    } else {
      process.stdout.write("Set them in your .env file or pass via --azure-* flags.\n");
    }
    process.stdout.write("\n");
  }

  await runImport(secrets, opts);
}

interface KvOpts extends CommonOpts {
  folder: string;
  fromEnv: string[];
  fromFile?: string;
  secret: string[]; // flat [name, value, name, value, ...]
}

async function kvAction(opts: KvOpts): Promise<void> {
  loadDotenv(opts.envFile || ".env");

  process.stdout.write(`\nSecrets for folder '${opts.folder}'\n`);
  process.stdout.write("=".repeat(60) + "\n");

  const secrets: ImportSecret[] = [];
  const missing: string[] = [];

  // From env vars
  for (const envKey of opts.fromEnv) {
    const value = process.env[envKey] ?? "";
    const secretName = envToSecretName(envKey);
    const itemName = `${opts.folder}/${secretName}`;
    if (value) {
      process.stdout.write(
        `  [OK]   ${itemName} = ${mask(value)} (${value.length} chars)\n`,
      );
      secrets.push({ name: itemName, folder: opts.folder, value });
    } else {
      process.stdout.write(`  [MISS] ${itemName} (${envKey} not set)\n`);
      missing.push(envKey);
    }
  }

  // From JSON file
  if (opts.fromFile) {
    const fileSecrets = parseJsonc(readFileSync(opts.fromFile, "utf8")) as Record<
      string,
      unknown
    >;
    for (const [secretName, rawValue] of Object.entries(fileSecrets)) {
      const itemName = `${opts.folder}/${secretName}`;
      const value = rawValue == null ? "" : String(rawValue);
      if (value) {
        process.stdout.write(
          `  [OK]   ${itemName} = ${mask(value)} (${value.length} chars)\n`,
        );
        secrets.push({ name: itemName, folder: opts.folder, value });
      } else {
        process.stdout.write(`  [MISS] ${itemName} (empty value in file)\n`);
        missing.push(secretName);
      }
    }
  }

  // Inline secrets (commander collects [name, value] pairs into a flat array)
  for (let i = 0; i + 1 < opts.secret.length; i += 2) {
    const secretName = opts.secret[i];
    const value = opts.secret[i + 1];
    const itemName = `${opts.folder}/${secretName}`;
    process.stdout.write(
      `  [OK]   ${itemName} = ${mask(value)} (${value.length} chars)\n`,
    );
    secrets.push({ name: itemName, folder: opts.folder, value });
  }

  process.stdout.write("\n");

  if (missing.length > 0) {
    process.stdout.write(
      `WARNING: ${missing.length} secret(s) missing: ${missing.join(", ")}\n`,
    );
    process.stdout.write("\n");
  }

  await runImport(secrets, opts);
}

interface GcpOpts extends CommonOpts {
  tenant: string;
  project: string;
}

async function gcpAction(files: string[], opts: GcpOpts): Promise<void> {
  loadDotenv(opts.envFile || ".env");

  process.stdout.write(`\nGCP credentials for tenant '${opts.tenant}'\n`);
  process.stdout.write("=".repeat(60) + "\n");

  const secrets: ImportSecret[] = [];
  const skipped: string[] = [];

  for (const filepath of files) {
    let data: Record<string, unknown>;
    try {
      data = parseJsonc(readFileSync(filepath, "utf8")) as Record<string, unknown>;
    } catch (exc) {
      process.stdout.write(`  [SKIP] ${filepath} — ${(exc as Error).message}\n`);
      skipped.push(filepath);
      continue;
    }

    const gcpType = detectGcpType(data);
    if (gcpType === null) {
      process.stdout.write(
        `  [SKIP] ${filepath} — not a recognised GCP credential file\n`,
      );
      skipped.push(filepath);
      continue;
    }

    let entry: ImportSecret;
    let label: string;
    if (gcpType === "service_account") {
      entry = gcpEntryFromSa(data, opts.project, opts.tenant);
      label = `service-account (${(data.client_email as string) ?? "?"})`;
    } else {
      const wrapper = GCP_OAUTH_KEYS.find((k) => k in data) ?? "?";
      entry = gcpEntryFromOauth(data, opts.project, opts.tenant);
      const inner = (data[wrapper] as Record<string, unknown>) ?? {};
      label = `oauth-${wrapper} (${(inner.project_id as string) ?? "?"})`;
    }

    process.stdout.write(
      `  [OK]   ${entry.name} — ${label} (${entry.value.length} chars)\n`,
    );
    secrets.push(entry);
  }

  process.stdout.write("\n");

  if (skipped.length > 0) {
    process.stdout.write(`WARNING: ${skipped.length} file(s) skipped.\n\n`);
  }

  await runImport(secrets, opts);
}

// ── Command wiring ───────────────────────────────────────────────────────────

function collect(value: string, prev: string[]): string[] {
  prev.push(value);
  return prev;
}

/** Build the `import` command group to attach under `locke vault`. */
export function buildVaultImportCommand(): Command {
  const cmd = new Command("import").description(
    "Import secrets into Vaultwarden (create or update, no duplicates).",
  );

  const addCommon = (c: Command): Command =>
    c
      .option("--dry-run", "Show what would be imported without making changes")
      .option(
        "--export-json <path>",
        "Export Bitwarden-compatible JSON to file instead of importing via API",
      )
      .option("--env-file <path>", "Path to .env file to read values from");

  addCommon(
    cmd
      .command("csv")
      .description("Import from a standard Bitwarden CSV file.")
      .argument("<file>", "Path to the CSV file"),
  ).action(async (file: string, opts: CommonOpts) => {
    await csvAction(file, opts);
  });

  addCommon(
    cmd
      .command("azure")
      .description("Import Azure tenant credentials into Vaultwarden.")
      .requiredOption("--tenant <slug>", "Tenant slug (e.g. mycompany)")
      .option("--project <name>", "Project prefix for vault folder", "myapp")
      .option("--account-index <n>", "Account index: 1=default, 2=second, ...", "1")
      .option("--azure-tenant-id <value>", "Azure AD tenant ID")
      .option("--azure-client-id <value>", "Azure AD app client ID")
      .option("--azure-client-secret <value>", "Azure AD app client secret")
      .option("--azure-user-principal-name <value>", "User principal name"),
  ).action(
    async (opts: {
      tenant: string;
      project: string;
      accountIndex: string;
      azureTenantId?: string;
      azureClientId?: string;
      azureClientSecret?: string;
      azureUserPrincipalName?: string;
    } & CommonOpts) => {
      await azureAction({
        ...opts,
        accountIndex: parseInt(opts.accountIndex, 10) || 1,
      });
    },
  );

  addCommon(
    cmd
      .command("kv")
      .description("Import arbitrary key-value secrets into Vaultwarden.")
      .requiredOption("--folder <path>", "Vault folder path (e.g. myapp/infra)")
      .option(
        "--from-env <VAR>",
        "Import an env var as a secret (repeatable)",
        collect,
        [] as string[],
      )
      .option(
        "--from-file <file>",
        'JSON file mapping secret names to values: {"bunny-api-key": "..."}',
      )
      .option(
        "--secret <values...>",
        "Inline secret: --secret <name> <value> (repeatable)",
        (val: string, prev: string[]) => {
          prev.push(val);
          return prev;
        },
        [] as string[],
      ),
  ).action(
    async (opts: {
      folder: string;
      fromEnv: string[];
      fromFile?: string;
      secret: string[];
    } & CommonOpts) => {
      await kvAction(opts);
    },
  );

  addCommon(
    cmd
      .command("gcp")
      .description("Import GCP credential JSON files into Vaultwarden.")
      .argument("<files...>", "GCP credential JSON file(s)")
      .requiredOption("--tenant <slug>", "Tenant slug (e.g. mycompany)")
      .option("--project <name>", "Project prefix for vault folder", "myapp"),
  ).action(
    async (
      files: string[],
      opts: { tenant: string; project: string } & CommonOpts,
    ) => {
      await gcpAction(files, opts);
    },
  );

  return cmd;
}
