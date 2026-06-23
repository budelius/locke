/**
 * `locke keystore` — manage OS keystore credentials.
 *
 * Mirrors the Python reference `python/locke/cli/keystore.py`. Adds a
 * `bio-reset` subcommand to invalidate the persistent biometric session.
 */

import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { Command } from "commander";

import {
  deleteCredential,
  findLegacyCredentials,
  getCredential,
  invalidateBioSession,
  migrateCredential,
  setCredential,
} from "../keystore.js";
import {
  BiometricDeniedError,
  BiometricUnavailableError,
  KeystoreUnavailableError,
} from "../errors.js";

/** Prompt for a value without echoing it to the terminal. */
function promptHidden(label: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const stdout = process.stdout as NodeJS.WriteStream & { _writeToOutput?: unknown };
    // Mute echoed characters.
    const originalWrite = stdout.write.bind(stdout);
    (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput =
      () => {};
    process.stdout.write(`${label}: `);
    rl.question("", (answer) => {
      rl.close();
      stdout.write = originalWrite;
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

/** Report a biometric/keystore error and set the appropriate exit code. */
function reportError(exc: unknown): void {
  if (exc instanceof BiometricDeniedError || exc instanceof BiometricUnavailableError) {
    process.stderr.write(`Biometric error: ${exc.message}\n`);
    process.exitCode = 3;
  } else if (exc instanceof KeystoreUnavailableError) {
    process.stderr.write(`Error: ${exc.message}\n`);
    process.exitCode = 2;
  } else {
    process.stderr.write(`Error: ${(exc as Error).message}\n`);
    process.exitCode = 1;
  }
}

/** Build the `keystore` command group to attach under the root program. */
export function buildKeystoreCommand(): Command {
  const cmd = new Command("keystore").description("Manage OS keystore credentials.");

  cmd
    .command("get")
    .description("Read a credential from the OS keystore.")
    .argument("<name>")
    .action(async (name: string) => {
      let value: string | null;
      try {
        value = await getCredential(name);
      } catch (exc) {
        reportError(exc);
        return;
      }
      if (value === null) {
        process.stderr.write(`Credential '${name}' not found in keystore\n`);
        process.exitCode = 1;
        return;
      }
      process.stdout.write(`${value}\n`);
    });

  cmd
    .command("set")
    .description("Write a credential to the OS keystore.")
    .argument("<name>")
    .option("--value <value>", "Credential value")
    .option("--prompt", "Prompt for value (no echo)")
    .action(async (name: string, opts: { value?: string; prompt?: boolean }) => {
      let value = opts.value;
      if (opts.prompt) {
        value = await promptHidden(`Enter value for '${name}'`);
      } else if (value === undefined) {
        process.stderr.write("Error: Provide --value or --prompt\n");
        process.exitCode = 1;
        return;
      }
      try {
        await setCredential(name, value);
        process.stderr.write(`Credential '${name}' stored in keystore\n`);
      } catch (exc) {
        reportError(exc);
        if (process.exitCode === 2) process.exitCode = 1; // set maps keystore err to 1
      }
    });

  cmd
    .command("delete")
    .description("Remove a credential from the OS keystore.")
    .argument("<name>")
    .action(async (name: string) => {
      try {
        await deleteCredential(name);
        process.stderr.write(`Credential '${name}' deleted from keystore\n`);
      } catch (exc) {
        reportError(exc);
        if (process.exitCode === 2) process.exitCode = 1;
      }
    });

  cmd
    .command("generate")
    .description("Generate a 32-byte random encryption key.")
    .argument("[name]", "Optional credential name to store the key under")
    .option("--print", "Print the key to stdout (even when storing)")
    .action(async (name: string | undefined, opts: { print?: boolean }) => {
      const key = randomBytes(32).toString("hex");
      if (name) {
        try {
          await setCredential(name, key);
          process.stderr.write(`Generated and stored '${name}' in keystore\n`);
        } catch (exc) {
          reportError(exc);
          if (process.exitCode === 2) process.exitCode = 1;
          return;
        }
        if (opts.print) process.stdout.write(`${key}\n`);
      } else {
        process.stdout.write(`${key}\n`);
      }
    });

  cmd
    .command("migrate")
    .description("Migrate credentials from legacy naming to the Locke namespace.")
    .argument("[name]", "Locke credential name to migrate")
    .option("--name <name...>", "Locke credential name(s) to migrate (repeatable)")
    .option("--delete-legacy", "Delete the legacy entry after migrating")
    .option("--dry-run", "Show what would be migrated without changing anything")
    .action(
      async (
        positional: string | undefined,
        opts: { name?: string[]; deleteLegacy?: boolean; dryRun?: boolean },
      ) => {
        const names = [...(opts.name ?? [])];
        if (positional) names.push(positional);
        const nameList = names.length > 0 ? names : null;

        if (opts.dryRun) {
          let legacy;
          try {
            legacy = await findLegacyCredentials(nameList);
          } catch (exc) {
            reportError(exc);
            return;
          }
          if (legacy.length === 0) {
            process.stdout.write("No legacy credentials found.\n");
            return;
          }
          for (const entry of legacy) {
            const status = entry.alreadyMigrated ? " (already in locke)" : "";
            process.stdout.write(
              `  ${entry.lockeName} <- target='${entry.legacyTarget}', ` +
                `user='${entry.legacyUsername}'${status}\n`,
            );
          }
          return;
        }

        let targets: string[];
        if (nameList) {
          targets = nameList;
        } else {
          let legacy;
          try {
            legacy = await findLegacyCredentials(null);
          } catch (exc) {
            reportError(exc);
            return;
          }
          targets = legacy.filter((e) => !e.alreadyMigrated).map((e) => e.lockeName);
        }

        if (targets.length === 0) {
          process.stdout.write("Nothing to migrate.\n");
          return;
        }

        let migrated = 0;
        for (const credName of targets) {
          let source: string | null;
          try {
            source = await migrateCredential(credName, {
              deleteLegacy: opts.deleteLegacy,
            });
          } catch (exc) {
            reportError(exc);
            if (process.exitCode === 2) process.exitCode = 1;
            return;
          }
          if (source) {
            process.stdout.write(`  Migrated ${credName} from ${source}\n`);
            migrated += 1;
          } else {
            process.stderr.write(`  No legacy credential found for ${credName}\n`);
          }
        }
        process.stdout.write(`\n${migrated} credential(s) migrated.\n`);
      },
    );

  cmd
    .command("bio-reset")
    .description("Invalidate the persistent biometric session.")
    .action(() => {
      if (invalidateBioSession()) {
        process.stdout.write("Biometric session invalidated.\n");
      } else {
        process.stdout.write("No active biometric session.\n");
      }
    });

  return cmd;
}
