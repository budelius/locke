//! Locke CLI entrypoint (Rust).

mod vault_import;

use std::path::Path;
use std::process;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "locke", version, about = "Unified credentials framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypt, flatten, and output config as environment variables
    Env {
        #[arg(long, default_value = ".locke/config.encrypted.json")]
        config: String,
        #[arg(long, default_value = "shell")]
        format: String,
    },
    /// Decrypt an encrypted config file
    Decrypt {
        #[arg(long, default_value = ".locke/config.encrypted.json")]
        config: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Encrypt a plaintext config file
    Encrypt {
        #[arg(long, default_value = ".locke/config.json")]
        config: String,
        #[arg(long, default_value = ".locke/config.encrypted.json")]
        output: String,
    },
    /// Vaultwarden secret operations
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// Manage OS keystore credentials
    Keystore {
        #[command(subcommand)]
        command: KeystoreCommands,
    },
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Retrieve a secret from Vaultwarden by path
    Get(VaultGetArgs),
    /// Create or update a Vaultwarden secret by path
    Set(VaultSetArgs),
    /// Import secrets into Vaultwarden (create or update, no duplicates)
    Import {
        #[command(subcommand)]
        command: VaultImportCommands,
    },
}

#[derive(Subcommand)]
enum VaultImportCommands {
    /// Import from a standard Bitwarden CSV file
    Csv(ImportCsvArgs),
    /// Import Azure tenant credentials
    Azure(ImportAzureArgs),
    /// Import arbitrary key-value secrets
    Kv(ImportKvArgs),
    /// Import GCP credential JSON files
    Gcp(ImportGcpArgs),
}

#[derive(Args)]
struct ImportCsvArgs {
    /// Path to the Bitwarden CSV file
    csv_file: String,
    /// Path to a .env file for vault connection vars
    #[arg(long)]
    env_file: Option<String>,
    /// Show what would be imported without making changes
    #[arg(long)]
    dry_run: bool,
    /// Convert to Bitwarden JSON file instead of importing via API
    #[arg(long = "export-json", value_name = "PATH")]
    export_json: Option<String>,
}

#[derive(Args)]
struct ImportAzureArgs {
    /// Tenant slug (e.g. mycompany)
    #[arg(long, required = true)]
    tenant: String,
    /// Project prefix for vault folder
    #[arg(long, default_value = "myapp")]
    project: String,
    /// Account index: 1=default, 2=second, ...
    #[arg(long = "account-index", default_value_t = 1)]
    account_index: i64,
    #[arg(long = "azure-tenant-id")]
    azure_tenant_id: Option<String>,
    #[arg(long = "azure-client-id")]
    azure_client_id: Option<String>,
    #[arg(long = "azure-client-secret")]
    azure_client_secret: Option<String>,
    #[arg(long = "azure-user-principal-name")]
    azure_user_principal_name: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long = "export-json", value_name = "PATH")]
    export_json: Option<String>,
    #[arg(long)]
    env_file: Option<String>,
}

#[derive(Args)]
struct ImportKvArgs {
    /// Vault folder path (e.g. myapp/infra)
    #[arg(long, required = true)]
    folder: String,
    /// Import an env var as a secret (repeatable). Name derived from the var.
    #[arg(long = "from-env", value_name = "VAR")]
    from_env: Vec<String>,
    /// JSON file mapping secret names to values
    #[arg(long = "from-file", value_name = "FILE")]
    from_file: Option<String>,
    /// Inline secret: --secret <name> <value> (repeatable)
    #[arg(long = "secret", value_names = ["NAME", "VALUE"], num_args = 2)]
    secret: Vec<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long = "export-json", value_name = "PATH")]
    export_json: Option<String>,
    #[arg(long)]
    env_file: Option<String>,
}

#[derive(Args)]
struct ImportGcpArgs {
    /// GCP credential JSON files
    #[arg(required = true)]
    files: Vec<String>,
    /// Tenant slug (e.g. mycompany)
    #[arg(long, required = true)]
    tenant: String,
    /// Project prefix for vault folder
    #[arg(long, default_value = "myapp")]
    project: String,
    #[arg(long)]
    dry_run: bool,
    #[arg(long = "export-json", value_name = "PATH")]
    export_json: Option<String>,
    #[arg(long)]
    env_file: Option<String>,
}

#[derive(Subcommand)]
enum KeystoreCommands {
    /// Read a credential from the OS keystore
    Get { name: String },
    /// Write a credential to the OS keystore
    Set {
        name: String,
        #[arg(long)]
        value: Option<String>,
    },
    /// Remove a credential from the OS keystore
    Delete { name: String },
    /// Migrate credentials from legacy naming to the Locke namespace
    Migrate {
        /// Locke credential name to migrate (repeatable)
        #[arg(long = "name")]
        names: Vec<String>,
        /// Delete the legacy entry after migrating
        #[arg(long = "delete-legacy")]
        delete_legacy: bool,
        /// Show what would be migrated without changing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Reset the in-memory and persistent biometric session
    BioReset,
}

#[derive(Args)]
struct VaultGetArgs {
    /// Secret path ({project}/{tenant}/{name})
    path: String,
    /// Which field(s) to print
    #[arg(long, default_value = "password")]
    field: VaultField,
}

#[derive(Args)]
struct VaultSetArgs {
    /// Secret path ({project}/{tenant}/{name})
    path: String,
    /// Username to store alongside the password
    #[arg(long)]
    username: Option<String>,
    /// Password / secret value
    #[arg(long)]
    password: Option<String>,
    /// Folder to file the secret under (defaults to the path prefix)
    #[arg(long)]
    folder: Option<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum VaultField {
    Password,
    Username,
    Both,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Env { config, format } => {
            match locke::load_config(Path::new(&config)) {
                Ok(flat) => {
                    for (key, value) in &flat {
                        match format.as_str() {
                            "json" => {} // handled below
                            "dotenv" => println!("{key}={value}"),
                            _ => println!("export {key}='{value}'"),
                        }
                    }
                    if format == "json" {
                        let json = serde_json::to_string_pretty(
                            &flat.into_iter().collect::<std::collections::HashMap<_, _>>(),
                        )
                        .unwrap();
                        println!("{json}");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }
        Commands::Decrypt { config, output } => {
            let contents = match std::fs::read_to_string(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            let encrypted: serde_json::Value = match locke::jsonc::parse_jsonc(&contents) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: Invalid JSON/JSONC: {e}");
                    process::exit(1);
                }
            };

            let cred = match locke::pipeline::resolve_credential("LOCKE_ENCRYPTION_KEY") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };

            match locke::crypto::decrypt_config(&encrypted, &cred.value) {
                Ok(plaintext) => {
                    let json = serde_json::to_string_pretty(&plaintext).unwrap();
                    if let Some(out_path) = output {
                        std::fs::write(&out_path, &json).unwrap();
                        eprintln!("Decrypted config written to {out_path}");
                    } else {
                        println!("{json}");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }
        Commands::Encrypt {
            config,
            output,
        } => {
            let contents = match std::fs::read_to_string(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            // parse_jsonc accepts plain JSON and JSONC (comments + trailing
            // commas), so annotated config files encrypt without pre-stripping.
            let plaintext: serde_json::Value = match locke::jsonc::parse_jsonc(&contents) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: Invalid JSON/JSONC: {e}");
                    process::exit(1);
                }
            };

            let cred = match locke::pipeline::resolve_credential("LOCKE_ENCRYPTION_KEY") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };

            match locke::crypto::encrypt_config(&plaintext, &cred.value) {
                Ok(encrypted) => {
                    let json = serde_json::to_string_pretty(&encrypted).unwrap();
                    std::fs::write(&output, &json).unwrap();
                    eprintln!("Encrypted config written to {output}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }
        Commands::Vault { command } => run_vault(command),
        Commands::Keystore { command } => run_keystore(command),
    }
}

fn run_vault(command: VaultCommands) {
    match command {
        VaultCommands::Import { command } => run_vault_import(command),
        VaultCommands::Get(args) => {
            let mut client = match locke::VaultClient::connect() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            match args.field {
                VaultField::Password => match client.get_secret(&args.path) {
                    Ok(value) => println!("{value}"),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        process::exit(1);
                    }
                },
                VaultField::Username | VaultField::Both => {
                    match client.get_secret_pair(&args.path) {
                        Ok(pair) => match args.field {
                            VaultField::Username => {
                                println!("{}", pair.username.unwrap_or_default())
                            }
                            VaultField::Both => println!(
                                "{}:{}",
                                pair.username.unwrap_or_default(),
                                pair.password
                            ),
                            VaultField::Password => unreachable!(),
                        },
                        Err(e) => {
                            eprintln!("Error: {e}");
                            process::exit(1);
                        }
                    }
                }
            }
        }
        VaultCommands::Set(args) => {
            let mut client = match locke::VaultClient::connect() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            let result = if args.username.is_some() {
                client.set_secret_pair(
                    &args.path,
                    args.username.as_deref(),
                    args.password.as_deref(),
                    args.folder.as_deref(),
                    None,
                    None,
                )
            } else {
                client.set_secret(
                    &args.path,
                    args.password.as_deref(),
                    args.folder.as_deref(),
                    None,
                    None,
                    None,
                )
            };
            match result {
                Ok(action) => eprintln!("Vault secret {} {}", args.path, action),
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }
    }
}

fn run_vault_import(command: VaultImportCommands) {
    match command {
        VaultImportCommands::Csv(a) => vault_import::run_csv(
            &a.csv_file,
            a.env_file.as_deref(),
            a.dry_run,
            a.export_json.as_deref(),
        ),
        VaultImportCommands::Azure(a) => vault_import::run_azure(
            &a.tenant,
            &a.project,
            a.account_index,
            a.azure_tenant_id.as_deref(),
            a.azure_client_id.as_deref(),
            a.azure_client_secret.as_deref(),
            a.azure_user_principal_name.as_deref(),
            a.dry_run,
            a.export_json.as_deref(),
            a.env_file.as_deref(),
        ),
        VaultImportCommands::Kv(a) => {
            // --secret pairs arrive as a flat Vec; chunk into (name, value).
            let inline: Vec<(String, String)> = a
                .secret
                .chunks_exact(2)
                .map(|c| (c[0].clone(), c[1].clone()))
                .collect();
            vault_import::run_kv(
                &a.folder,
                &a.from_env,
                a.from_file.as_deref(),
                &inline,
                a.dry_run,
                a.export_json.as_deref(),
                a.env_file.as_deref(),
            )
        }
        VaultImportCommands::Gcp(a) => vault_import::run_gcp(
            &a.files,
            &a.tenant,
            &a.project,
            a.dry_run,
            a.export_json.as_deref(),
            a.env_file.as_deref(),
        ),
    }
}

fn run_keystore(command: KeystoreCommands) {
    use locke::keystore;

    match command {
        KeystoreCommands::Get { name } => match keystore::get_credential(&name) {
            Ok(Some(value)) => println!("{value}"),
            Ok(None) => {
                eprintln!("Credential '{name}' not found in keystore");
                process::exit(1);
            }
            Err(e @ (locke::errors::LockeError::BiometricDenied { .. }
            | locke::errors::LockeError::BiometricUnavailable { .. })) => {
                eprintln!("Biometric error: {e}");
                process::exit(3);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(2);
            }
        },
        KeystoreCommands::Set { name, value } => {
            let value = match value {
                Some(v) => v,
                None => {
                    eprintln!("Error: Provide --value");
                    process::exit(1);
                }
            };
            match keystore::set_credential(&name, &value) {
                Ok(()) => eprintln!("Credential '{name}' stored in keystore"),
                Err(e @ (locke::errors::LockeError::BiometricDenied { .. }
                | locke::errors::LockeError::BiometricUnavailable { .. })) => {
                    eprintln!("Biometric error: {e}");
                    process::exit(3);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            }
        }
        KeystoreCommands::Delete { name } => match keystore::delete_credential(&name) {
            Ok(()) => eprintln!("Credential '{name}' deleted from keystore"),
            Err(e @ (locke::errors::LockeError::BiometricDenied { .. }
            | locke::errors::LockeError::BiometricUnavailable { .. })) => {
                eprintln!("Biometric error: {e}");
                process::exit(3);
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        },
        KeystoreCommands::Migrate {
            names,
            delete_legacy,
            dry_run,
        } => run_keystore_migrate(names, delete_legacy, dry_run),
        KeystoreCommands::BioReset => {
            let removed = keystore::invalidate_bio_session();
            if removed {
                eprintln!("Biometric session invalidated.");
            } else {
                eprintln!("No biometric session to invalidate (in-memory cache cleared).");
            }
        }
    }
}

fn run_keystore_migrate(names: Vec<String>, delete_legacy: bool, dry_run: bool) {
    use locke::keystore;

    let name_list: Option<Vec<String>> = if names.is_empty() { None } else { Some(names) };

    if dry_run {
        let legacy = match keystore::find_legacy_credentials(name_list.as_deref()) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        };
        if legacy.is_empty() {
            println!("No legacy credentials found.");
            return;
        }
        for entry in legacy {
            let status = if entry.already_migrated {
                " (already in locke)"
            } else {
                ""
            };
            println!(
                "  {} <- target={:?}, user={:?}{status}",
                entry.locke_name, entry.legacy_target, entry.legacy_username
            );
        }
        return;
    }

    let targets: Vec<String> = match &name_list {
        Some(n) => n.clone(),
        None => match keystore::find_legacy_credentials(None) {
            Ok(legacy) => legacy
                .into_iter()
                .filter(|e| !e.already_migrated)
                .map(|e| e.locke_name)
                .collect(),
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        },
    };

    if targets.is_empty() {
        println!("Nothing to migrate.");
        return;
    }

    let mut migrated = 0u32;
    for cred_name in targets {
        match keystore::migrate_credential(&cred_name, delete_legacy) {
            Ok(Some(source)) => {
                println!("  Migrated {cred_name} from {source}");
                migrated += 1;
            }
            Ok(None) => {
                eprintln!("  No legacy credential found for {cred_name}");
            }
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    }

    println!("\n{migrated} credential(s) migrated.");
}
