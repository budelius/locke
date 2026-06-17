//! Locke CLI entrypoint (Rust).

use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};

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
    }
}
