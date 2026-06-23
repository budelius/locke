//! Locke — Unified credentials framework.

pub mod crypto;
pub mod env;
pub mod errors;
pub mod flatten;
pub mod jsonc;
pub mod keystore;
pub mod pipeline;
pub mod vault;

use std::collections::BTreeMap;
use std::path::Path;

use errors::LockeError;

pub use vault::{CredentialPair, VaultClient};

pub fn load_config(config_path: &Path) -> Result<BTreeMap<String, String>, LockeError> {
    let contents = std::fs::read_to_string(config_path)?;
    let encrypted: serde_json::Value = jsonc::parse_jsonc(&contents)?;

    let credential = pipeline::resolve_credential("LOCKE_ENCRYPTION_KEY")?;
    let plaintext = crypto::decrypt_config(&encrypted, &credential.value)?;
    flatten::flatten_config(&plaintext)
}
