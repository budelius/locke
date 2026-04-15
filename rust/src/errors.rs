//! Locke error types.
//!
//! All errors avoid including secret values in messages.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LockeError {
    #[error("Credential '{name}' not found in backends: {}", backends_searched.join(", "))]
    CredentialNotFound {
        name: String,
        backends_searched: Vec<String>,
    },

    #[error("Decryption failed for '{file_path}'{}", if detail.is_empty() { String::new() } else { format!(": {}", detail) })]
    Decryption { file_path: String, detail: String },

    #[error("Invalid key: expected {expected_bytes} bytes, got {actual_bytes}")]
    InvalidKey {
        expected_bytes: usize,
        actual_bytes: usize,
    },

    #[error("Invalid config: {0}")]
    InvalidConfig(String),

    #[error("Key collision: '{key}' produced by both '{path_a}' and '{path_b}'")]
    Collision {
        key: String,
        path_a: String,
        path_b: String,
    },

    #[error("Vault authentication failed for '{vault_url}'{}", if detail.is_empty() { String::new() } else { format!(": {}", detail) })]
    VaultAuth { vault_url: String, detail: String },

    #[error("Vault secret not found: '{path}'")]
    SecretNotFound { path: String },

    #[error("Keystore unavailable on {platform}: {service}")]
    KeystoreUnavailable { platform: String, service: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, LockeError>;
