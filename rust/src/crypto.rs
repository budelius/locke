//! AES-256-GCM encryption/decryption with PBKDF2-SHA256 KDF.
//!
//! Handles hex/base64 key encoding auto-detection for backward compatibility.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::errors::LockeError;

const REQUIRED_KEY_LENGTH: usize = 32;
const KDF_ITERATIONS: u32 = 100_000;
const IV_LENGTH: usize = 12;
const AUTH_TAG_LENGTH: usize = 16;
const CURRENT_VERSION: u64 = 2;

pub fn decode_key(key_input: &str) -> Result<Vec<u8>, LockeError> {
    // Try hex: 64 hex chars = 32 bytes
    if key_input.len() == 64 && key_input.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(key_input).map_err(|_| LockeError::InvalidKey {
            expected_bytes: REQUIRED_KEY_LENGTH,
            actual_bytes: key_input.len(),
        });
    }

    // Try base64
    if let Ok(bytes) = BASE64.decode(key_input) {
        if bytes.len() == REQUIRED_KEY_LENGTH {
            return Ok(bytes);
        }
    }

    Err(LockeError::InvalidKey {
        expected_bytes: REQUIRED_KEY_LENGTH,
        actual_bytes: key_input.len(),
    })
}

fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; REQUIRED_KEY_LENGTH];
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
    key
}

pub fn decrypt_config(
    encrypted: &serde_json::Value,
    key: &str,
) -> Result<serde_json::Value, LockeError> {
    let obj = encrypted
        .as_object()
        .ok_or_else(|| LockeError::InvalidConfig("expected JSON object".into()))?;

    for field in ["algorithm", "kdf", "salt", "iv", "authTag", "ciphertext"] {
        if !obj.contains_key(field) {
            return Err(LockeError::InvalidConfig(format!(
                "missing field '{field}'"
            )));
        }
    }

    let version = obj.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != CURRENT_VERSION {
        eprintln!(
            "WARNING: Encrypted config version {version} (expected {CURRENT_VERSION}). Attempting best-effort decryption."
        );
    }

    let algorithm = obj["algorithm"].as_str().unwrap_or("");
    if algorithm != "aes-256-gcm" {
        return Err(LockeError::InvalidConfig(format!(
            "unsupported algorithm '{algorithm}'"
        )));
    }

    let kdf = obj["kdf"].as_str().unwrap_or("");
    if kdf != "pbkdf2" {
        return Err(LockeError::InvalidConfig(format!(
            "unsupported KDF '{kdf}'"
        )));
    }

    let key_bytes = decode_key(key)?;

    let salt = BASE64
        .decode(obj["salt"].as_str().unwrap_or(""))
        .map_err(|_| LockeError::InvalidConfig("invalid base64 in salt".into()))?;
    let iv = BASE64
        .decode(obj["iv"].as_str().unwrap_or(""))
        .map_err(|_| LockeError::InvalidConfig("invalid base64 in iv".into()))?;
    let auth_tag = BASE64
        .decode(obj["authTag"].as_str().unwrap_or(""))
        .map_err(|_| LockeError::InvalidConfig("invalid base64 in authTag".into()))?;
    let ciphertext = BASE64
        .decode(obj["ciphertext"].as_str().unwrap_or(""))
        .map_err(|_| LockeError::InvalidConfig("invalid base64 in ciphertext".into()))?;

    let iterations = obj
        .get("kdfIterations")
        .and_then(|v| v.as_u64())
        .unwrap_or(KDF_ITERATIONS as u64) as u32;

    let derived_key = derive_key(&key_bytes, &salt, iterations);

    // Combine ciphertext + auth tag for aes-gcm
    let mut ct_with_tag = ciphertext;
    ct_with_tag.extend_from_slice(&auth_tag);

    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| LockeError::Decryption {
            file_path: "<encrypted config>".into(),
            detail: "key derivation failed".into(),
        })?;

    let nonce = Nonce::from_slice(&iv);
    let plaintext_bytes = cipher.decrypt(nonce, ct_with_tag.as_ref()).map_err(|_| {
        LockeError::Decryption {
            file_path: "<encrypted config>".into(),
            detail: "authentication tag verification failed".into(),
        }
    })?;

    serde_json::from_slice(&plaintext_bytes).map_err(|_| LockeError::Decryption {
        file_path: "<encrypted config>".into(),
        detail: "decrypted content is not valid JSON".into(),
    })
}

pub fn encrypt_config(
    plaintext: &serde_json::Value,
    key: &str,
) -> Result<serde_json::Value, LockeError> {
    let key_bytes = decode_key(key)?;

    let mut salt = vec![0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| LockeError::Decryption {
        file_path: "<encrypt>".into(),
        detail: format!("random generation failed: {e}"),
    })?;

    let mut iv = vec![0u8; IV_LENGTH];
    getrandom::fill(&mut iv).map_err(|e| LockeError::Decryption {
        file_path: "<encrypt>".into(),
        detail: format!("random generation failed: {e}"),
    })?;

    let derived_key = derive_key(&key_bytes, &salt, KDF_ITERATIONS);

    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| LockeError::Decryption {
            file_path: "<encrypt>".into(),
            detail: "key initialization failed".into(),
        })?;

    let plaintext_str = serde_json::to_string(plaintext)
        .map_err(|e| LockeError::InvalidConfig(format!("failed to serialize: {e}")))?;

    let nonce = Nonce::from_slice(&iv);
    let ct_with_tag = cipher
        .encrypt(nonce, plaintext_str.as_bytes())
        .map_err(|_| LockeError::Decryption {
            file_path: "<encrypt>".into(),
            detail: "encryption failed".into(),
        })?;

    let (ciphertext, auth_tag) = ct_with_tag.split_at(ct_with_tag.len() - AUTH_TAG_LENGTH);

    Ok(serde_json::json!({
        "version": CURRENT_VERSION,
        "algorithm": "aes-256-gcm",
        "kdf": "pbkdf2",
        "kdfIterations": KDF_ITERATIONS,
        "salt": BASE64.encode(&salt),
        "iv": BASE64.encode(&iv),
        "authTag": BASE64.encode(auth_tag),
        "ciphertext": BASE64.encode(ciphertext),
    }))
}
