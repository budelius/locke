//! Vaultwarden/Bitwarden API client.
//!
//! Connects to Vaultwarden via Bitwarden-compatible API v1.
//! Secret path convention: {project}/{tenant_slug}/{secret_name}
//!
//! Bitwarden encrypts all vault data client-side. After authentication the
//! server returns an encrypted symmetric key which must be decrypted locally
//! using the master key derived from the user's password. All cipher fields
//! (name, login password, notes, …) are then decrypted with that symmetric
//! key. Encrypted strings use the format `{type}.{iv}|{ct}|{mac}` where
//! type 2 = AES-256-CBC + HMAC-SHA256.

use std::collections::HashMap;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::errors::LockeError;
use crate::pipeline;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const VAULT_URL_VAR: &str = "LOCKE_VAULT_URL";
const VAULT_USERNAME_VAR: &str = "LOCKE_VAULT_USERNAME";
const VAULT_PASSWORD_CREDENTIAL: &str = "LOCKE_VAULT_PASSWORD";

const KDF_ITERATIONS: u32 = 600_000;

/// Locke-owned placeholder convention for intentionally unfilled vault secrets.
pub const PLACEHOLDER_VALUE: &str = "FILL_ME";

/// Return true when `value` is a Locke vault placeholder.
pub fn is_placeholder(value: &str) -> bool {
    value.trim() == PLACEHOLDER_VALUE
}

/// A username + password retrieved from a single vault entry.
///
/// Bitwarden login ciphers natively carry both a `username` and a `password`
/// field. Storing a credential as one entry (rather than two separate secrets)
/// keeps the pair together and lets callers fetch both in a single round-trip
/// via [`VaultClient::get_secret_pair`].
///
/// `username` is `None` when the entry has no username set; `password` is the
/// empty string when only a username is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPair {
    pub username: Option<String>,
    pub password: String,
}

// ---------------------------------------------------------------------------
// Bitwarden client-side crypto helpers
// ---------------------------------------------------------------------------

/// HKDF-Expand (RFC 5869) using HMAC-SHA256. Extract step is skipped: `prk` is
/// used directly as the pseudo-random key, matching the Python reference.
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    const HASH_LEN: usize = 32; // SHA-256 output
    let n = length.div_ceil(HASH_LEN);
    let mut okm = Vec::with_capacity(n * HASH_LEN);
    let mut t: Vec<u8> = Vec::new();
    for i in 1..=n {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);
        t = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
    }
    okm.truncate(length);
    okm
}

/// Derive the 32-byte master key from password + email.
fn make_master_key(password: &str, email: &str, iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        email.to_lowercase().as_bytes(),
        iterations,
        &mut key,
    );
    key
}

/// Stretch master key into (enc_key, mac_key) via HKDF-Expand.
fn stretch_master_key(master_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let enc_key = hkdf_expand(master_key, b"enc", 32);
    let mac_key = hkdf_expand(master_key, b"mac", 32);
    (enc_key, mac_key)
}

/// Pre-hash master password the way Bitwarden expects.
///
/// 1. PBKDF2-SHA256(password, lowercase(email), 600_000) -> master key
/// 2. PBKDF2-SHA256(master_key, password, 1) -> hashed password
/// 3. Base64-encode the result
fn hash_password(password: &str, email: &str) -> String {
    let master_key = make_master_key(password, email, KDF_ITERATIONS);
    let mut hashed = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(&master_key, password.as_bytes(), 1, &mut hashed);
    BASE64.encode(hashed)
}

/// Encrypt a plaintext string into Bitwarden `2.iv|ct|mac` format.
/// Type 2 = AES-256-CBC + HMAC-SHA256.
fn encrypt_string(plaintext: &str, enc_key: &[u8], mac_key: &[u8]) -> Result<String, LockeError> {
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv).map_err(|e| LockeError::VaultAuth {
        vault_url: "<encrypt>".to_string(),
        detail: format!("random generation failed: {e}"),
    })?;

    let enc = Aes256CbcEnc::new_from_slices(enc_key, &iv).map_err(|e| LockeError::VaultAuth {
        vault_url: "<encrypt>".to_string(),
        detail: format!("cipher init failed: {e}"),
    })?;
    let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&iv);
    mac.update(&ct);
    let mac_bytes = mac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        BASE64.encode(iv),
        BASE64.encode(&ct),
        BASE64.encode(mac_bytes),
    ))
}

/// Decrypt a Bitwarden encrypted string (`2.iv|ct|mac` format).
/// Type 2 = AES-256-CBC + HMAC-SHA256.
fn decrypt_encrypted_string(
    enc_string: &str,
    enc_key: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, LockeError> {
    if enc_string.is_empty() {
        return Ok(Vec::new());
    }

    let err = |detail: &str| LockeError::VaultAuth {
        vault_url: "<decrypt>".to_string(),
        detail: detail.to_string(),
    };

    let (type_str, rest) = enc_string
        .split_once('.')
        .ok_or_else(|| err("invalid encrypted string format: no type prefix"))?;
    let enc_type: u8 = type_str
        .parse()
        .map_err(|_| err("invalid encrypted string type prefix"))?;
    if enc_type != 2 {
        return Err(err(&format!(
            "unsupported encryption type {enc_type} (expected 2)"
        )));
    }

    let segments: Vec<&str> = rest.split('|').collect();
    if segments.len() != 3 {
        return Err(err(&format!(
            "expected 3 segments (iv|ct|mac), got {}",
            segments.len()
        )));
    }

    let iv = BASE64
        .decode(segments[0])
        .map_err(|_| err("invalid base64 in iv"))?;
    let ct = BASE64
        .decode(segments[1])
        .map_err(|_| err("invalid base64 in ct"))?;
    let mac_tag = BASE64
        .decode(segments[2])
        .map_err(|_| err("invalid base64 in mac"))?;

    // Verify HMAC-SHA256(mac_key, iv + ct) — constant time via `verify_slice`.
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&iv);
    mac.update(&ct);
    mac.verify_slice(&mac_tag)
        .map_err(|_| err("HMAC verification failed"))?;

    let dec = Aes256CbcDec::new_from_slices(enc_key, &iv)
        .map_err(|_| err("cipher init failed (bad key/iv length)"))?;
    let plaintext = dec
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| err("AES-CBC decryption / padding failed"))?;
    Ok(plaintext)
}

/// Decrypt the user's symmetric key from the login response `Key` field.
/// Returns `(enc_key, mac_key)` — the 64-byte symmetric key split in half.
fn decrypt_symmetric_key(
    encrypted_key: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), LockeError> {
    let (stretched_enc, stretched_mac) = stretch_master_key(master_key);
    let raw = decrypt_encrypted_string(encrypted_key, &stretched_enc, &stretched_mac)?;
    if raw.len() != 64 {
        return Err(LockeError::VaultAuth {
            vault_url: "<decrypt>".to_string(),
            detail: format!("decrypted symmetric key is {} bytes (expected 64)", raw.len()),
        });
    }
    Ok((raw[..32].to_vec(), raw[32..].to_vec()))
}

/// Decrypt an optional Bitwarden cipher field to a UTF-8 string. Returns `None`
/// on empty input or any decode/decrypt failure (matching Python's behavior of
/// logging and swallowing the error).
fn decrypt_cipher_string(enc_string: Option<&str>, enc_key: &[u8], mac_key: &[u8]) -> Option<String> {
    let enc_string = enc_string?;
    if enc_string.is_empty() {
        return None;
    }
    match decrypt_encrypted_string(enc_string, enc_key, mac_key) {
        Ok(bytes) => String::from_utf8(bytes).ok(),
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Vault client
// ---------------------------------------------------------------------------

/// Decrypted lookup maps from one `/api/sync` round-trip.
struct CipherIndex {
    /// plaintext name -> cipher id
    names: HashMap<String, String>,
    /// plaintext folder name -> folder id
    folders: HashMap<String, String>,
    /// plaintext name -> value (login.password or notes)
    values: HashMap<String, String>,
    /// plaintext name -> metadata (username/uri/notes)
    metadata: HashMap<String, CipherMetadata>,
}

#[derive(Debug, Clone, Default)]
struct CipherMetadata {
    username: Option<String>,
    uri: Option<String>,
    notes: Option<String>,
}

/// Bitwarden-compatible API client for Vaultwarden.
pub struct VaultClient {
    base_url: String,
    access_token: String,
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
    /// path -> plaintext value, populated on first sync().
    secrets: Option<HashMap<String, String>>,
    /// path -> metadata, populated on first sync().
    metadata: Option<HashMap<String, CipherMetadata>>,
}

impl VaultClient {
    /// Create an authenticated vault client using pipeline-resolved credentials.
    pub fn connect() -> Result<Self, LockeError> {
        let base_url = std::env::var(VAULT_URL_VAR).map_err(|_| LockeError::VaultAuth {
            vault_url: "unknown".to_string(),
            detail: format!("environment variable {VAULT_URL_VAR} is not set"),
        })?;
        if base_url.is_empty() {
            return Err(LockeError::VaultAuth {
                vault_url: "unknown".to_string(),
                detail: format!("environment variable {VAULT_URL_VAR} is not set"),
            });
        }

        let username = std::env::var(VAULT_USERNAME_VAR).map_err(|_| LockeError::VaultAuth {
            vault_url: base_url.clone(),
            detail: format!("environment variable {VAULT_USERNAME_VAR} is not set"),
        })?;
        if username.is_empty() {
            return Err(LockeError::VaultAuth {
                vault_url: base_url.clone(),
                detail: format!("environment variable {VAULT_USERNAME_VAR} is not set"),
            });
        }

        let password_cred = pipeline::resolve_credential(VAULT_PASSWORD_CREDENTIAL)?;
        Self::connect_with(&base_url, &username, &password_cred.value)
    }

    /// Create an authenticated vault client using explicit credentials.
    pub fn connect_with(
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, LockeError> {
        if base_url.is_empty() {
            return Err(LockeError::VaultAuth {
                vault_url: "unknown".to_string(),
                detail: "empty base_url passed to connect_with()".to_string(),
            });
        }
        if username.is_empty() {
            return Err(LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail: "empty username passed to connect_with()".to_string(),
            });
        }

        let base_url = base_url.trim_end_matches('/').to_string();
        let (access_token, encrypted_key) = Self::authenticate(&base_url, username, password)?;

        let master_key = make_master_key(password, username, KDF_ITERATIONS);
        let (enc_key, mac_key) = decrypt_symmetric_key(&encrypted_key, &master_key)?;

        Ok(Self {
            base_url,
            access_token,
            enc_key,
            mac_key,
            secrets: None,
            metadata: None,
        })
    }

    /// Authenticate with the Bitwarden/Vaultwarden identity endpoint.
    /// Returns `(access_token, encrypted_key)` where `encrypted_key` is the
    /// user's encrypted symmetric key (`Key` field in the response).
    fn authenticate(
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<(String, String), LockeError> {
        let identity_url = format!("{base_url}/identity/connect/token");
        let hashed_password = hash_password(password, username);

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(&identity_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "password"),
                ("username", username),
                ("password", hashed_password.as_str()),
                ("scope", "api offline_access"),
                ("client_id", "cli"),
                ("deviceType", "9"),
                ("deviceIdentifier", "locke-client"),
                ("deviceName", "locke"),
            ])
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    LockeError::VaultAuth {
                        vault_url: base_url.to_string(),
                        detail: "connection timed out".to_string(),
                    }
                } else {
                    LockeError::VaultAuth {
                        vault_url: base_url.to_string(),
                        detail: format!("cannot reach server ({e})"),
                    }
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let detail = match status.as_u16() {
                400 => "invalid credentials (wrong username or password)".to_string(),
                401 => "unauthorized (bad password or expired token)".to_string(),
                404 => format!("identity endpoint not found at {identity_url}"),
                other => format!("HTTP {other}"),
            };
            return Err(LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail,
            });
        }

        let data: serde_json::Value = response.json().map_err(|e| LockeError::VaultAuth {
            vault_url: base_url.to_string(),
            detail: format!("invalid JSON response: {e}"),
        })?;

        let access_token = data["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail: "response missing access_token field".to_string(),
            })?;

        let encrypted_key = data["Key"].as_str().unwrap_or("");
        if encrypted_key.is_empty() {
            return Err(LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail: "server did not return an encrypted symmetric key (Key field)".to_string(),
            });
        }

        Ok((access_token, encrypted_key.to_string()))
    }

    fn encrypt(&self, plaintext: Option<&str>) -> Option<String> {
        let plaintext = plaintext?;
        if plaintext.is_empty() {
            return None;
        }
        encrypt_string(plaintext, &self.enc_key, &self.mac_key).ok()
    }

    fn decrypt(&self, enc_string: Option<&str>) -> Option<String> {
        decrypt_cipher_string(enc_string, &self.enc_key, &self.mac_key)
    }

    /// Return raw `/api/sync` data from Vaultwarden.
    fn sync_data(&self) -> Result<serde_json::Value, LockeError> {
        let client = reqwest::blocking::Client::new();
        let response = client
            .get(format!("{}/api/sync", self.base_url))
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .map_err(|e| LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!("sync failed: {e}"),
            })?;

        if !response.status().is_success() {
            return Err(LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!(
                    "sync failed with HTTP {} (token may be expired)",
                    response.status().as_u16()
                ),
            });
        }

        response.json().map_err(|e| LockeError::VaultAuth {
            vault_url: self.base_url.clone(),
            detail: format!("sync failed: {e}"),
        })
    }

    /// Return decrypted lookup maps for ciphers and folders.
    fn cipher_index(&self) -> Result<CipherIndex, LockeError> {
        let sync_data = self.sync_data()?;

        let mut names = HashMap::new();
        let mut values = HashMap::new();
        let mut metadata = HashMap::new();

        if let Some(ciphers) = sync_data["ciphers"].as_array() {
            for cipher in ciphers {
                let name = match self.decrypt(cipher["name"].as_str()) {
                    Some(n) => n,
                    None => continue,
                };
                if let Some(id) = cipher["id"].as_str() {
                    names.insert(name.clone(), id.to_string());
                }
                let login = &cipher["login"];
                let username = self.decrypt(login["username"].as_str());
                let uri = login["uris"]
                    .as_array()
                    .and_then(|uris| uris.first())
                    .and_then(|first| self.decrypt(first["uri"].as_str()));
                let notes = self.decrypt(cipher["notes"].as_str());
                let value = self
                    .decrypt(login["password"].as_str())
                    .or_else(|| notes.clone());
                if let Some(v) = value {
                    if is_placeholder(&v) {
                        eprintln!("WARNING: Vault secret {name} is still a placeholder");
                    }
                    values.insert(name.clone(), v);
                }
                metadata.insert(
                    name,
                    CipherMetadata {
                        username,
                        uri,
                        notes,
                    },
                );
            }
        }

        let mut folders = HashMap::new();
        if let Some(folder_list) = sync_data["folders"].as_array() {
            for folder in folder_list {
                if let Some(name) = self.decrypt(folder["name"].as_str()) {
                    if let Some(id) = folder["id"].as_str() {
                        folders.insert(name, id.to_string());
                    }
                }
            }
        }

        Ok(CipherIndex {
            names,
            folders,
            values,
            metadata,
        })
    }

    /// Fetch and decrypt every cipher in one `/api/sync` round-trip, caching the
    /// result on the instance. Subsequent calls reuse the cache unless
    /// `force_refresh` is set.
    pub fn sync(&mut self, force_refresh: bool) -> Result<&HashMap<String, String>, LockeError> {
        if self.secrets.is_none() || force_refresh {
            let index = self.cipher_index()?;
            self.secrets = Some(index.values);
            self.metadata = Some(index.metadata);
        }
        Ok(self.secrets.as_ref().expect("secrets populated above"))
    }

    fn ensure_synced(&mut self) -> Result<(), LockeError> {
        if self.secrets.is_none() || self.metadata.is_none() {
            self.sync(false)?;
        }
        Ok(())
    }

    /// Return cached secrets whose plaintext name starts with `prefix`. Pass an
    /// empty string to get every secret in the vault.
    pub fn list_secrets(&mut self, prefix: &str) -> Result<HashMap<String, String>, LockeError> {
        self.ensure_synced()?;
        let secrets = self.secrets.as_ref().unwrap();
        if prefix.is_empty() {
            Ok(secrets.clone())
        } else {
            Ok(secrets
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    /// Retrieve a secret by path. Reads from the in-memory snapshot populated by
    /// [`sync`](Self::sync) (called automatically on first access).
    pub fn get_secret(&mut self, path: &str) -> Result<String, LockeError> {
        self.ensure_synced()?;
        match self.secrets.as_ref().unwrap().get(path) {
            Some(value) => {
                if is_placeholder(value) {
                    eprintln!("WARNING: Vault secret {path} is still a placeholder");
                }
                Ok(value.clone())
            }
            None => Err(LockeError::SecretNotFound {
                path: path.to_string(),
            }),
        }
    }

    /// Retrieve a username + password stored in a single vault entry.
    pub fn get_secret_pair(&mut self, path: &str) -> Result<CredentialPair, LockeError> {
        self.ensure_synced()?;
        let meta = self.metadata.as_ref().unwrap().get(path);
        let has_secret = self.secrets.as_ref().unwrap().contains_key(path);
        if meta.is_none() && !has_secret {
            return Err(LockeError::SecretNotFound {
                path: path.to_string(),
            });
        }
        let password = self
            .secrets
            .as_ref()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or_default();
        if is_placeholder(&password) {
            eprintln!("WARNING: Vault secret {path} is still a placeholder");
        }
        let username = meta.and_then(|m| m.username.clone());
        Ok(CredentialPair { username, password })
    }

    fn resolve_folder_id(
        &self,
        folder_name: Option<&str>,
        index: &mut CipherIndex,
    ) -> Result<Option<String>, LockeError> {
        let folder_name = match folder_name {
            Some(f) if !f.is_empty() => f,
            _ => return Ok(None),
        };
        if let Some(id) = index.folders.get(folder_name) {
            return Ok(Some(id.clone()));
        }

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(format!("{}/api/folders", self.base_url))
            .header("Authorization", format!("Bearer {}", self.access_token))
            .json(&serde_json::json!({ "name": self.encrypt(Some(folder_name)) }))
            .send()
            .map_err(|e| LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!("folder create failed: {e}"),
            })?;
        if !response.status().is_success() {
            return Err(LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!("folder create failed with HTTP {}", response.status().as_u16()),
            });
        }
        let data: serde_json::Value = response.json().map_err(|e| LockeError::VaultAuth {
            vault_url: self.base_url.clone(),
            detail: format!("invalid folder response: {e}"),
        })?;
        let folder_id = data["id"]
            .as_str()
            .ok_or_else(|| LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: "folder response missing id".to_string(),
            })?
            .to_string();
        index
            .folders
            .insert(folder_name.to_string(), folder_id.clone());
        Ok(Some(folder_id))
    }

    /// Build an encrypted Bitwarden login cipher payload.
    fn build_cipher_payload(
        &self,
        path: &str,
        value: &str,
        folder_id: Option<&str>,
        username: Option<&str>,
        uri: Option<&str>,
        notes: Option<&str>,
    ) -> serde_json::Value {
        let encrypted_uri = self.encrypt(uri);
        let uris = match &encrypted_uri {
            Some(u) => serde_json::json!([{ "match": serde_json::Value::Null, "uri": u }]),
            None => serde_json::json!([]),
        };
        serde_json::json!({
            "type": 1,
            "name": self.encrypt(Some(path)),
            "folderId": folder_id,
            "login": {
                "username": self.encrypt(username),
                "password": self.encrypt(Some(value)),
                "uris": uris,
            },
            "notes": self.encrypt(notes),
            "favorite": false,
            "reprompt": 0,
        })
    }

    /// Create or update a Vaultwarden secret by path. Returns `"created"` or
    /// `"updated"`.
    ///
    /// When `folder` is `None` the folder is derived from the path prefix before
    /// the final slash; pass `Some("")` to leave the item unfiled.
    #[allow(clippy::too_many_arguments)]
    pub fn set_secret(
        &mut self,
        path: &str,
        value: Option<&str>,
        folder: Option<&str>,
        username: Option<&str>,
        uri: Option<&str>,
        notes: Option<&str>,
    ) -> Result<&'static str, LockeError> {
        if path.is_empty() {
            return Err(LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: "path must not be empty".to_string(),
            });
        }
        let value: String = match value {
            None | Some("") => {
                eprintln!("WARNING: Vault secret {path} written with placeholder value");
                PLACEHOLDER_VALUE.to_string()
            }
            Some(v) => {
                if is_placeholder(v) {
                    eprintln!("WARNING: Vault secret {path} written with placeholder value");
                }
                v.to_string()
            }
        };

        let mut index = self.cipher_index()?;

        // Folder defaults to the path prefix before the final slash.
        let derived_folder: Option<String> = match folder {
            None => Some(
                path.rsplit_once('/')
                    .map(|(prefix, _)| prefix.to_string())
                    .unwrap_or_default(),
            ),
            Some(f) => Some(f.to_string()),
        };
        let folder_id = self.resolve_folder_id(derived_folder.as_deref(), &mut index)?;

        let cipher_id = index.names.get(path).cloned();
        let client = reqwest::blocking::Client::new();

        let (response, action) = if let Some(cipher_id) = cipher_id {
            let current = index.metadata.get(path);
            let eff_username =
                username.map(str::to_string).or_else(|| current.and_then(|m| m.username.clone()));
            let eff_uri =
                uri.map(str::to_string).or_else(|| current.and_then(|m| m.uri.clone()));
            let eff_notes =
                notes.map(str::to_string).or_else(|| current.and_then(|m| m.notes.clone()));
            let payload = self.build_cipher_payload(
                path,
                &value,
                folder_id.as_deref(),
                eff_username.as_deref(),
                eff_uri.as_deref(),
                eff_notes.as_deref(),
            );
            let resp = client
                .put(format!("{}/api/ciphers/{cipher_id}", self.base_url))
                .header("Authorization", format!("Bearer {}", self.access_token))
                .json(&payload)
                .send()
                .map_err(|e| LockeError::VaultAuth {
                    vault_url: self.base_url.clone(),
                    detail: format!("cipher update failed: {e}"),
                })?;
            (resp, "updated")
        } else {
            let payload =
                self.build_cipher_payload(path, &value, folder_id.as_deref(), username, uri, notes);
            let resp = client
                .post(format!("{}/api/ciphers", self.base_url))
                .header("Authorization", format!("Bearer {}", self.access_token))
                .json(&payload)
                .send()
                .map_err(|e| LockeError::VaultAuth {
                    vault_url: self.base_url.clone(),
                    detail: format!("cipher create failed: {e}"),
                })?;
            (resp, "created")
        };

        if !response.status().is_success() {
            return Err(LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!("cipher {action} failed with HTTP {}", response.status().as_u16()),
            });
        }

        // Update caches when present.
        if let Some(secrets) = self.secrets.as_mut() {
            secrets.insert(path.to_string(), value.clone());
        }
        if let Some(meta_map) = self.metadata.as_mut() {
            let current = meta_map.get(path).cloned().unwrap_or_default();
            meta_map.insert(
                path.to_string(),
                CipherMetadata {
                    username: username.map(str::to_string).or(current.username),
                    uri: uri.map(str::to_string).or(current.uri),
                    notes: notes.map(str::to_string).or(current.notes),
                },
            );
        }

        Ok(action)
    }

    /// Create or update a single vault entry holding a username + password.
    /// Returns `"created"` or `"updated"`.
    pub fn set_secret_pair(
        &mut self,
        path: &str,
        username: Option<&str>,
        password: Option<&str>,
        folder: Option<&str>,
        uri: Option<&str>,
        notes: Option<&str>,
    ) -> Result<&'static str, LockeError> {
        self.set_secret(path, password, folder, username, uri, notes)
    }
}

// ---------------------------------------------------------------------------
// Module-level convenience functions
// ---------------------------------------------------------------------------

/// Retrieve a secret from Vaultwarden by path.
pub fn get_vault_secret(path: &str) -> Result<String, LockeError> {
    let mut client = VaultClient::connect()?;
    client.get_secret(path)
}

/// Retrieve a username + password stored in a single Vaultwarden entry.
pub fn get_vault_secret_pair(path: &str) -> Result<CredentialPair, LockeError> {
    let mut client = VaultClient::connect()?;
    client.get_secret_pair(path)
}

/// Create or update a Vaultwarden secret by path. Returns `"created"` or
/// `"updated"`.
pub fn set_vault_secret(
    path: &str,
    value: Option<&str>,
    folder: Option<&str>,
    username: Option<&str>,
    uri: Option<&str>,
    notes: Option<&str>,
) -> Result<&'static str, LockeError> {
    let mut client = VaultClient::connect()?;
    client.set_secret(path, value, folder, username, uri, notes)
}

/// Create or update a single Vaultwarden entry holding a username + password.
/// Returns `"created"` or `"updated"`.
pub fn set_vault_secret_pair(
    path: &str,
    username: Option<&str>,
    password: Option<&str>,
    folder: Option<&str>,
    uri: Option<&str>,
    notes: Option<&str>,
) -> Result<&'static str, LockeError> {
    let mut client = VaultClient::connect()?;
    client.set_secret_pair(path, username, password, folder, uri, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn load_vectors() -> serde_json::Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test-vectors")
            .join("vault-cipher.json");
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&contents).unwrap()
    }

    /// Build a client without network access, injecting decrypted caches.
    fn client_with_caches(
        secrets: HashMap<String, String>,
        metadata: HashMap<String, CipherMetadata>,
    ) -> VaultClient {
        VaultClient {
            base_url: "http://localhost".to_string(),
            access_token: "test-token".to_string(),
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
            secrets: Some(secrets),
            metadata: Some(metadata),
        }
    }

    #[test]
    fn master_key_derivation() {
        let v = load_vectors();
        let mk = &v["master_key_derivation"];
        let key = make_master_key(
            mk["password"].as_str().unwrap(),
            mk["email"].as_str().unwrap(),
            mk["iterations"].as_u64().unwrap() as u32,
        );
        assert_eq!(hex::encode(&key), mk["expected_master_key_hex"].as_str().unwrap());
    }

    #[test]
    fn stretch_master_key_vectors() {
        let v = load_vectors();
        let s = &v["stretch_master_key"];
        let mk = hex::decode(s["master_key_hex"].as_str().unwrap()).unwrap();
        let (enc, mac) = stretch_master_key(&mk);
        assert_eq!(hex::encode(&enc), s["expected_enc_key_hex"].as_str().unwrap());
        assert_eq!(hex::encode(&mac), s["expected_mac_key_hex"].as_str().unwrap());
    }

    #[test]
    fn decrypt_cipher_string_vector() {
        let v = load_vectors();
        let d = &v["decrypt_cipher_string"];
        let enc_key = hex::decode(d["enc_key_hex"].as_str().unwrap()).unwrap();
        let mac_key = hex::decode(d["mac_key_hex"].as_str().unwrap()).unwrap();
        let plaintext =
            decrypt_encrypted_string(d["cipher_string"].as_str().unwrap(), &enc_key, &mac_key)
                .unwrap();
        assert_eq!(
            String::from_utf8(plaintext).unwrap(),
            d["expected_plaintext"].as_str().unwrap()
        );
    }

    #[test]
    fn decrypt_symmetric_key_vector() {
        let v = load_vectors();
        let d = &v["decrypt_symmetric_key"];
        let mk = hex::decode(d["master_key_hex"].as_str().unwrap()).unwrap();
        let (enc, mac) =
            decrypt_symmetric_key(d["encrypted_key"].as_str().unwrap(), &mk).unwrap();
        assert_eq!(hex::encode(&enc), d["expected_enc_key_hex"].as_str().unwrap());
        assert_eq!(hex::encode(&mac), d["expected_mac_key_hex"].as_str().unwrap());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let v = load_vectors();
        let r = &v["roundtrip"];
        let enc_key = hex::decode(r["enc_key_hex"].as_str().unwrap()).unwrap();
        let mac_key = hex::decode(r["mac_key_hex"].as_str().unwrap()).unwrap();
        let plaintext = r["plaintext"].as_str().unwrap();

        let enc_string = encrypt_string(plaintext, &enc_key, &mac_key).unwrap();
        assert!(enc_string.starts_with("2."));
        let decrypted =
            decrypt_encrypted_string(&enc_string, &enc_key, &mac_key).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), plaintext);
    }

    #[test]
    fn hmac_tamper_rejected() {
        let v = load_vectors();
        let d = &v["decrypt_cipher_string"];
        let enc_key = hex::decode(d["enc_key_hex"].as_str().unwrap()).unwrap();
        let mac_key = hex::decode(d["mac_key_hex"].as_str().unwrap()).unwrap();
        // Wrong mac key must fail HMAC verification.
        let wrong_mac = vec![0u8; 32];
        let result =
            decrypt_encrypted_string(d["cipher_string"].as_str().unwrap(), &enc_key, &wrong_mac);
        assert!(result.is_err());
        let _ = mac_key;
    }

    #[test]
    fn hash_password_is_deterministic() {
        let h1 = hash_password("correct horse battery staple", "User@Example.COM");
        let h2 = hash_password("correct horse battery staple", "user@example.com");
        // Email is lowercased, so both inputs produce the same hash.
        assert_eq!(h1, h2);
        // Base64 of a 32-byte digest is 44 chars.
        assert_eq!(h1.len(), 44);
    }

    #[test]
    fn get_secret_pair_returns_username_and_password() {
        let mut secrets = HashMap::new();
        secrets.insert("proj/db".to_string(), "s3cret".to_string());
        let mut metadata = HashMap::new();
        metadata.insert(
            "proj/db".to_string(),
            CipherMetadata {
                username: Some("dbuser".to_string()),
                uri: None,
                notes: None,
            },
        );
        let mut client = client_with_caches(secrets, metadata);
        let pair = client.get_secret_pair("proj/db").unwrap();
        assert_eq!(pair.username, Some("dbuser".to_string()));
        assert_eq!(pair.password, "s3cret");
    }

    #[test]
    fn get_secret_pair_missing_path_errors() {
        let mut client = client_with_caches(HashMap::new(), HashMap::new());
        let err = client.get_secret_pair("missing").unwrap_err();
        assert!(matches!(err, LockeError::SecretNotFound { .. }));
    }

    #[test]
    fn get_secret_pair_no_username() {
        let mut secrets = HashMap::new();
        secrets.insert("proj/token".to_string(), "abc123".to_string());
        let mut metadata = HashMap::new();
        metadata.insert("proj/token".to_string(), CipherMetadata::default());
        let mut client = client_with_caches(secrets, metadata);
        let pair = client.get_secret_pair("proj/token").unwrap();
        assert_eq!(pair.username, None);
        assert_eq!(pair.password, "abc123");
    }

    #[test]
    fn is_placeholder_detects_fill_me() {
        assert!(is_placeholder("FILL_ME"));
        assert!(is_placeholder("  FILL_ME  "));
        assert!(!is_placeholder("real-value"));
    }
}
