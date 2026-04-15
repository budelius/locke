//! Vaultwarden/Bitwarden API client.
//!
//! Connects to Vaultwarden via Bitwarden-compatible API v1.
//! Secret path convention: {project}/{tenant_slug}/{secret_name}

use crate::errors::LockeError;
use crate::pipeline;

const VAULT_URL_VAR: &str = "LOCKE_VAULT_URL";
const VAULT_USERNAME_VAR: &str = "LOCKE_VAULT_USERNAME";
const VAULT_PASSWORD_CREDENTIAL: &str = "LOCKE_VAULT_PASSWORD";

pub struct VaultClient {
    base_url: String,
    access_token: String,
}

impl VaultClient {
    pub fn connect() -> Result<Self, LockeError> {
        let base_url = std::env::var(VAULT_URL_VAR).map_err(|_| LockeError::VaultAuth {
            vault_url: "unknown".to_string(),
            detail: format!("environment variable {VAULT_URL_VAR} is not set"),
        })?;

        let username =
            std::env::var(VAULT_USERNAME_VAR).map_err(|_| LockeError::VaultAuth {
                vault_url: base_url.clone(),
                detail: format!("environment variable {VAULT_USERNAME_VAR} is not set"),
            })?;

        let password_cred = pipeline::resolve_credential(VAULT_PASSWORD_CREDENTIAL)?;
        let token = Self::authenticate(&base_url, &username, &password_cred.value)?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: token,
        })
    }

    fn authenticate(
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<String, LockeError> {
        let url = format!(
            "{}/identity/connect/token",
            base_url.trim_end_matches('/')
        );

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "password"),
                ("username", username),
                ("password", password),
                ("scope", "api"),
                ("client_id", "cli"),
                ("deviceType", "9"),
                ("deviceIdentifier", "locke-client"),
                ("deviceName", "locke"),
            ])
            .send()
            .map_err(|e| LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail: format!("cannot reach server ({})", e),
            })?;

        let status = response.status();
        if !status.is_success() {
            let detail = match status.as_u16() {
                400 => "invalid credentials (wrong username or password)".to_string(),
                401 => "unauthorized (bad password or expired token)".to_string(),
                404 => format!("identity endpoint not found at {}", url),
                _ => format!("HTTP {}", status.as_u16()),
            };
            return Err(LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail,
            });
        }

        let data: serde_json::Value = response.json().map_err(|e| LockeError::VaultAuth {
            vault_url: base_url.to_string(),
            detail: format!("invalid JSON response: {}", e),
        })?;

        data["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or(LockeError::VaultAuth {
                vault_url: base_url.to_string(),
                detail: "response missing access_token field".to_string(),
            })
    }

    pub fn get_secret(&self, path: &str) -> Result<String, LockeError> {
        let url = format!("{}/api/sync", self.base_url);

        let client = reqwest::blocking::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .map_err(|e| LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!("sync request failed: {}", e),
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

        let sync_data: serde_json::Value =
            response.json().map_err(|e| LockeError::VaultAuth {
                vault_url: self.base_url.clone(),
                detail: format!("invalid sync response: {}", e),
            })?;

        if let Some(ciphers) = sync_data["ciphers"].as_array() {
            for cipher in ciphers {
                if cipher["name"].as_str() == Some(path) {
                    if let Some(password) = cipher["login"]["password"].as_str() {
                        return Ok(password.to_string());
                    }
                    if let Some(notes) = cipher["notes"].as_str() {
                        return Ok(notes.to_string());
                    }
                }
            }
        }

        Err(LockeError::SecretNotFound {
            path: path.to_string(),
        })
    }
}

pub fn get_vault_secret(path: &str) -> Result<String, LockeError> {
    let client = VaultClient::connect()?;
    client.get_secret(path)
}
