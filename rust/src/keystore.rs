//! OS keystore access with biometric gating.
//!
//! Provides platform-native credential storage via the `keyring` crate:
//! - Windows: Credential Manager (with optional Windows Hello gating)
//! - macOS: Keychain (with optional Touch ID gating)
//! - Linux: Secret Service (D-Bus) — no biometric support
//!
//! Biometric gating is controlled by LOCKE_USE_BIOMETRIC environment variable.

use crate::errors::LockeError;

const SERVICE_NAME: &str = "locke";
const SERVICE_NAME_BIOMETRIC: &str = "locke-bio";

fn biometric_enabled() -> bool {
    std::env::var("LOCKE_USE_BIOMETRIC")
        .map(|v| !["false", "0", "no"].contains(&v.to_lowercase().trim()))
        .unwrap_or(true)
}

fn is_linux() -> bool {
    std::env::consts::OS == "linux"
}

fn effective_service() -> &'static str {
    if biometric_enabled() && !is_linux() {
        SERVICE_NAME_BIOMETRIC
    } else {
        SERVICE_NAME
    }
}

fn make_entry(service: &str, name: &str) -> Result<keyring::Entry, LockeError> {
    keyring::Entry::new(service, name).map_err(|_| LockeError::KeystoreUnavailable {
        platform: std::env::consts::OS.to_string(),
        service: "keyring".to_string(),
    })
}

pub fn get_credential(name: &str) -> Result<Option<String>, LockeError> {
    let service = effective_service();
    let entry = make_entry(service, name)?;

    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => {
            // Fallback to non-biometric service
            if service != SERVICE_NAME {
                let fallback = make_entry(SERVICE_NAME, name)?;
                match fallback.get_password() {
                    Ok(value) => Ok(Some(value)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(_) => Ok(None),
                }
            } else {
                Ok(None)
            }
        }
        Err(_) => Err(LockeError::KeystoreUnavailable {
            platform: std::env::consts::OS.to_string(),
            service: "keyring".to_string(),
        }),
    }
}

pub fn set_credential(name: &str, value: &str) -> Result<(), LockeError> {
    let service = effective_service();
    let entry = make_entry(service, name)?;

    entry
        .set_password(value)
        .map_err(|_| LockeError::KeystoreUnavailable {
            platform: std::env::consts::OS.to_string(),
            service: "keyring".to_string(),
        })
}

pub fn delete_credential(name: &str) -> Result<(), LockeError> {
    let service = effective_service();
    let entry = make_entry(service, name)?;

    match entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(_) => {
            return Err(LockeError::KeystoreUnavailable {
                platform: std::env::consts::OS.to_string(),
                service: "keyring".to_string(),
            })
        }
    }

    // Also clean up non-biometric service entry if applicable
    if service != SERVICE_NAME {
        if let Ok(fallback) = make_entry(SERVICE_NAME, name) {
            let _ = fallback.delete_credential();
        }
    }

    Ok(())
}
