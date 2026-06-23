//! OS keystore access with biometric gating.
//!
//! Provides platform-native credential storage via the `keyring` crate:
//! - Windows: Credential Manager + Windows Hello (UserConsentVerifier)
//! - macOS: Keychain (Touch ID gating not yet implemented — logged + passed)
//! - Linux: Secret Service (D-Bus) — no biometric support
//!
//! Biometric gating is controlled by the `LOCKE_USE_BIOMETRIC` env var
//! (default `true`). When enabled on Windows, credential reads trigger a
//! Windows Hello prompt (fingerprint / face / PIN) via the WinRT
//! `UserConsentVerifier` API. Verification is cached in-memory for
//! `LOCKE_BIO_CACHE_TTL` seconds (default 300) and persisted to a session
//! file for `LOCKE_BIO_SESSION_TTL` seconds (default 7 days), mirroring the
//! Python reference implementation byte-for-byte.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::errors::LockeError;

type HmacSha256 = Hmac<Sha256>;

/// Canonical service name under which Locke stores credentials.
const SERVICE_NAME: &str = "locke";

// ---------------------------------------------------------------------------
// Legacy credential naming (migration support)
// ---------------------------------------------------------------------------
// Older credential-management tools stored secrets using the project name as
// the service/target and a short credential name as the username. Locke
// unifies under service="locke" with UPPER_SNAKE_CASE names. The helpers below
// describe legacy naming conventions Locke can still read so users can migrate
// without losing credentials.
//
// Legacy patterns (target -> username):
//   "{project}"                        -> "config-encryption-key" | "config_encryption_key"
//   "config-encryption-key@{project}"  -> "config-encryption-key"
//   "locke-bio"                        -> "LOCKE_VAULT_PASSWORD"  (older locke versions)

const LEGACY_KEY_SUFFIX: &str = "_CONFIG_ENCRYPTION_KEY";

const LEGACY_VAULT_PASSWORD_PATTERNS: &[(&str, &str)] = &[("locke-bio", "LOCKE_VAULT_PASSWORD")];

/// Return legacy `(target, username)` pairs to try for a Locke credential name.
fn legacy_lookups_for(name: &str) -> Vec<(String, String)> {
    let mut candidates: Vec<(String, String)> = Vec::new();

    if name == "LOCKE_VAULT_PASSWORD" {
        for (t, u) in LEGACY_VAULT_PASSWORD_PATTERNS {
            candidates.push((t.to_string(), u.to_string()));
        }
        return candidates;
    }

    if let Some(prefix) = name.strip_suffix(LEGACY_KEY_SUFFIX) {
        let project = prefix.to_lowercase();
        candidates.push((project.clone(), "config-encryption-key".to_string()));
        candidates.push((project.clone(), "config_encryption_key".to_string()));
        candidates.push((
            format!("config-encryption-key@{project}"),
            "config-encryption-key".to_string(),
        ));
    }

    candidates
}

// ---------------------------------------------------------------------------
// Biometric configuration
// ---------------------------------------------------------------------------

const BIO_CACHE_TTL_DEFAULT: u64 = 300; // seconds
const BIO_SESSION_TTL_DEFAULT: u64 = 604_800; // 7 days in seconds
const BIO_SESSION_FILE: &str = "bio_session.json";

/// In-memory cache of the most recent successful verification (monotonic clock).
static BIO_VERIFIED_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// Check if biometric gating is enabled (mirrors Python `_biometric_enabled`).
pub fn biometric_enabled() -> bool {
    match std::env::var("LOCKE_USE_BIOMETRIC") {
        Ok(v) => {
            let flag = v.trim().to_lowercase();
            !matches!(flag.as_str(), "false" | "0" | "no")
        }
        Err(_) => true,
    }
}

/// Return the biometric in-memory cache TTL in seconds.
fn bio_cache_ttl() -> u64 {
    std::env::var("LOCKE_BIO_CACHE_TTL")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map(|f| f.max(0.0) as u64)
        .unwrap_or(BIO_CACHE_TTL_DEFAULT)
}

/// Return the persistent session TTL in seconds.
fn bio_session_ttl() -> u64 {
    std::env::var("LOCKE_BIO_SESSION_TTL")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map(|f| f.max(0.0) as u64)
        .unwrap_or(BIO_SESSION_TTL_DEFAULT)
}

/// Return true if a recent in-memory biometric verification is still valid.
fn bio_cache_valid() -> bool {
    let guard = BIO_VERIFIED_AT.lock().expect("bio cache mutex poisoned");
    match *guard {
        Some(at) => at.elapsed().as_secs() < bio_cache_ttl(),
        None => false,
    }
}

/// Warm the in-memory cache with the current instant.
fn warm_bio_cache() {
    let mut guard = BIO_VERIFIED_AT.lock().expect("bio cache mutex poisoned");
    *guard = Some(Instant::now());
}

/// Invalidate the biometric verification cache (useful for testing).
pub fn reset_bio_cache() {
    let mut guard = BIO_VERIFIED_AT.lock().expect("bio cache mutex poisoned");
    *guard = None;
}

// ---------------------------------------------------------------------------
// Persistent biometric session (survives across process invocations)
// ---------------------------------------------------------------------------

/// Return the directory for storing the biometric session file.
///
/// Uses `%LOCALAPPDATA%\locke` on Windows, `~/.locke` elsewhere. Creates the
/// directory if it does not exist.
fn get_bio_session_dir() -> std::io::Result<PathBuf> {
    let dir = if cfg!(windows) {
        match std::env::var("LOCALAPPDATA") {
            Ok(base) if !base.is_empty() => PathBuf::from(base).join("locke"),
            _ => home_dir().join(".locke"),
        }
    } else {
        home_dir().join(".locke")
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn home_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var("USERPROFILE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        std::env::var("HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

/// Return a stable machine identifier.
///
/// On Windows, reads `MachineGuid` from the registry
/// (`HKLM\SOFTWARE\Microsoft\Cryptography`). Returns `"unknown"` on other
/// platforms or on failure.
fn get_machine_id() -> String {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Microsoft\Cryptography") {
            if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
                return guid;
            }
        }
        "unknown".to_string()
    }
    #[cfg(not(windows))]
    {
        "unknown".to_string()
    }
}

/// Return the current OS username.
fn get_username() -> String {
    if cfg!(windows) {
        std::env::var("USERNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("USERNAME").ok())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// Format `verified_at` to match Python's `repr(float)`.
///
/// Python formats `time.time()` (a float) via `json.dump`, then re-reads it as
/// `float(...)`. The HMAC message uses `f"{verified_at}|..."` which is Python's
/// `str(float)`. Both serializations use the shortest round-trippable form. We
/// reproduce that with Rust's default `f64` `Display`, which is also shortest
/// round-trip, ensuring byte-for-byte HMAC parity for the same numeric value.
fn format_verified_at(verified_at: f64) -> String {
    // Rust's f64 Display emits the shortest representation that round-trips,
    // matching Python's repr(float)/str(float) for the same value.
    let s = format!("{verified_at}");
    // Python always renders whole-number floats with a trailing ".0"
    // (e.g. "1700000000.0"); Rust renders "1700000000". Align to Python.
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

/// Compute an HMAC-SHA256 over the session payload.
///
/// The machine GUID is used as the HMAC key — this prevents casual tampering
/// but is not a cryptographic secret. Mirrors Python `_compute_session_hmac`
/// byte-for-byte: `HMAC-SHA256(key=machine_id, msg="{verified_at}|{machine_id}|{username}")`.
fn compute_session_hmac(verified_at: f64, machine_id: &str, username: &str) -> String {
    let msg = format!(
        "{}|{}|{}",
        format_verified_at(verified_at),
        machine_id,
        username
    );
    let mut mac =
        HmacSha256::new_from_slice(machine_id.as_bytes()).expect("HMAC accepts any key length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Current wall-clock time as seconds since the Unix epoch (matches `time.time()`).
fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Write a persistent biometric session file after successful verification.
///
/// Atomic write: temp file in the same directory, then rename over the target.
fn write_bio_session() {
    let result = (|| -> std::io::Result<()> {
        let session_dir = get_bio_session_dir()?;
        let machine_id = get_machine_id();
        let username = get_username();
        let verified_at = now_unix();
        let payload = serde_json::json!({
            "verified_at": verified_at,
            "machine_id": machine_id,
            "username": username,
            "hmac": compute_session_hmac(verified_at, &machine_id, &username),
        });
        let target = session_dir.join(BIO_SESSION_FILE);

        // Atomic write: unique temp file in same directory, then rename.
        let tmp = session_dir.join(format!(
            ".{}.{}.tmp",
            BIO_SESSION_FILE,
            std::process::id()
        ));
        let body = serde_json::to_vec(&payload)?;
        match std::fs::write(&tmp, &body) {
            Ok(()) => {}
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        }
        if let Err(e) = std::fs::rename(&tmp, &target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("DEBUG: failed to write biometric session: {e}");
    }
}

/// Check the persistent biometric session file.
///
/// Returns true if the session is valid (exists, not expired, matches the
/// current machine and user, HMAC intact via constant-time comparison).
fn read_bio_session() -> bool {
    let target = match get_bio_session_dir() {
        Ok(d) => d.join(BIO_SESSION_FILE),
        Err(_) => return false,
    };
    if !target.is_file() {
        return false;
    }
    let data: serde_json::Value = match std::fs::read_to_string(&target)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => return false,
    };

    let verified_at = match data["verified_at"].as_f64() {
        Some(v) => v,
        None => return false,
    };
    let machine_id = match data["machine_id"].as_str() {
        Some(v) => v.to_string(),
        None => return false,
    };
    let username = match data["username"].as_str() {
        Some(v) => v.to_string(),
        None => return false,
    };
    let stored_hmac = match data["hmac"].as_str() {
        Some(v) => v,
        None => return false,
    };

    // Machine binding.
    if machine_id != get_machine_id() {
        return false;
    }
    if username != get_username() {
        return false;
    }

    // HMAC integrity (constant-time comparison via Hmac::verify_slice).
    let expected = compute_session_hmac(verified_at, &machine_id, &username);
    let expected_bytes = match hex::decode(&expected) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let stored_bytes = match hex::decode(stored_hmac) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if !constant_time_eq(&expected_bytes, &stored_bytes) {
        return false;
    }

    // TTL.
    let age = now_unix() - verified_at;
    if age < 0.0 || age >= bio_session_ttl() as f64 {
        return false;
    }

    true
}

/// Constant-time byte slice comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Delete the persistent biometric session file and reset the in-memory cache.
///
/// Returns true if a session file was removed, false otherwise.
pub fn invalidate_bio_session() -> bool {
    reset_bio_cache();
    if let Ok(dir) = get_bio_session_dir() {
        let target = dir.join(BIO_SESSION_FILE);
        if target.is_file() && std::fs::remove_file(&target).is_ok() {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Interactivity detection
// ---------------------------------------------------------------------------

/// Detect whether the current process has an interactive console.
///
/// Returns false in background services, CI runners, or shells where the
/// Windows Hello dialog cannot be shown (stdin is not a TTY, or — on Windows —
/// there is no console window).
fn is_interactive() -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    #[cfg(windows)]
    {
        // GetConsoleWindow() returns 0 (null) when there is no attached console.
        use windows::Win32::System::Console::GetConsoleWindow;
        let hwnd = unsafe { GetConsoleWindow() };
        if hwnd.0.is_null() {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Windows Hello verification (WinRT UserConsentVerifier)
// ---------------------------------------------------------------------------

/// Trigger a Windows Hello prompt; return Ok(()) when verified.
///
/// On non-Windows targets this is a no-op success. On Windows it blocks on the
/// WinRT `UserConsentVerifier` IAsyncOperation via `.get()`.
#[cfg(windows)]
fn verify_windows_hello() -> Result<(), LockeError> {
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };

    // Check availability first.
    let availability = (|| -> windows::core::Result<UserConsentVerifierAvailability> {
        UserConsentVerifier::CheckAvailabilityAsync()?.get()
    })()
    .map_err(|e| LockeError::BiometricUnavailable {
        detail: format!("availability check failed: {e}"),
    })?;

    if availability != UserConsentVerifierAvailability::Available {
        return Err(LockeError::BiometricUnavailable {
            detail: format!("Windows Hello not available (status: {availability:?})"),
        });
    }

    // Request verification — shows the Windows Hello dialog. `.get()` blocks
    // the calling thread until the IAsyncOperation completes. The live prompt
    // cannot be exercised in unit tests; the degradation paths (disabled,
    // non-interactive, non-Windows) are covered instead.
    let message = HSTRING::from("Locke: Verify your identity to access credentials");
    let result = (|| -> windows::core::Result<UserConsentVerificationResult> {
        UserConsentVerifier::RequestVerificationAsync(&message)?.get()
    })()
    .map_err(|e| LockeError::BiometricDenied {
        reason: format!("denied: verification failed: {e}"),
    })?;

    match result {
        UserConsentVerificationResult::Verified => {
            warm_bio_cache();
            write_bio_session();
            Ok(())
        }
        UserConsentVerificationResult::Canceled => Err(LockeError::BiometricDenied {
            reason: "cancelled by user".to_string(),
        }),
        other => Err(LockeError::BiometricDenied {
            reason: format!("denied (result: {other:?})"),
        }),
    }
}

#[cfg(not(windows))]
fn verify_windows_hello() -> Result<(), LockeError> {
    // No Windows Hello off Windows; treated as a pass-through by callers.
    Ok(())
}

/// Gate access behind biometric verification when enabled.
///
/// No-op when biometric is disabled, on Linux, or when the in-memory cache or
/// persistent session is still valid. In non-interactive shells the prompt is
/// skipped with a warning (keystore access proceeds ungated, relying on the OS
/// user session). On macOS, Touch ID gating is logged as not-implemented and
/// passes through.
fn require_biometric() -> Result<(), LockeError> {
    if !biometric_enabled() {
        return Ok(());
    }

    // Linux has no biometric support.
    if cfg!(target_os = "linux") {
        return Ok(());
    }

    // Cache / session shortcuts (apply on every platform that gets here).
    if bio_cache_valid() {
        return Ok(());
    }
    if read_bio_session() {
        warm_bio_cache();
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        eprintln!("DEBUG: macOS Touch ID gating not yet implemented");
        return Ok(());
    }

    #[cfg(windows)]
    {
        if !is_interactive() {
            eprintln!(
                "WARNING: Non-interactive shell detected — skipping Windows Hello prompt. \
                 Keystore access proceeds without biometric gate."
            );
            return Ok(());
        }
        verify_windows_hello()
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Direct Windows Credential Manager access (bypasses keyring naming)
// ---------------------------------------------------------------------------

/// Read a credential from Windows Credential Manager by exact target name.
///
/// Bypasses keyring's `{service}/{username}` naming convention to access
/// credentials stored under bare target names (mirrors Python
/// `_wincred_read_by_target`). Returns None when not found or not on Windows.
#[cfg(windows)]
fn wincred_read_by_target(target: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    // Build a NUL-terminated UTF-16 target name.
    let target_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();

    let ok = unsafe {
        CredReadW(
            PCWSTR(target_w.as_ptr()),
            CRED_TYPE_GENERIC,
            None,
            &mut pcred,
        )
    };
    if ok.is_err() || pcred.is_null() {
        return None;
    }

    let result = unsafe {
        let cred = &*pcred;
        let size = cred.CredentialBlobSize as usize;
        let value = if size == 0 || cred.CredentialBlob.is_null() {
            None
        } else {
            let blob = std::slice::from_raw_parts(cred.CredentialBlob, size);
            // Stored as UTF-16-LE bytes (mirrors Python decode("utf-16-le")).
            if size % 2 == 0 {
                let utf16: Vec<u16> = blob
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&utf16).ok()
            } else {
                None
            }
        };
        CredFree(pcred as *const _ as *mut _);
        value
    };
    result
}

#[cfg(not(windows))]
fn wincred_read_by_target(_target: &str) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// keyring helpers
// ---------------------------------------------------------------------------

fn keystore_unavailable() -> LockeError {
    LockeError::KeystoreUnavailable {
        platform: std::env::consts::OS.to_string(),
        service: "keyring".to_string(),
    }
}

fn make_entry(service: &str, name: &str) -> Result<keyring::Entry, LockeError> {
    keyring::Entry::new(service, name).map_err(|_| keystore_unavailable())
}

/// Read a password via keyring, returning None on NoEntry.
fn keyring_get(service: &str, name: &str) -> Result<Option<String>, LockeError> {
    let entry = make_entry(service, name)?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(keystore_unavailable()),
    }
}

// ---------------------------------------------------------------------------
// Credential CRUD
// ---------------------------------------------------------------------------

/// Retrieve a credential from the OS keystore.
///
/// When biometric is enabled on Windows, triggers a Windows Hello prompt
/// (cached after first verification). Tries the canonical `locke` service
/// first, then falls back to legacy naming patterns. Returns None if the
/// credential is not found.
pub fn get_credential(name: &str) -> Result<Option<String>, LockeError> {
    require_biometric()?;

    if let Some(value) = keyring_get(SERVICE_NAME, name)? {
        return Ok(Some(value));
    }

    // Canonical lookup missed — try legacy patterns.
    let mut tried_wincred: Vec<String> = Vec::new();
    for (target, username) in legacy_lookups_for(name) {
        let mut value = keyring_get(&target, &username).unwrap_or_default();

        // On Windows, keyring constructs the target as "{service}/{username}"
        // which doesn't match credentials stored under bare target names. Fall
        // back to direct CredRead by exact target name.
        if value.is_none() && !tried_wincred.contains(&target) {
            tried_wincred.push(target.clone());
            value = wincred_read_by_target(&target);
        }

        if let Some(v) = value {
            eprintln!(
                "WARNING: Credential '{name}' found under legacy name (target={target:?}). \
                 Run 'locke keystore migrate' to update to the new naming."
            );
            return Ok(Some(v));
        }
    }

    Ok(None)
}

/// Store a credential in the OS keystore.
///
/// When biometric is enabled on Windows, triggers a Windows Hello prompt
/// before storing.
pub fn set_credential(name: &str, value: &str) -> Result<(), LockeError> {
    require_biometric()?;
    let entry = make_entry(SERVICE_NAME, name)?;
    entry.set_password(value).map_err(|_| keystore_unavailable())
}

/// Remove a credential from the OS keystore.
pub fn delete_credential(name: &str) -> Result<(), LockeError> {
    require_biometric()?;
    let entry = make_entry(SERVICE_NAME, name)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(keystore_unavailable()),
    }
}

// ---------------------------------------------------------------------------
// Legacy credential migration
// ---------------------------------------------------------------------------

/// A legacy credential discovered under an older naming convention.
#[derive(Debug, Clone)]
pub struct LegacyCredential {
    pub locke_name: String,
    pub legacy_target: String,
    pub legacy_username: String,
    pub already_migrated: bool,
}

/// Scan for credentials stored under legacy naming conventions.
///
/// When `names` is None, only `LOCKE_VAULT_PASSWORD` is checked, since
/// project-specific `*_CONFIG_ENCRYPTION_KEY` names cannot be enumerated.
pub fn find_legacy_credentials(
    names: Option<&[String]>,
) -> Result<Vec<LegacyCredential>, LockeError> {
    let candidates: Vec<String> = match names {
        Some(n) => n.to_vec(),
        None => vec!["LOCKE_VAULT_PASSWORD".to_string()],
    };

    let mut found = Vec::new();
    for name in candidates {
        let mut tried: Vec<String> = Vec::new();
        for (target, username) in legacy_lookups_for(&name) {
            let mut value = keyring_get(&target, &username).unwrap_or(None);
            if value.is_none() && !tried.contains(&target) {
                tried.push(target.clone());
                value = wincred_read_by_target(&target);
            }
            if value.is_some() {
                let current = keyring_get(SERVICE_NAME, &name).unwrap_or(None);
                found.push(LegacyCredential {
                    locke_name: name.clone(),
                    legacy_target: target,
                    legacy_username: username,
                    already_migrated: current.is_some(),
                });
            }
        }
    }
    Ok(found)
}

/// Copy a legacy credential into the Locke namespace.
///
/// Returns the legacy source description (e.g. `target="myproject"`) if
/// migration succeeded, or None if no legacy credential was found.
pub fn migrate_credential(name: &str, delete_legacy: bool) -> Result<Option<String>, LockeError> {
    require_biometric()?;

    let mut tried: Vec<String> = Vec::new();
    for (target, username) in legacy_lookups_for(name) {
        let mut value = keyring_get(&target, &username).unwrap_or(None);
        if value.is_none() && !tried.contains(&target) {
            tried.push(target.clone());
            value = wincred_read_by_target(&target);
        }
        if let Some(v) = value {
            let entry = make_entry(SERVICE_NAME, name)?;
            entry.set_password(&v).map_err(|_| keystore_unavailable())?;
            let source = format!("target={target:?}");
            if delete_legacy {
                if let Ok(legacy_entry) = make_entry(&target, &username) {
                    let _ = legacy_entry.delete_credential();
                }
            }
            return Ok(Some(source));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // Env-var manipulation in tests must be serialized: the process env is
    // global shared state and these tests mutate LOCKE_USE_BIOMETRIC etc.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            EnvGuard { key, prev }
        }
        fn unset(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            EnvGuard { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn biometric_enabled_default_true() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::unset("LOCKE_USE_BIOMETRIC");
        assert!(biometric_enabled());
    }

    #[test]
    fn biometric_enabled_false_variants() {
        let _lock = ENV_LOCK.lock().unwrap();
        for v in ["false", "FALSE", "0", "no", "No", " false "] {
            let _g = EnvGuard::set("LOCKE_USE_BIOMETRIC", v);
            assert!(!biometric_enabled(), "expected disabled for {v:?}");
        }
    }

    #[test]
    fn biometric_enabled_true_variants() {
        let _lock = ENV_LOCK.lock().unwrap();
        for v in ["true", "1", "yes", "anything"] {
            let _g = EnvGuard::set("LOCKE_USE_BIOMETRIC", v);
            assert!(biometric_enabled(), "expected enabled for {v:?}");
        }
    }

    #[test]
    fn require_biometric_noop_when_disabled() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("LOCKE_USE_BIOMETRIC", "false");
        // Must not prompt or error when disabled.
        assert!(require_biometric().is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn require_biometric_noop_on_linux() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set("LOCKE_USE_BIOMETRIC", "true");
        // On Linux, biometric gating is always a no-op even when enabled.
        assert!(require_biometric().is_ok());
    }

    #[test]
    fn session_hmac_matches_known_value() {
        // Known-answer test computed from the same algorithm Python uses:
        // HMAC-SHA256(key=machine_id, msg="{verified_at}|{machine_id}|{username}")
        // with verified_at rendered as Python str(float) -> "1700000000.0".
        let machine_id = "test-machine-guid";
        let username = "tester";
        let verified_at = 1_700_000_000.0_f64;

        let got = compute_session_hmac(verified_at, machine_id, username);

        // Recompute independently to lock the message format.
        let msg = "1700000000.0|test-machine-guid|tester";
        let mut mac = HmacSha256::new_from_slice(machine_id.as_bytes()).unwrap();
        mac.update(msg.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        assert_eq!(got, expected);
        // Sanity: stable, 64 hex chars.
        assert_eq!(got.len(), 64);
    }

    #[test]
    fn format_verified_at_python_parity() {
        assert_eq!(format_verified_at(1_700_000_000.0), "1700000000.0");
        assert_eq!(format_verified_at(1_700_000_000.5), "1700000000.5");
        assert_eq!(format_verified_at(0.0), "0.0");
    }

    /// Build a session JSON object with a valid HMAC for the current machine/user.
    fn make_session_json(verified_at: f64, machine_id: &str, username: &str) -> serde_json::Value {
        serde_json::json!({
            "verified_at": verified_at,
            "machine_id": machine_id,
            "username": username,
            "hmac": compute_session_hmac(verified_at, machine_id, username),
        })
    }

    fn write_session(dir: &std::path::Path, value: &serde_json::Value) {
        std::fs::write(
            dir.join(BIO_SESSION_FILE),
            serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
    }

    /// Run a closure with LOCALAPPDATA/HOME pointed at `dir` so the session
    /// file resolves inside the temp directory.
    fn with_session_dir<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _g1 = EnvGuard::set("LOCALAPPDATA", dir.to_str().unwrap());
        let _g2 = EnvGuard::set("HOME", dir.to_str().unwrap());
        // get_bio_session_dir appends "locke" under LOCALAPPDATA on Windows and
        // ".locke" under HOME elsewhere; create it so writes/reads line up.
        let _ = get_bio_session_dir();
        f();
    }

    #[test]
    fn session_accept_good() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_session_dir(tmp.path(), || {
            let sdir = get_bio_session_dir().unwrap();
            let mid = get_machine_id();
            let user = get_username();
            let session = make_session_json(now_unix(), &mid, &user);
            write_session(&sdir, &session);
            assert!(read_bio_session(), "freshly written session should validate");
        });
    }

    #[test]
    fn session_reject_tampered() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_session_dir(tmp.path(), || {
            let sdir = get_bio_session_dir().unwrap();
            let mid = get_machine_id();
            let user = get_username();
            let mut session = make_session_json(now_unix(), &mid, &user);
            // Corrupt the HMAC.
            session["hmac"] = serde_json::Value::String("0".repeat(64));
            write_session(&sdir, &session);
            assert!(!read_bio_session(), "tampered HMAC must be rejected");
        });
    }

    #[test]
    fn session_reject_wrong_machine() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_session_dir(tmp.path(), || {
            let sdir = get_bio_session_dir().unwrap();
            let user = get_username();
            // A different machine_id than the host: HMAC is self-consistent but
            // the machine binding check must reject it.
            let session = make_session_json(now_unix(), "some-other-machine", &user);
            write_session(&sdir, &session);
            assert!(!read_bio_session(), "wrong machine must be rejected");
        });
    }

    #[test]
    fn session_reject_expired() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _ttl = EnvGuard::set("LOCKE_BIO_SESSION_TTL", "10");
        with_session_dir(tmp.path(), || {
            let sdir = get_bio_session_dir().unwrap();
            let mid = get_machine_id();
            let user = get_username();
            // verified_at well in the past (age > TTL).
            let session = make_session_json(now_unix() - 1000.0, &mid, &user);
            write_session(&sdir, &session);
            assert!(!read_bio_session(), "expired session must be rejected");
        });
    }

    #[test]
    fn session_roundtrip_write_then_read() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        with_session_dir(tmp.path(), || {
            reset_bio_cache();
            write_bio_session();
            assert!(read_bio_session(), "written session should validate");
            assert!(invalidate_bio_session(), "session file should be removed");
            assert!(!read_bio_session(), "session must be gone after invalidate");
        });
    }

    #[test]
    fn cache_reset_clears_validity() {
        warm_bio_cache();
        assert!(bio_cache_valid());
        reset_bio_cache();
        assert!(!bio_cache_valid());
    }

    #[test]
    fn legacy_lookups_for_vault_password() {
        let pairs = legacy_lookups_for("LOCKE_VAULT_PASSWORD");
        assert_eq!(
            pairs,
            vec![("locke-bio".to_string(), "LOCKE_VAULT_PASSWORD".to_string())]
        );
    }

    #[test]
    fn legacy_lookups_for_config_key() {
        let pairs = legacy_lookups_for("MYAPP_CONFIG_ENCRYPTION_KEY");
        assert_eq!(
            pairs,
            vec![
                ("myapp".to_string(), "config-encryption-key".to_string()),
                ("myapp".to_string(), "config_encryption_key".to_string()),
                (
                    "config-encryption-key@myapp".to_string(),
                    "config-encryption-key".to_string()
                ),
            ]
        );
    }

    #[test]
    fn legacy_lookups_for_unknown_name() {
        assert!(legacy_lookups_for("SOMETHING_ELSE").is_empty());
    }
}
