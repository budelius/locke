//! `locke vault import` — push secrets to Vaultwarden via API.
//!
//! Mirrors `python/locke/cli/vault_import.py`. Uses the Bitwarden-compatible
//! API (via `VaultClient`) to create or update secrets directly, avoiding
//! duplicates on repeated imports.
//!
//! Modes:
//!   - csv:   import a standard Bitwarden CSV file
//!   - azure: import Azure tenant credentials (env/CLI overrides)
//!   - kv:    import arbitrary key-value secrets (env/file/inline)
//!   - gcp:   import GCP service-account / OAuth credential JSON files
//!
//! Shared flags: `--dry-run`, `--export-json <path>`, `--env-file <path>`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process;

use locke::VaultClient;

// ---------------------------------------------------------------------------
// Secret model
// ---------------------------------------------------------------------------

/// A single secret to import, with full Bitwarden login fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    pub folder: String,
    pub value: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
}

impl Secret {
    fn basic(name: String, folder: String, value: String) -> Self {
        Secret {
            name,
            folder,
            value,
            username: None,
            uri: None,
            notes: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

/// Azure credential field definitions: (secret-name, env-var, description).
pub const AZURE_FIELDS: &[(&str, &str, &str)] = &[
    ("azure-tenant-id", "AZURE_TENANT_ID", "Azure AD tenant ID"),
    ("azure-client-id", "AZURE_CLIENT_ID", "Azure AD app client ID"),
    (
        "azure-client-secret",
        "AZURE_CLIENT_SECRET",
        "Azure AD app client secret",
    ),
    (
        "azure-user-principal-name",
        "AZURE_USER_PRINCIPAL_NAME",
        "User principal name",
    ),
];

/// Return Vaultwarden secret names for the given Azure account index.
///
/// Index 1 (default): `azure-tenant-id`, `azure-client-id`, ...
/// Index 2+:          `azure-2-tenant-id`, `azure-2-client-id`, ...
pub fn azure_secret_names(index: i64) -> Vec<String> {
    let base_names: Vec<&str> = AZURE_FIELDS.iter().map(|(n, _, _)| *n).collect();
    if index == 1 {
        return base_names.iter().map(|s| s.to_string()).collect();
    }
    let prefix = format!("azure-{index}-");
    base_names
        .iter()
        .map(|name| {
            // name.split('-', 1)[1] in Python: drop the leading "azure-".
            let rest = name.split_once('-').map(|x| x.1).unwrap_or(name);
            format!("{prefix}{rest}")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Mask a secret value for display (mirrors Python `_mask`).
pub fn mask(value: &str) -> String {
    if value.chars().count() <= 8 {
        return "****".to_string();
    }
    let chars: Vec<char> = value.chars().collect();
    let first: String = chars[..4].iter().collect();
    let last: String = chars[chars.len() - 4..].iter().collect();
    format!("{first}...{last}")
}

/// Convert SCREAMING_SNAKE_CASE env var to kebab-case secret name.
///
/// `BUNNY_API_KEY` -> `bunny-api-key`
pub fn env_to_secret_name(env_key: &str) -> String {
    env_key.to_lowercase().replace('_', "-")
}

/// Load a .env file into the process environment without overriding existing
/// values (mirrors Python `_load_dotenv` / `os.environ.setdefault`).
pub fn load_dotenv(path: &str) {
    let p = Path::new(path);
    if !p.is_file() {
        return;
    }
    let content = match std::fs::read_to_string(p) {
        Ok(c) => c,
        Err(_) => return,
    };
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        let mut value = value.to_string();
        // Strip matching surrounding quotes.
        let bytes = value.as_bytes();
        if bytes.len() >= 2 && bytes[0] == bytes[bytes.len() - 1] && (bytes[0] == b'"' || bytes[0] == b'\'') {
            value = value[1..value.len() - 1].to_string();
        }
        if std::env::var(key).is_err() {
            std::env::set_var(key, value);
        }
    }
}

// ---------------------------------------------------------------------------
// GCP detection / entry building
// ---------------------------------------------------------------------------

const GCP_SA_TYPE: &str = "service_account";
const GCP_OAUTH_KEYS: &[&str] = &["web", "installed"];

/// Detected GCP credential file type.
#[derive(Debug, PartialEq, Eq)]
pub enum GcpType {
    ServiceAccount,
    OauthClient,
}

/// Detect the type of GCP credential file from its parsed JSON content.
pub fn detect_gcp_type(data: &serde_json::Value) -> Option<GcpType> {
    if data.get("type").and_then(|t| t.as_str()) == Some(GCP_SA_TYPE) {
        return Some(GcpType::ServiceAccount);
    }
    if GCP_OAUTH_KEYS.iter().any(|k| data.get(*k).is_some()) {
        return Some(GcpType::OauthClient);
    }
    None
}

/// Build a vault entry from a GCP service-account key file.
pub fn gcp_entry_from_sa(data: &serde_json::Value, project: &str, tenant: &str) -> Secret {
    let client_email = data
        .get("client_email")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let account_name = if client_email.contains('@') {
        client_email.split('@').next().unwrap_or("unknown")
    } else {
        "unknown"
    };
    let gcp_project = data
        .get("project_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let folder = format!("{project}/{tenant}");
    let item_name = format!("{project}/{tenant}/gcp-sa-{account_name}");
    Secret {
        name: item_name,
        folder,
        value: serde_json::to_string_pretty(data).unwrap_or_default(),
        username: Some(client_email.to_string()),
        uri: data
            .get("token_uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        notes: Some(format!(
            "GCP service account key for {client_email} (project: {gcp_project})"
        )),
    }
}

/// Build a vault entry from a GCP OAuth client-secret file.
pub fn gcp_entry_from_oauth(data: &serde_json::Value, project: &str, tenant: &str) -> Secret {
    let wrapper_key = GCP_OAUTH_KEYS
        .iter()
        .find(|k| data.get(**k).is_some())
        .copied();
    let inner = wrapper_key
        .and_then(|k| data.get(k))
        .unwrap_or(data);
    let client_id = inner
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let gcp_project = inner
        .get("project_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let folder = format!("{project}/{tenant}");
    let item_name = format!("{project}/{tenant}/gcp-oauth-{gcp_project}");
    Secret {
        name: item_name,
        folder,
        value: serde_json::to_string_pretty(data).unwrap_or_default(),
        username: Some(client_id.to_string()),
        uri: inner
            .get("token_uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        notes: Some(format!(
            "GCP OAuth {} client (project: {gcp_project})",
            wrapper_key.unwrap_or("unknown")
        )),
    }
}

// ---------------------------------------------------------------------------
// Bitwarden JSON export
// ---------------------------------------------------------------------------

/// Build the Bitwarden-compatible export JSON value (mirrors Python
/// `_export_bitwarden_json` / `_export_bitwarden_json_full`).
///
/// Folders are numbered by first appearance; `folderId` references the
/// zero-based index of the folder in insertion order (matching Python).
pub fn build_bitwarden_export(secrets: &[Secret]) -> serde_json::Value {
    let mut folders_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut folder_order: Vec<String> = Vec::new();
    let mut items: Vec<serde_json::Value> = Vec::new();

    for s in secrets {
        let folder = &s.folder;
        let folder_id: Option<usize> = if folder.is_empty() {
            None
        } else {
            if !folders_seen.contains_key(folder) {
                folders_seen.insert(folder.clone(), folder_order.len());
                folder_order.push(folder.clone());
            }
            Some(folders_seen[folder])
        };

        let uris = match &s.uri {
            Some(u) if !u.is_empty() => {
                serde_json::json!([{ "match": serde_json::Value::Null, "uri": u }])
            }
            _ => serde_json::json!([]),
        };

        items.push(serde_json::json!({
            "type": 1,
            "name": s.name,
            "folderId": folder_id,
            "login": {
                "username": s.username.clone().unwrap_or_default(),
                "password": s.value,
                "uris": uris,
            },
            "notes": s.notes,
            "favorite": false,
            "reprompt": 0,
        }));
    }

    let folders: Vec<serde_json::Value> = folder_order
        .iter()
        .enumerate()
        .map(|(i, name)| serde_json::json!({ "id": (i + 1).to_string(), "name": name }))
        .collect();

    serde_json::json!({
        "encrypted": false,
        "folders": folders,
        "items": items,
    })
}

/// Write the Bitwarden export JSON to `path` (pretty-printed, trailing newline).
pub fn write_bitwarden_export(secrets: &[Secret], path: &str) -> std::io::Result<()> {
    let export = build_bitwarden_export(secrets);
    let mut json = serde_json::to_string_pretty(&export)?;
    json.push('\n');
    std::fs::write(path, json)
}

// ---------------------------------------------------------------------------
// Import dispatch (export / dry-run / API)
// ---------------------------------------------------------------------------

/// Dispatch to export, dry-run, or API import. Mirrors Python `_run_import`.
fn run_import(secrets: &[Secret], dry_run: bool, export_path: Option<&str>) {
    if secrets.is_empty() {
        eprintln!("No secrets to import. Exiting.");
        process::exit(1);
    }

    if let Some(path) = export_path {
        match write_bitwarden_export(secrets, path) {
            Ok(()) => {
                println!("Bitwarden JSON written to: {path}");
                println!("  {} item(s)", secrets.len());
                println!();
                println!("  DELETE this file after import: rm {path}");
            }
            Err(e) => {
                eprintln!("Error writing export: {e}");
                process::exit(1);
            }
        }
        return;
    }

    if dry_run {
        println!("Dry run — no changes made. Secrets that would be imported:");
        for s in secrets {
            println!("  {}", s.name);
        }
        return;
    }

    import_via_api(secrets);
}

/// Connect, sync, and create/update each secret via the vault API.
fn import_via_api(secrets: &[Secret]) {
    println!("Connecting to Vaultwarden...");
    let mut client = match VaultClient::connect() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error connecting to vault: {e}");
            process::exit(1);
        }
    };

    println!("Syncing vault to check for existing secrets...");
    // Prime the cache so set_secret create/update detection sees existing items.
    if let Err(e) = client.sync(true) {
        eprintln!("Error syncing vault: {e}");
        process::exit(1);
    }

    let mut created = 0u32;
    let mut updated = 0u32;

    for s in secrets {
        let folder = if s.folder.is_empty() {
            Some("")
        } else {
            Some(s.folder.as_str())
        };
        let result = client.set_secret(
            &s.name,
            Some(s.value.as_str()),
            folder,
            s.username.as_deref(),
            s.uri.as_deref(),
            s.notes.as_deref(),
        );
        match result {
            Ok("updated") => {
                println!("  [UPD] {}", s.name);
                updated += 1;
            }
            Ok(_) => {
                println!("  [NEW] {}", s.name);
                created += 1;
            }
            Err(e) => {
                eprintln!("  [ERR] {} — {e}", s.name);
                process::exit(1);
            }
        }
    }

    println!("\nDone: {created} created, {updated} updated.");
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Parse a standard Bitwarden CSV into secrets. Returns the parsed secrets and
/// the count of rows skipped for an empty name.
pub fn parse_csv(path: &str) -> Result<Vec<Secret>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .map_err(|e| format!("cannot read CSV: {e}"))?;

    let mut secrets = Vec::new();
    for record in rdr.deserialize::<std::collections::HashMap<String, String>>() {
        let row = record.map_err(|e| format!("CSV parse error: {e}"))?;
        let get = |k: &str| row.get(k).map(|s| s.trim().to_string()).unwrap_or_default();

        let name = get("name");
        if name.is_empty() {
            continue;
        }
        let password = get("login_password");
        let username = get("login_username");
        let uri = get("login_uri");
        let notes = get("notes");

        secrets.push(Secret {
            name,
            folder: get("folder"),
            value: password,
            username: if username.is_empty() { None } else { Some(username) },
            uri: if uri.is_empty() { None } else { Some(uri) },
            notes: if notes.is_empty() { None } else { Some(notes) },
        });
    }
    Ok(secrets)
}

// ---------------------------------------------------------------------------
// Public command entry points (called from main.rs)
// ---------------------------------------------------------------------------

pub fn run_csv(csv_file: &str, env_file: Option<&str>, dry_run: bool, export_path: Option<&str>) {
    load_dotenv(env_file.unwrap_or(".env"));

    let secrets = match parse_csv(csv_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if secrets.is_empty() {
        eprintln!("No secrets to import (CSV empty or all rows skipped).");
        process::exit(1);
    }

    println!("\nParsed {} entry/entries from {csv_file}", secrets.len());
    println!("{}", "=".repeat(60));
    for s in &secrets {
        let display = if s.value.is_empty() {
            "(no password)".to_string()
        } else {
            mask(&s.value)
        };
        println!("  [OK]   {} = {display}", s.name);
    }
    println!();

    run_import(&secrets, dry_run, export_path);
}

#[allow(clippy::too_many_arguments)]
pub fn run_azure(
    tenant: &str,
    project: &str,
    account_index: i64,
    azure_tenant_id: Option<&str>,
    azure_client_id: Option<&str>,
    azure_client_secret: Option<&str>,
    azure_user_principal_name: Option<&str>,
    dry_run: bool,
    export_path: Option<&str>,
    env_file: Option<&str>,
) {
    load_dotenv(env_file.unwrap_or(".env"));

    let cli_overrides: [(&str, Option<&str>); 4] = [
        ("AZURE_TENANT_ID", azure_tenant_id),
        ("AZURE_CLIENT_ID", azure_client_id),
        ("AZURE_CLIENT_SECRET", azure_client_secret),
        ("AZURE_USER_PRINCIPAL_NAME", azure_user_principal_name),
    ];

    let secret_names = azure_secret_names(account_index);
    let folder = format!("{project}/{tenant}");

    let label = if account_index > 1 {
        format!("account #{account_index}")
    } else {
        "default account".to_string()
    };
    println!("\nAzure credentials for tenant '{tenant}' ({label})");
    println!("{}", "=".repeat(60));

    let mut secrets: Vec<Secret> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for (i, (_, env_var, _)) in AZURE_FIELDS.iter().enumerate() {
        let secret_name = &secret_names[i];
        let item_name = format!("{project}/{tenant}/{secret_name}");

        // CLI override wins; otherwise (only for the default account) read env.
        let mut value: Option<String> = cli_overrides[i].1.map(|s| s.to_string());
        if value.as_deref().unwrap_or("").is_empty() && account_index <= 1 {
            value = std::env::var(env_var).ok().filter(|s| !s.is_empty());
        }
        let value = value.filter(|s| !s.is_empty());

        match value {
            Some(v) => {
                println!("  [OK]   {item_name} = {} ({} chars)", mask(&v), v.len());
                secrets.push(Secret::basic(item_name, folder.clone(), v));
            }
            None => {
                println!("  [MISS] {item_name} (not set)");
                missing.push(secret_name.clone());
            }
        }
    }
    println!();

    if !missing.is_empty() {
        println!(
            "WARNING: {} secret(s) missing: {}",
            missing.len(),
            missing.join(", ")
        );
        if account_index > 1 {
            println!("For additional accounts, pass values via --azure-* flags.");
        } else {
            println!("Set them in your .env file or pass via --azure-* flags.");
        }
        println!();
    }

    run_import(&secrets, dry_run, export_path);
}

#[allow(clippy::too_many_arguments)]
pub fn run_kv(
    folder: &str,
    env_keys: &[String],
    secrets_file: Option<&str>,
    inline_secrets: &[(String, String)],
    dry_run: bool,
    export_path: Option<&str>,
    env_file: Option<&str>,
) {
    load_dotenv(env_file.unwrap_or(".env"));

    println!("\nSecrets for folder '{folder}'");
    println!("{}", "=".repeat(60));

    let mut secrets: Vec<Secret> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    // From env vars.
    for env_key in env_keys {
        let value = std::env::var(env_key).unwrap_or_default();
        let secret_name = env_to_secret_name(env_key);
        let item_name = format!("{folder}/{secret_name}");
        if !value.is_empty() {
            println!("  [OK]   {item_name} = {} ({} chars)", mask(&value), value.len());
            secrets.push(Secret::basic(item_name, folder.to_string(), value));
        } else {
            println!("  [MISS] {item_name} ({env_key} not set)");
            missing.push(env_key.clone());
        }
    }

    // From JSON file (supports JSONC via the locke jsonc parser).
    if let Some(file) = secrets_file {
        let contents = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading {file}: {e}");
                process::exit(1);
            }
        };
        let parsed: serde_json::Value = match locke::jsonc::parse_jsonc(&contents) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error parsing {file}: {e}");
                process::exit(1);
            }
        };
        if let Some(map) = parsed.as_object() {
            for (secret_name, value) in map {
                let item_name = format!("{folder}/{secret_name}");
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => String::new(),
                    other => other.to_string(),
                };
                if !value_str.is_empty() {
                    println!(
                        "  [OK]   {item_name} = {} ({} chars)",
                        mask(&value_str),
                        value_str.len()
                    );
                    secrets.push(Secret::basic(item_name, folder.to_string(), value_str));
                } else {
                    println!("  [MISS] {item_name} (empty value in file)");
                    missing.push(secret_name.clone());
                }
            }
        }
    }

    // Inline secrets.
    for (secret_name, value) in inline_secrets {
        let item_name = format!("{folder}/{secret_name}");
        println!("  [OK]   {item_name} = {} ({} chars)", mask(value), value.len());
        secrets.push(Secret::basic(item_name, folder.to_string(), value.clone()));
    }

    println!();

    if !missing.is_empty() {
        println!(
            "WARNING: {} secret(s) missing: {}",
            missing.len(),
            missing.join(", ")
        );
        println!();
    }

    run_import(&secrets, dry_run, export_path);
}

pub fn run_gcp(
    files: &[String],
    tenant: &str,
    project: &str,
    dry_run: bool,
    export_path: Option<&str>,
    env_file: Option<&str>,
) {
    load_dotenv(env_file.unwrap_or(".env"));

    println!("\nGCP credentials for tenant '{tenant}'");
    println!("{}", "=".repeat(60));

    let mut secrets: Vec<Secret> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for filepath in files {
        let contents = match std::fs::read_to_string(filepath) {
            Ok(c) => c,
            Err(e) => {
                println!("  [SKIP] {filepath} — {e}");
                skipped.push(filepath.clone());
                continue;
            }
        };
        let data: serde_json::Value = match locke::jsonc::parse_jsonc(&contents) {
            Ok(v) => v,
            Err(e) => {
                println!("  [SKIP] {filepath} — {e}");
                skipped.push(filepath.clone());
                continue;
            }
        };

        let gcp_type = match detect_gcp_type(&data) {
            Some(t) => t,
            None => {
                println!("  [SKIP] {filepath} — not a recognised GCP credential file");
                skipped.push(filepath.clone());
                continue;
            }
        };

        let (entry, label) = match gcp_type {
            GcpType::ServiceAccount => {
                let entry = gcp_entry_from_sa(&data, project, tenant);
                let email = data
                    .get("client_email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                (entry, format!("service-account ({email})"))
            }
            GcpType::OauthClient => {
                let wrapper = GCP_OAUTH_KEYS
                    .iter()
                    .find(|k| data.get(**k).is_some())
                    .copied()
                    .unwrap_or("?");
                let entry = gcp_entry_from_oauth(&data, project, tenant);
                let proj = data
                    .get(wrapper)
                    .and_then(|w| w.get("project_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                (entry, format!("oauth-{wrapper} ({proj})"))
            }
        };

        let json_len = entry.value.len();
        println!("  [OK]   {} — {label} ({json_len} chars)", entry.name);
        secrets.push(entry);
    }
    println!();

    if !skipped.is_empty() {
        println!("WARNING: {} file(s) skipped.", skipped.len());
        println!();
    }

    run_import(&secrets, dry_run, export_path);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_to_secret_name_derivation() {
        assert_eq!(env_to_secret_name("BUNNY_API_KEY"), "bunny-api-key");
        assert_eq!(
            env_to_secret_name("HETZNER_S3_ACCESS_KEY"),
            "hetzner-s3-access-key"
        );
    }

    #[test]
    fn azure_indexing_default() {
        let names = azure_secret_names(1);
        assert_eq!(
            names,
            vec![
                "azure-tenant-id",
                "azure-client-id",
                "azure-client-secret",
                "azure-user-principal-name",
            ]
        );
    }

    #[test]
    fn azure_indexing_second_account() {
        let names = azure_secret_names(2);
        assert_eq!(
            names,
            vec![
                "azure-2-tenant-id",
                "azure-2-client-id",
                "azure-2-client-secret",
                "azure-2-user-principal-name",
            ]
        );
    }

    #[test]
    fn azure_indexing_third_account() {
        let names = azure_secret_names(3);
        assert_eq!(names[0], "azure-3-tenant-id");
        assert_eq!(names[3], "azure-3-user-principal-name");
    }

    #[test]
    fn mask_short_and_long() {
        assert_eq!(mask("short"), "****");
        assert_eq!(mask("12345678"), "****");
        assert_eq!(mask("123456789"), "1234...6789");
        assert_eq!(mask("sk_live_abcdefg"), "sk_l...defg");
    }

    #[test]
    fn detect_gcp_service_account() {
        let data = serde_json::json!({ "type": "service_account", "client_email": "x@y.iam" });
        assert_eq!(detect_gcp_type(&data), Some(GcpType::ServiceAccount));
    }

    #[test]
    fn detect_gcp_oauth() {
        let web = serde_json::json!({ "web": { "client_id": "abc" } });
        assert_eq!(detect_gcp_type(&web), Some(GcpType::OauthClient));
        let installed = serde_json::json!({ "installed": { "client_id": "abc" } });
        assert_eq!(detect_gcp_type(&installed), Some(GcpType::OauthClient));
    }

    #[test]
    fn detect_gcp_unrecognized() {
        let data = serde_json::json!({ "foo": "bar" });
        assert_eq!(detect_gcp_type(&data), None);
    }

    #[test]
    fn gcp_sa_entry_building() {
        let data = serde_json::json!({
            "type": "service_account",
            "client_email": "svc@my-project.iam.gserviceaccount.com",
            "project_id": "my-project",
            "token_uri": "https://oauth2.googleapis.com/token",
        });
        let entry = gcp_entry_from_sa(&data, "myapp", "acme");
        assert_eq!(entry.name, "myapp/acme/gcp-sa-svc");
        assert_eq!(entry.folder, "myapp/acme");
        assert_eq!(
            entry.username.as_deref(),
            Some("svc@my-project.iam.gserviceaccount.com")
        );
        assert_eq!(
            entry.uri.as_deref(),
            Some("https://oauth2.googleapis.com/token")
        );
        assert_eq!(
            entry.notes.as_deref(),
            Some("GCP service account key for svc@my-project.iam.gserviceaccount.com (project: my-project)")
        );
        // The value is the full JSON, pretty-printed.
        assert!(entry.value.contains("service_account"));
        assert!(entry.value.contains('\n'));
    }

    #[test]
    fn gcp_oauth_entry_building() {
        let data = serde_json::json!({
            "web": {
                "client_id": "client-123.apps.googleusercontent.com",
                "project_id": "my-project",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        });
        let entry = gcp_entry_from_oauth(&data, "myapp", "acme");
        assert_eq!(entry.name, "myapp/acme/gcp-oauth-my-project");
        assert_eq!(entry.folder, "myapp/acme");
        assert_eq!(
            entry.username.as_deref(),
            Some("client-123.apps.googleusercontent.com")
        );
        assert_eq!(
            entry.uri.as_deref(),
            Some("https://oauth2.googleapis.com/token")
        );
        assert_eq!(
            entry.notes.as_deref(),
            Some("GCP OAuth web client (project: my-project)")
        );
    }

    #[test]
    fn export_json_shape() {
        let secrets = vec![
            Secret {
                name: "myapp/acme/azure-tenant-id".to_string(),
                folder: "myapp/acme".to_string(),
                value: "tenant-value".to_string(),
                username: None,
                uri: None,
                notes: None,
            },
            Secret {
                name: "myapp/acme/db".to_string(),
                folder: "myapp/acme".to_string(),
                value: "dbpass".to_string(),
                username: Some("dbuser".to_string()),
                uri: Some("https://db.example".to_string()),
                notes: Some("primary db".to_string()),
            },
        ];
        let export = build_bitwarden_export(&secrets);

        assert_eq!(export["encrypted"], serde_json::json!(false));

        // One folder, id="1".
        let folders = export["folders"].as_array().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0]["id"], serde_json::json!("1"));
        assert_eq!(folders[0]["name"], serde_json::json!("myapp/acme"));

        let items = export["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);

        // First item: no username/uri/notes.
        assert_eq!(items[0]["type"], serde_json::json!(1));
        assert_eq!(items[0]["name"], serde_json::json!("myapp/acme/azure-tenant-id"));
        assert_eq!(items[0]["folderId"], serde_json::json!(0));
        assert_eq!(items[0]["login"]["username"], serde_json::json!(""));
        assert_eq!(items[0]["login"]["password"], serde_json::json!("tenant-value"));
        assert_eq!(items[0]["login"]["uris"], serde_json::json!([]));
        assert_eq!(items[0]["notes"], serde_json::Value::Null);
        assert_eq!(items[0]["favorite"], serde_json::json!(false));
        assert_eq!(items[0]["reprompt"], serde_json::json!(0));

        // Second item: full fields with a URI entry.
        assert_eq!(items[1]["login"]["username"], serde_json::json!("dbuser"));
        assert_eq!(
            items[1]["login"]["uris"],
            serde_json::json!([{ "match": null, "uri": "https://db.example" }])
        );
        assert_eq!(items[1]["notes"], serde_json::json!("primary db"));
        assert_eq!(items[1]["folderId"], serde_json::json!(0));
    }

    #[test]
    fn export_json_multiple_folders_indexed() {
        let secrets = vec![
            Secret::basic("a/x".to_string(), "a".to_string(), "1".to_string()),
            Secret::basic("b/y".to_string(), "b".to_string(), "2".to_string()),
            Secret::basic("a/z".to_string(), "a".to_string(), "3".to_string()),
        ];
        let export = build_bitwarden_export(&secrets);
        let folders = export["folders"].as_array().unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0]["name"], serde_json::json!("a"));
        assert_eq!(folders[1]["name"], serde_json::json!("b"));
        let items = export["items"].as_array().unwrap();
        // a -> 0, b -> 1, a -> 0
        assert_eq!(items[0]["folderId"], serde_json::json!(0));
        assert_eq!(items[1]["folderId"], serde_json::json!(1));
        assert_eq!(items[2]["folderId"], serde_json::json!(0));
    }

    #[test]
    fn parse_csv_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.csv");
        std::fs::write(
            &path,
            "name,folder,login_username,login_password,login_uri,notes,type\n\
             db,myapp/infra,dbuser,s3cret,https://db,primary,login\n\
             ,emptyname,,,,,login\n\
             token,myapp/infra,,abc123,,,login\n",
        )
        .unwrap();

        let secrets = parse_csv(path.to_str().unwrap()).unwrap();
        assert_eq!(secrets.len(), 2); // empty-name row skipped

        assert_eq!(secrets[0].name, "db");
        assert_eq!(secrets[0].folder, "myapp/infra");
        assert_eq!(secrets[0].username.as_deref(), Some("dbuser"));
        assert_eq!(secrets[0].value, "s3cret");
        assert_eq!(secrets[0].uri.as_deref(), Some("https://db"));
        assert_eq!(secrets[0].notes.as_deref(), Some("primary"));

        assert_eq!(secrets[1].name, "token");
        assert_eq!(secrets[1].username, None);
        assert_eq!(secrets[1].value, "abc123");
        assert_eq!(secrets[1].uri, None);
    }

    #[test]
    fn load_dotenv_no_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(
            &path,
            "# comment\nLOCKE_TEST_DOTENV_A=\"quoted\"\nLOCKE_TEST_DOTENV_B=plain\n",
        )
        .unwrap();

        std::env::remove_var("LOCKE_TEST_DOTENV_A");
        std::env::set_var("LOCKE_TEST_DOTENV_B", "preexisting");

        load_dotenv(path.to_str().unwrap());

        assert_eq!(std::env::var("LOCKE_TEST_DOTENV_A").unwrap(), "quoted");
        // setdefault semantics: existing value preserved.
        assert_eq!(std::env::var("LOCKE_TEST_DOTENV_B").unwrap(), "preexisting");

        std::env::remove_var("LOCKE_TEST_DOTENV_A");
        std::env::remove_var("LOCKE_TEST_DOTENV_B");
    }
}
