//! Credential resolution pipeline.
//!
//! Evaluates backends in priority order:
//! 1. OS Keystore
//! 2. Environment variable
//! 3. GitLab CLI (glab)
//! 4. .env file fallback (dev/staging only)

use chrono::{DateTime, Utc};

use crate::env::is_production;
use crate::errors::LockeError;
use crate::keystore;

#[derive(Debug, Clone)]
pub struct Credential {
    pub name: String,
    pub value: String,
    pub source: String,
    pub resolved_at: String,
}

fn resolve_from_keystore(name: &str) -> Option<String> {
    // Biometric errors (denied / unavailable) are treated as "keystore
    // unavailable" so the pipeline falls through to env var, GitLab CLI, and
    // .env backends. This enables graceful degradation in non-interactive
    // shells where Windows Hello cannot prompt (mirrors the Python pipeline).
    match keystore::get_credential(name) {
        Ok(value) => value,
        Err(
            LockeError::BiometricDenied { .. } | LockeError::BiometricUnavailable { .. },
        ) => {
            eprintln!(
                "WARNING: Biometric gating prevented keystore access for '{name}' — \
                 trying remaining backends."
            );
            None
        }
        Err(_) => None,
    }
}

fn resolve_from_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Return glab's stdout as a token only if it is one whitespace-free line.
///
/// glab versions without an `auth token` subcommand print the `glab auth` help
/// page to stdout and exit 0, and a logged-out glab prints a "no token found"
/// message. Neither is a credential; a token never contains whitespace.
fn as_glab_token(stdout: &str) -> Option<String> {
    let value = stdout.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return None;
    }
    Some(value.to_string())
}

fn resolve_from_glab(name: &str) -> Option<String> {
    use std::process::Command;

    // Check if glab is available
    if Command::new("glab").arg("version").output().is_err() {
        return None;
    }

    // Try glab variable get
    if let Ok(output) = Command::new("glab")
        .args(["variable", "get", name])
        .output()
    {
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    // For auth tokens, try glab auth token
    let upper = name.to_uppercase();
    if upper.contains("TOKEN") || upper.contains("GLAB") {
        if let Ok(output) = Command::new("glab").args(["auth", "token"]).output() {
            if output.status.success() {
                if let Some(token) = as_glab_token(&String::from_utf8_lossy(&output.stdout)) {
                    return Some(token);
                }
            }
        }
    }

    None
}

fn resolve_from_dotenv(name: &str) -> Option<String> {
    use std::fs;
    use std::path::Path;

    let dotenv_path = Path::new(".env");
    if !dotenv_path.exists() {
        return None;
    }

    let content = fs::read_to_string(dotenv_path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let mut value = trimmed[eq_pos + 1..].trim().to_string();
            // Remove surrounding quotes
            if value.len() >= 2 {
                let first = value.as_bytes()[0];
                let last = value.as_bytes()[value.len() - 1];
                if first == last && (first == b'"' || first == b'\'') {
                    value = value[1..value.len() - 1].to_string();
                }
            }
            if key == name {
                eprintln!(
                    "WARNING: Credential '{}' resolved from .env file (fallback). Consider storing in OS keystore instead.",
                    name
                );
                return Some(value);
            }
        }
    }

    None
}

struct Backend {
    name: &'static str,
    resolver: fn(&str) -> Option<String>,
}

const BACKENDS: &[Backend] = &[
    Backend {
        name: "keystore",
        resolver: resolve_from_keystore,
    },
    Backend {
        name: "env_var",
        resolver: resolve_from_env,
    },
    Backend {
        name: "gitlab_cli",
        resolver: resolve_from_glab,
    },
    Backend {
        name: "dotenv",
        resolver: resolve_from_dotenv,
    },
];

pub fn resolve_credential(name: &str) -> Result<Credential, LockeError> {
    let mut backends_searched = Vec::new();

    for backend in BACKENDS {
        if backend.name == "dotenv" && is_production() {
            continue;
        }

        backends_searched.push(backend.name.to_string());
        if let Some(value) = (backend.resolver)(name) {
            return Ok(Credential {
                name: name.to_string(),
                value,
                source: backend.name.to_string(),
                resolved_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    Err(LockeError::CredentialNotFound {
        name: name.to_string(),
        backends_searched,
    })
}

#[cfg(test)]
mod glab_token_shape_tests {
    use super::as_glab_token;

    #[test]
    fn refuses_help_text_and_messages() {
        let help =
            "\n  Manages authentication for glab against one or more GitLab instances.\n  USAGE\n";
        assert_eq!(as_glab_token(help), None);
        assert_eq!(
            as_glab_token("! No token found (checked config file).\n"),
            None
        );
        assert_eq!(as_glab_token("  \n"), None);
    }

    #[test]
    fn accepts_a_single_token_line() {
        assert_eq!(
            as_glab_token("glpat-abc_DEF-123\n"),
            Some("glpat-abc_DEF-123".to_string())
        );
    }
}
