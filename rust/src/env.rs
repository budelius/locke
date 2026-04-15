//! Environment detection.
//!
//! Determines the current environment (development, staging, production)
//! by checking environment variables in priority order.

const ENV_VAR_PRIORITY: &[&str] = &[
    "LOCKE_ENV",
    "NODE_ENV",
    "PYTHON_ENV",
    "RAILS_ENV",
    "FLASK_ENV",
    "APP_ENV",
];

const DEFAULT_ENVIRONMENT: &str = "development";

pub fn detect_environment() -> String {
    for var_name in ENV_VAR_PRIORITY {
        if let Ok(value) = std::env::var(var_name) {
            if !value.is_empty() {
                return value.to_lowercase().trim().to_string();
            }
        }
    }
    DEFAULT_ENVIRONMENT.to_string()
}

pub fn is_production() -> bool {
    detect_environment() == "production"
}

pub fn is_development() -> bool {
    detect_environment() == "development"
}
