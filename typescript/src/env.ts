/**
 * Environment detection.
 *
 * Determines the current environment (development, staging, production)
 * by checking environment variables in priority order.
 */

const ENV_VAR_PRIORITY = [
  "LOCKE_ENV",
  "NODE_ENV",
  "PYTHON_ENV",
  "RAILS_ENV",
  "FLASK_ENV",
  "APP_ENV",
] as const;

const DEFAULT_ENVIRONMENT = "development";

export function detectEnvironment(): string {
  for (const varName of ENV_VAR_PRIORITY) {
    const value = process.env[varName];
    if (value) {
      return value.toLowerCase().trim();
    }
  }
  return DEFAULT_ENVIRONMENT;
}

export function isProduction(): boolean {
  return detectEnvironment() === "production";
}

export function isDevelopment(): boolean {
  return detectEnvironment() === "development";
}
