# Changelog

All notable changes to Locke are documented here. Versions are kept aligned
across the Python, TypeScript, and Rust packages.

## [Unreleased]

### Added

- Added Python `locke genkeys` / `locke-genkeys` commands to replace
  project-local generation scripts. They discover the project-root `.env` and
  read `LOCKE_INPUT_DIR`, `LOCKE_OUTPUT_DIR`, and `LOCKE_KEY_NAME` from it.
- Added Python `locke strip-jsonc` / `locke-strip-jsonc` commands for converting
  JSONC files to strict JSON.

## [0.9.1] - 2026-07-21

### Fixed

- Python Vaultwarden connections now resolve `LOCKE_VAULT_URL` and
  `LOCKE_VAULT_USERNAME` from the process environment first, then from `./.env`
  in development and staging.
- Production continues to ignore `.env`, and the vault password remains behind
  the keystore-first credential pipeline.

### Documentation

- Documented vault connection-setting precedence and production behavior.

## [0.9.0] - 2026-07-12

### Added

- Python OpenBao KV v1/v2 support with secret and combined-credential APIs.
- `locke openbao get` and `locke openbao set` commands.

## [0.8.0] - 2026-05-07

### Added

- Cross-language Vaultwarden read/write and import support.
- Combined username/password credentials and placeholder handling.
- Windows Hello biometric gating.

## [0.7.0] - 2026-04-23

### Added

- JSONC support for all configuration reads in Python, TypeScript, and Rust.

[0.9.1]: https://gitlab.com/martin-wieser/locke/-/compare/v0.9.0...v0.9.1
[0.9.0]: https://gitlab.com/martin-wieser/locke/-/compare/v0.8.0...v0.9.0
[0.8.0]: https://gitlab.com/martin-wieser/locke/-/compare/v0.7.0...v0.8.0
[0.7.0]: https://gitlab.com/martin-wieser/locke/-/compare/v0.6.1...v0.7.0
