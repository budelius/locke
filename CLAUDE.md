# CLAUDE.md

Guidance for Claude Code when working with this repository.

## Project Overview

**Locke** is a unified credentials framework — a polyglot library (Python,
TypeScript, Rust) and CLI that gives any project a consistent way to manage
secrets: encrypted configs checked into git, OS keystore resolution,
environment-variable fallback, and Vaultwarden integration.

## Architecture

### Credential Resolution Pipeline

Pluggable backends evaluated in priority order:

1. **OS Keystore** — Windows Credential Manager (via `keyring`/`keytar`),
   macOS Keychain, or Linux Secret Service
2. **Environment variables** — `LOCKE_ENCRYPTION_KEY`, `LOCKE_VAULT_PASSWORD`, etc.

On Windows, Windows Hello biometrics gate access to the OS keystore by default.

### Two Categories of Secrets

| Category | Storage | Checked In? | Example |
|----------|---------|-------------|---------|
| **Shared project secrets** | `config.encrypted.json` in repo | Yes (encrypted) | DB URIs, Sentry DSN, CDN keys |
| **Per-developer secrets** | Vaultwarden (personal vault) | Never | API keys, personal tokens |

### Encryption Spec

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **KDF**: PBKDF2-SHA256, 100,000 iterations
- **IV**: 12 bytes random per encryption
- **Auth tag**: 16 bytes
- **Key**: 32-byte passphrase (hex or base64 encoded)
- **File format version**: 2

### Encryption Key Resolution

Each project picks its own encryption key name. Locke resolves it — it does not
impose a namespace. Example:

```python
from locke import load_config
config = load_config("config.encrypted.json", key_name="MYAPP_CONFIG_ENCRYPTION_KEY")
```

The key is stored in the OS keystore (service `locke`) or as an env var.

### Vaultwarden Integration

- Bitwarden-compatible API via `httpx` (direct REST calls, no SDK)
- Connection requires: `LOCKE_VAULT_URL`, `LOCKE_VAULT_USERNAME`, and a password
  from the OS keystore or env var `LOCKE_VAULT_PASSWORD`
- Import via API: `locke vault import csv|azure|kv|gcp` creates or updates
  secrets directly (no duplicates on re-import)

### Config Flattening

Nested JSON configs flatten to `SCREAMING_SNAKE_CASE`:

```
{ "mongo": { "uri": "..." } }  →  MONGO_URI=...
```

## Key Design Decisions

- **OS keystore is the root of trust** for local development
- **Encoding auto-detection**: both hex and base64 accepted for backward
  compatibility with encrypted configs
- **Graceful degradation**: dev/staging warn and fall back to `.env`; production
  must fail hard
- **Windows Hello**: enabled on Windows unless `LOCKE_USE_BIOMETRIC=false`
- **Python version support**: 3.11–3.14 with explicit upper bound (`<3.15`)
- **Cross-language parity**: Python, TypeScript, and Rust implementations must
  produce identical encrypt/decrypt results, verified by shared test vectors in
  `test-vectors/`

## Repository Layout

```
locke/
├── python/        # Python package
├── typescript/    # TypeScript package
├── rust/          # Rust crate
├── test-vectors/  # Cross-language parity vectors
├── templates/     # Example configs + bootstrap guide
└── scripts/       # Version bumping helpers
```

## Testing

```bash
# Python
cd python && pip install -e ".[dev]" && pytest

# TypeScript
cd typescript && npm install && npm test

# Rust
cd rust && cargo test
```

Cross-language parity must be maintained: any change to the encryption format
or resolution logic needs matching changes and test updates in all three
implementations, validated against `test-vectors/`.
