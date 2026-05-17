# Locke: Project Credentials Guide

## Quick Start (Humans)

1. **Install Locke**: `pip install locke` / `npm install locke` / `cargo install locke`
2. **Store encryption key**: `locke keystore set {key_name} --prompt`
3. **Load secrets**: `eval $(locke env)` or use the library API
4. **Get vault secrets**: `locke vault get {project}/{tenant}/{name}`
5. **Validate setup**: `locke validate` — checks all keys from `locke.json` are reachable

## File Reference

| File | Purpose | Committed? |
|------|---------|------------|
| `locke.json` | Project config, classification rules, and **key registry** | Yes |
| `config.json` | Plaintext config (pre-encryption) | **NO** |
| `config.encrypted.*.json` | Encrypted shared secrets (per environment) | Yes |
| `.env.example` | Template for non-secret env vars | Yes |
| `vault-references.example.json` | Documents vault secret paths | Yes |
| `BOOTSTRAP.md` | This file | Yes |

## Key Registry (`locke.json` → `keys` section)

The `keys` section in `locke.json` is the single source of truth for **what secrets this project needs, where they live, and what they do**. It has four categories:

### `keys.keystore` — OS Keystore Credentials

Stored in the OS credential manager (service = `locke`). These are the root-of-trust secrets that unlock everything else.

| Example key | Purpose |
|-------------|---------|
| `{key_name}` | Decrypts `config.encrypted.*.json` for this project |
| `LOCKE_VAULT_PASSWORD` | Vaultwarden master password (shared across projects) |

**Set**: `locke keystore set {key_name} --prompt`
**Get**: `locke keystore get {key_name}`

### `keys.encryptedConfig` — Encrypted Config Contents

Keys inside `config.encrypted.*.json`. These are shared team secrets (DB URIs, API keys, service URLs) that are checked into the repo in encrypted form. Locke decrypts and flattens them to `SCREAMING_SNAKE_CASE` environment variables at runtime.

| JSON path | Flattened env var | Example |
|-----------|-------------------|---------|
| `mongo.uri` | `MONGO_URI` | `mongodb://user:pass@host:27017/` |
| `sentry.dsn` | `SENTRY_DSN` | `https://key@sentry.io/123` |
| `s3.access_key` | `S3_ACCESS_KEY` | Hetzner S3 access key |

**Decrypt**: `locke decrypt --key-name {key_name}`
**Encrypt**: `locke encrypt config.json --key-name {key_name}`
**Load as env**: `eval $(locke env --key-name {key_name})`

### `keys.vault` — Vaultwarden Secrets

Per-developer secrets stored in Vaultwarden (personal vault). These are **never** checked into the repo. Each entry maps a vault path to the environment variable it populates.

| Vault path | Env var | Purpose |
|------------|---------|---------|
| `{project}/{tenant}/api_key` | `API_KEY` | Personal API key |

Path format: `{project}/{tenant}/{secret_name}` (tenant-scoped) or `{project}/{category}/{secret_name}` (infra).

**Get**: `locke vault get {project}/{tenant}/{name}`
**Import**: `locke vault import csv vault-import.csv`
**Setup**: `locke vault setup --interactive`

#### Bootstrapping the Vault (first-time setup)

When cloning a project fresh, the vault entries listed under `keys.vault` don't exist in your personal Vaultwarden yet. Bootstrap them directly from the key registry:

```
locke vault setup
```

This creates missing vault entries with the `FILL_ME` placeholder so the team can add new vault paths before every developer knows their personal value. To fill values from the command line, run:

```
locke vault setup --interactive
```

Notes:
- The setup command is idempotent: re-running creates newly documented entries and leaves configured values alone.
- `locke validate` treats `FILL_ME` as not configured, so placeholders do not accidentally pass validation.
- You can still import a full CSV manually with `locke vault import csv .locke/{project}-vault-import.csv` when a project keeps one.

### `keys.env` — Environment Variables

Plain (non-secret) configuration set in `.env` or deployment config. These control runtime behavior and don't need encryption.

| Example | Purpose |
|---------|---------|
| `NODE_ENV` | Runtime environment (development/staging/production) |
| `LOG_LEVEL` | Logging verbosity |
| `LOCKE_USE_BIOMETRIC` | Enable Windows Hello / Touch ID gating |

## Decision Tree (for AI Agents)

```
New secret needed?
├── Shared across team? (DB URIs, DSNs, CDN keys, service URLs)
│   └── Add to config.json → locke encrypt → commit config.encrypted.json
│   └── Document in locke.json → keys.encryptedConfig
├── Personal? (API keys, personal tokens, login credentials)
│   └── Store in Vaultwarden: {project}/{tenant}/{secret_name}
│   └── Document in locke.json → keys.vault
├── Infrastructure? (encryption key, vault password)
│   └── OS keystore: locke keystore set NAME --prompt
│   └── Document in locke.json → keys.keystore
└── Non-secret config? (ports, regions, feature flags)
    └── .env file or deployment config
    └── Document in locke.json → keys.env
```

## Validation

Run `locke validate` to check that all keys documented in `locke.json` are actually reachable:

```
$ locke validate
Keystore:
  ✓ {key_name} — found in OS keystore
  ✗ LOCKE_VAULT_PASSWORD — not found

Encrypted Config:
  ✓ config.encrypted.development.json — decryptable (18 keys)

Vault:
  ✓ {project}/infra/api-key — found
  ✗ {project}/infra/missing-key — not found

Environment:
  ✓ NODE_ENV = production
  ✗ LOG_LEVEL — not set (default will apply)
```

## CI/CD Setup

Locke is published to PyPI, npm, and crates.io — install it as a normal
dependency. Cap `requires-python` to match Locke's supported range:

```toml
# pyproject.toml
requires-python = ">=3.11,<3.15"

[project]
dependencies = ["locke>=0.1"]
```

Locke supports Python 3.11–3.14. When running under `uv`, match the CI image
Python version with `uv sync --python-version X.Y`.

## CLI Commands

| Action | Command |
|--------|---------|
| Load env vars | `eval $(locke env)` |
| Decrypt config | `locke decrypt` |
| Encrypt config | `locke encrypt` |
| Get keystore credential | `locke keystore get NAME` |
| Set keystore credential | `locke keystore set NAME --prompt` |
| Get vault secret | `locke vault get PROJECT/TENANT/NAME` |
| Set up vault placeholders | `locke vault setup` |
| Fill vault values interactively | `locke vault setup --interactive` |
| Validate setup | `locke validate` |
| Initialize project | `locke init --project NAME` |
| Check status | `locke status` |

## Credential Resolution Order

1. **OS Keystore** (Windows Credential Manager / macOS Keychain / Linux Secret Service)
2. **Environment variables**
3. **GitLab CLI** (`glab`)
4. **.env file** (dev/staging only — production fails hard)

## Error Reference

| Error | Meaning | Fix |
|-------|---------|-----|
| `CredentialNotFoundError` | Secret not in any backend | `locke keystore set` or set env var |
| `DecryptionError` | Wrong key or corrupt file | Verify key: `locke keystore get {key_name}` |
| `CollisionError` | Duplicate flattened key | Rename conflicting config path |
| `VaultAuthError` | Vault login failed | Check LOCKE_VAULT_URL, LOCKE_VAULT_USERNAME, password |
