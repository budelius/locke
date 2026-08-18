# Locke

Unified credentials framework for any project — encrypted config files, OS
keystore resolution, environment-variable fallback, and Vaultwarden integration.
Available in Python, TypeScript, and Rust with cross-language parity.

## What it gives you

- **Encrypted configs checked into git** — AES-256-GCM authenticated encryption
  with PBKDF2-SHA256 key derivation. Share secrets across a team without ever
  committing plaintext.
- **OS keystore resolution** — Windows Credential Manager, macOS Keychain,
  Linux Secret Service. On Windows, gated by Windows Hello biometrics by default.
- **Pluggable resolution pipeline** — OS keystore → environment variables → Vault,
  evaluated in priority order.
- **Vaultwarden/Bitwarden integration** — fetch and import secrets via the
  Bitwarden-compatible REST API.
- **OpenBao KV integration** (Python) — fetch and write secrets from an
  OpenBao KV v1/v2 mount, with the same shape as the Vaultwarden client.
- **Config flattening** — nested JSON flattens to `SCREAMING_SNAKE_CASE`
  environment variables (`{ "mongo": { "uri": "…" } }` → `MONGO_URI=…`).
- **JSONC config files** — every JSON config Locke reads accepts `//` line
  comments, `/* … */` block comments, and trailing commas, so you can annotate
  plaintext configs and the checked-in encrypted files. Comment markers inside
  strings (e.g. `mongodb://host`) are preserved.
- **Cross-language parity** — Python, TypeScript, and Rust implementations
  produce byte-identical encrypt/decrypt output, verified by shared test vectors.

## Install

### Python

```bash
pip install locke
```

#### Local install from this repository on macOS

From the repository root:

```bash
python3 -m pip install -e ./python
locke --version
```

This installs the Python package in editable mode and makes the `locke` CLI
available on your Python environment's `PATH` (for example,
`/Users/<you>/miniconda/bin/locke` when using Miniconda).

### TypeScript / Node

```bash
npm install locke
```

### Rust

```toml
# Cargo.toml
[dependencies]
locke = "0.1"
```

## Quick start

### Python

```python
import locke

# Decrypt config and get flattened env-var dict
env = locke.load_config(
    "config.encrypted.json",
    key_name="MYAPP_CONFIG_ENCRYPTION_KEY",
)
print(env["MONGO_URI"])

# Resolve a single credential through the pipeline
credential = locke.resolve_credential("MYAPP_CONFIG_ENCRYPTION_KEY")

# Fetch or write a vault secret
secret = locke.get_vault_secret("myapp/prod/api_key")
locke.set_vault_secret("myapp/prod/api_key", "new-value")

# Username + password in a single entry (combined credential)
locke.set_vault_secret_pair("myapp/prod/db_login", "admin", "s3cr3t")
pair = locke.get_vault_secret_pair("myapp/prod/db_login")
print(pair.username, pair.password)   # -> admin s3cr3t

# Locke owns the placeholder convention for not-yet-issued values
if locke.is_placeholder(secret):
    raise RuntimeError("vault secret still needs a real value")
```

### CLI

```bash
# Store the encryption key in the OS keystore
locke keystore set MYAPP_CONFIG_ENCRYPTION_KEY --prompt

# Encrypt a plaintext config
locke encrypt file config.development.json --key-name MYAPP_CONFIG_ENCRYPTION_KEY

# Decrypt to stdout
locke decrypt config.encrypted.development.json --key-name MYAPP_CONFIG_ENCRYPTION_KEY

# Export as shell env vars
eval $(locke env --key-name MYAPP_CONFIG_ENCRYPTION_KEY)

# Initialize Locke in a new project
locke init --project myapp

# Create missing Vaultwarden entries from keys.vault as FILL_ME placeholders
locke vault setup

# Fill missing or placeholder vault values interactively
locke vault setup --interactive

# Read / write a single secret
locke vault get myapp/prod/api_key
locke vault set myapp/prod/api_key --password "sk_live_..."

# Combined credential — username + password in one entry
locke vault set myapp/prod/db_login --username admin --password "s3cr3t"
locke vault get myapp/prod/db_login --field username   # -> admin
locke vault get myapp/prod/db_login --field both        # -> admin:s3cr3t

# Encrypt all project configs using project-root .env settings
locke genkeys

# Convert JSONC to strict JSON (also installed as locke-strip-jsonc)
locke strip-jsonc config.development.jsonc config.development.json
```

### Project-wide config generation

The Python package installs `locke-genkeys` and `locke-strip-jsonc` on `PATH`
alongside `locke`. Their equivalent subcommands are `locke genkeys` and
`locke strip-jsonc`.

`locke genkeys` searches from the current directory upward for the project's
`.env`. Directory values may be absolute or relative to that project root:

```dotenv
LOCKE_INPUT_DIR=../shared-configs/my-project
LOCKE_OUTPUT_DIR=.locke
LOCKE_KEY_NAME=MYAPP_CONFIG_ENCRYPTION_KEY
```

Options override process environment variables, which override `.env`. The
output directory defaults to `.locke`. The encryption key value itself still
uses the selected credential source (`--key-source keystore` by default), not
the `LOCKE_KEY_NAME` setting.

Vault placeholders are represented by `locke.PLACEHOLDER_VALUE` (`"FILL_ME"`).
`VaultClient.get_secret()` logs a warning when returning a placeholder, and
`VaultClient.set_secret(path, None)` / empty values create a placeholder while
logging a warning.

For Python vault commands, `LOCKE_VAULT_URL` and `LOCKE_VAULT_USERNAME` are
read from the process environment first. In development and staging, they fall
back to a `.env` file in the current directory; production deliberately ignores
`.env`. Last comes the user-level settings file (see below), which applies in
every environment. `LOCKE_VAULT_PASSWORD` still uses the credential pipeline
(OS keystore first) and is never loaded by this connection-settings fallback.

### User-level settings file

`.env` is read from the current directory only, so vault commands break as soon
as you run them somewhere else — a git worktree, a scheduled task, a different
repository. The user-level settings file fixes that: it is the same role
`~/.gitconfig` plays for git, and Locke reads it from any directory.

```toml
# ~/.config/locke/config.toml   (%APPDATA%\locke\config.toml on Windows)
vault_url = "https://vault.example.com"
vault_email = "ops@example.com"
```

```bash
locke config set vault_url https://vault.example.com
locke config set vault_email ops@example.com
locke config show          # effective settings
locke config path          # where the file lives
```

Resolution precedence is **environment variable → `./.env` (dev/staging only) →
user-level settings file**, so nothing that worked before changes behaviour.

The file is plaintext, so it holds only non-secret bootstrap settings. Writing a
password key is refused, and a password key found in an existing file is ignored
with a warning — the Vaultwarden master password belongs in the OS keystore:

```bash
locke keystore set LOCKE_VAULT_PASSWORD
```

`LOCKE_SETTINGS_FILE` overrides discovery with an explicit path (useful in CI).
Discovery otherwise prefers the first file that exists among
`%APPDATA%/locke/config.toml` (Windows only), `$XDG_CONFIG_HOME/locke/config.toml`,
and `~/.config/locke/config.toml`; when none exists, the platform-native location
is created.

### Combined credentials (username + password)

Credentials that pair a username with a password (database logins, SMTP
accounts, …) can live in a **single** vault entry instead of two separate
secrets. A Bitwarden login item natively carries both a `username` and a
`password` field, so Locke stores both together and returns them as a
`CredentialPair`:

```python
pair = locke.get_vault_secret_pair("myapp/prod/db_login")
pair.username   # "admin"  (None if unset)
pair.password   # "s3cr3t"
```

The same `get_secret_pair` / `set_secret_pair` API and `vault get --field` /
`vault set --username` CLI are available in all three implementations (Python,
TypeScript, Rust).

## OpenBao KV (Python)

Locke also supports [OpenBao](https://openbao.org/) as a secret backend,
shaped like the Vaultwarden client so call sites can migrate without changes.
Currently available in the **Python** package only.

```python
import locke

secret = locke.get_openbao_secret("myapp/prod/api_key")
locke.set_openbao_secret("myapp/prod/api_key", "new-value")

locke.set_openbao_secret_pair("myapp/prod/db_login", "admin", "s3cr3t")
pair = locke.get_openbao_secret_pair("myapp/prod/db_login")
```

```bash
locke openbao get myapp/prod/api_key
locke openbao set myapp/prod/api_key --password "sk_live_..."

# Combined credential
locke openbao set myapp/prod/db_login --username admin --password "s3cr3t"
locke openbao get myapp/prod/db_login --field username   # -> admin
```

Connects using `LOCKE_OPENBAO_ADDR` / `OPENBAO_ADDR` / `VAULT_ADDR` and
`LOCKE_OPENBAO_TOKEN` / `OPENBAO_TOKEN` / `VAULT_TOKEN` (checked in that
order), plus `LOCKE_OPENBAO_MOUNT` (default `secret`) and
`LOCKE_OPENBAO_KV_VERSION` (`1` or `2`, default `2`).

## Encrypted config format

```json
{
  "version": 2,
  "algorithm": "aes-256-gcm",
  "kdf": "pbkdf2",
  "kdfIterations": 100000,
  "salt": "<base64>",
  "iv": "<base64>",
  "authTag": "<base64>",
  "ciphertext": "<base64>"
}
```

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **KDF**: PBKDF2-SHA256, 100,000 iterations
- **IV**: 12 bytes random per encryption
- **Auth tag**: 16 bytes
- **Key**: 32-byte passphrase (hex or base64 encoded)

## Credential resolution pipeline

Locke resolves credentials in priority order:

1. **OS keystore** (service = `locke`) — the root of trust for local development
2. **Environment variables** — `LOCKE_ENCRYPTION_KEY`, `LOCKE_VAULT_PASSWORD`, etc.
3. **Vaultwarden** — via configured vault URL

Your application picks its own credential names (e.g.
`MYAPP_CONFIG_ENCRYPTION_KEY`); Locke does not impose a namespace.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `LOCKE_ENV` | Override environment detection (`development`/`staging`/`production`) |
| `LOCKE_USE_BIOMETRIC` | Set `false` to disable Windows Hello gating |
| `LOCKE_BIO_CACHE_TTL` | Seconds to cache biometric verification (default 300) |
| `LOCKE_VAULT_URL` | Vaultwarden server URL (Python: `.env` fallback outside production, then `vault_url` in the user-level settings file) |
| `LOCKE_VAULT_USERNAME` | Vaultwarden username (Python: `.env` fallback outside production, then `vault_email` in the user-level settings file) |
| `LOCKE_VAULT_PASSWORD` | Vaultwarden password (prefer OS keystore) |
| `LOCKE_INPUT_DIR` | `locke genkeys` plaintext config directory (relative to project root if needed) |
| `LOCKE_OUTPUT_DIR` | `locke genkeys` output directory (default `.locke`) |
| `LOCKE_KEY_NAME` | Credential name used by `locke genkeys` |
| `LOCKE_SETTINGS_FILE` | Explicit path to the user-level settings file (overrides discovery) |
| `LOCKE_OPENBAO_ADDR` | OpenBao server URL (Python only; falls back to `OPENBAO_ADDR`/`VAULT_ADDR`) |
| `LOCKE_OPENBAO_TOKEN` | OpenBao token (falls back to `OPENBAO_TOKEN`/`VAULT_TOKEN`) |
| `LOCKE_OPENBAO_MOUNT` | OpenBao KV mount name (default `secret`) |
| `LOCKE_OPENBAO_KV_VERSION` | OpenBao KV engine version, `1` or `2` (default `2`) |

## Repository layout

```
locke/
├── python/        # Python package (locke on PyPI)
├── typescript/    # TypeScript package (locke on npm)
├── rust/          # Rust crate (locke on crates.io)
├── test-vectors/  # Cross-language parity vectors
├── templates/     # Example config files + bootstrap guide
└── scripts/       # Version bumping helpers
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT — see [LICENSE](LICENSE).
