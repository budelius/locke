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
```

Vault placeholders are represented by `locke.PLACEHOLDER_VALUE` (`"FILL_ME"`).
`VaultClient.get_secret()` logs a warning when returning a placeholder, and
`VaultClient.set_secret(path, None)` / empty values create a placeholder while
logging a warning.

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
| `LOCKE_VAULT_URL` | Vaultwarden server URL |
| `LOCKE_VAULT_USERNAME` | Vaultwarden username |
| `LOCKE_VAULT_PASSWORD` | Vaultwarden password (prefer OS keystore) |

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

## License

MIT — see [LICENSE](LICENSE).
