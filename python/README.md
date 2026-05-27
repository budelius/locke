# Locke — Python

Unified credentials framework — encrypted config, OS keystore, Vaultwarden integration.

## Install

For local development from this repository:

```bash
cd python
pip install -e ".[dev]"
```

From the repository root on macOS, install the public Locke CLI/package locally:

```bash
python3 -m pip install -e ./python
locke --version
```

The `locke` executable is installed into the active Python environment's `bin`
directory, so make sure that directory is on your `PATH`.

## Usage

### Library

```python
import locke

# Load and decrypt config → flat env vars
env = locke.load_config(".locke/config.encrypted.json")
# env["MONGO_URI"], env["SENTRY_DSN"], etc.

# Resolve a single credential
cred = locke.resolve_credential("LOCKE_ENCRYPTION_KEY")

# Get or set a vault secret
secret = locke.get_vault_secret("myproject/staging/api_key")
locke.set_vault_secret("myproject/staging/api_key", "new-value")

# Check Locke-owned setup placeholders ("FILL_ME")
if locke.is_placeholder(secret):
    raise RuntimeError("vault secret still needs a real value")
```

### CLI

```bash
# Decrypt + flatten → shell exports
eval $(locke env)

# Decrypt to stdout
locke decrypt

# Encrypt plaintext config
locke encrypt

# Manage OS keystore
locke keystore set LOCKE_ENCRYPTION_KEY --prompt
locke keystore get LOCKE_ENCRYPTION_KEY

# Get vault secret
locke vault get myproject/staging/api_key

# Create missing vault entries from locke.json, then fill them interactively
locke vault setup
locke vault setup --interactive

# Initialize project
locke init --project myproject --tenant staging
```

## Vault placeholders

Locke uses `locke.PLACEHOLDER_VALUE` (`"FILL_ME"`) for vault entries that are
known but not filled yet. Use `locke.is_placeholder(value)` instead of
hard-coding the sentinel. `VaultClient.get_secret()` warns when it returns a
placeholder; `VaultClient.set_secret(path, None)` or an empty value writes a
placeholder and warns.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `LOCKE_ENV` | Override environment detection |
| `LOCKE_ENCRYPTION_KEY` | Encryption key (if not in keystore) |
| `LOCKE_USE_BIOMETRIC` | Set `false` to disable biometric gating |
| `LOCKE_VAULT_URL` | Vaultwarden server URL |
| `LOCKE_VAULT_USERNAME` | Vaultwarden username |

## Testing

```bash
cd python
pip install -e ".[dev]"
pytest
```
