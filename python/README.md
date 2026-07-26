# Locke — Python

Unified credentials framework — encrypted config, OS keystore, Vaultwarden and OpenBao integration.

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

# Get/set an OpenBao KV secret
locke openbao get myproject/staging/api_key
locke openbao set myproject/staging/api_key --password "new-value"

# Initialize project
locke init --project myproject --tenant staging

# Encrypt every config.{environment}.json[c] using project-root .env settings
locke genkeys

# Convert JSONC to strict JSON
locke strip-jsonc input.jsonc output.json
```

## Project tools on `PATH`

Installing Locke provides `locke-genkeys` and `locke-strip-jsonc` as standalone
commands, as well as `locke genkeys` and `locke strip-jsonc` subcommands.

From any directory below a project root, `locke genkeys` finds the nearest
ancestor containing `.env` and reads:

```dotenv
LOCKE_INPUT_DIR=../shared-configs/myproject
LOCKE_OUTPUT_DIR=.locke
LOCKE_KEY_NAME=MYPROJECT_CONFIG_ENCRYPTION_KEY
```

Relative paths are resolved from the discovered project root. CLI options take
precedence over process environment variables, which take precedence over the
project `.env`. `LOCKE_OUTPUT_DIR` defaults to `.locke`. Use `--project-root`
to select a root explicitly.

## OpenBao KV

Locke can also read/write secrets from an [OpenBao](https://openbao.org/) KV
v1/v2 mount, using the same shape as the Vaultwarden client
(`get_secret`/`set_secret`, `get_secret_pair`/`set_secret_pair`):

```python
secret = locke.get_openbao_secret("myproject/staging/api_key")
locke.set_openbao_secret("myproject/staging/api_key", "new-value")
```

Connects via `LOCKE_OPENBAO_ADDR`/`OPENBAO_ADDR`/`VAULT_ADDR` and
`LOCKE_OPENBAO_TOKEN`/`OPENBAO_TOKEN`/`VAULT_TOKEN`. See
`locke/openbao.py` for the full env var list (mount, KV version).

## Vault placeholders

Locke uses `locke.PLACEHOLDER_VALUE` (`"FILL_ME"`) for vault entries that are
known but not filled yet. Use `locke.is_placeholder(value)` instead of
hard-coding the sentinel. `VaultClient.get_secret()` warns when it returns a
placeholder; `VaultClient.set_secret(path, None)` or an empty value writes a
placeholder and warns.

### Vault connection settings from `.env`

`LOCKE_VAULT_URL` and `LOCKE_VAULT_USERNAME` are read from the process
environment first. In development and staging, Locke falls back to a `.env`
file in the current working directory. Production ignores `.env` and requires
real environment variables. The vault password is not read by this fallback:
`LOCKE_VAULT_PASSWORD` continues through the keystore-first credential pipeline.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `LOCKE_ENV` | Override environment detection |
| `LOCKE_ENCRYPTION_KEY` | Encryption key (if not in keystore) |
| `LOCKE_USE_BIOMETRIC` | Set `false` to disable biometric gating |
| `LOCKE_VAULT_URL` | Vaultwarden server URL; current-directory `.env` fallback outside production |
| `LOCKE_VAULT_USERNAME` | Vaultwarden username; current-directory `.env` fallback outside production |
| `LOCKE_INPUT_DIR` | `genkeys` plaintext config directory, absolute or project-root relative |
| `LOCKE_OUTPUT_DIR` | `genkeys` output directory (default `.locke`) |
| `LOCKE_KEY_NAME` | Credential name used by `genkeys` |
| `LOCKE_OPENBAO_ADDR` | OpenBao server URL (falls back to `OPENBAO_ADDR`/`VAULT_ADDR`) |
| `LOCKE_OPENBAO_TOKEN` | OpenBao token (falls back to `OPENBAO_TOKEN`/`VAULT_TOKEN`) |

## Testing

```bash
cd python
pip install -e ".[dev]"
pytest
```
