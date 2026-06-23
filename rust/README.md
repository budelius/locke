# Locke — Rust

Unified credentials framework — encrypted config, OS keystore, Vaultwarden integration.

## Build

```bash
cargo build
```

## Usage

### Library

```rust
use locke::load_config;
use std::path::Path;

let env = load_config(Path::new(".locke/config.encrypted.json"))?;
// env["MONGO_URI"], env["SENTRY_DSN"], etc.

// Username + password in a single entry (combined credential)
use locke::vault::{get_vault_secret_pair, set_vault_secret_pair};

// args: path, username, password, folder, uri, notes
set_vault_secret_pair("myproject/staging/db_login", Some("admin"), Some("s3cr3t"), None, None, None)?;
let pair = get_vault_secret_pair("myproject/staging/db_login")?;
// pair.username == Some("admin"), pair.password == "s3cr3t"
```

### CLI

```bash
# Decrypt + flatten → shell exports
eval $(cargo run -- env)

# Decrypt to stdout
cargo run -- decrypt

# Encrypt
cargo run -- encrypt

# Read / write vault secrets
cargo run -- vault get myproject/staging/db_login --field both
cargo run -- vault set myproject/staging/db_login --username admin --password s3cr3t
```

## Testing

```bash
cargo test
```
