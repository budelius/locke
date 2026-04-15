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
```

### CLI

```bash
# Decrypt + flatten → shell exports
eval $(cargo run -- env)

# Decrypt to stdout
cargo run -- decrypt

# Encrypt
cargo run -- encrypt
```

## Testing

```bash
cargo test
```
