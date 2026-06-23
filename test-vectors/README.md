# Test Vectors

Shared cross-language test vectors for Locke.

## Files

| File | Purpose |
|------|---------|
| `encrypt-decrypt.json` | AES-256-GCM encrypt/decrypt with PBKDF2-SHA256 |
| `flatten.json` | Config flattening to SCREAMING_SNAKE_CASE |
| `pipeline.json` | Credential resolution pipeline priority |
| `vault-cipher.json` | Bitwarden client-side crypto (PBKDF2 master key, HKDF stretch, AES-256-CBC+HMAC cipher strings, symmetric-key decryption) |

## Format

Each file contains a `vectors` array. Each vector has:

- `name` — Unique identifier
- `description` — What this vector tests
- Input/output fields specific to the test type
- Optional `expected_error` — Error type expected instead of output

## Adding New Vectors

1. Add the vector to the appropriate JSON file
2. Run tests in all three languages to verify
3. Include both positive (expected output) and negative (expected error) cases

## Cross-Language Validation

The vectors use deterministic inputs (fixed salt, IV) to enable exact
ciphertext comparison across Python, TypeScript, and Rust. Round-trip
vectors (which use random IV) verify encrypt→decrypt consistency.
