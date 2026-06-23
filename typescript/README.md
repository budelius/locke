# Locke — TypeScript

Unified credentials framework — encrypted config, OS keystore, Vaultwarden integration.

## Install

```bash
npm install
```

## Usage

### Library

```typescript
import {
  loadConfig,
  resolveCredential,
  getVaultSecret,
  getVaultSecretPair,
  setVaultSecretPair,
} from 'locke';

// Load and decrypt config → flat env vars
const env = await loadConfig('.locke/config.encrypted.json');
// env.MONGO_URI, env.SENTRY_DSN, etc.

// Resolve a single credential
const cred = await resolveCredential('LOCKE_ENCRYPTION_KEY');

// Get a vault secret
const secret = await getVaultSecret('myproject/staging/api_key');

// Username + password in a single entry (combined credential)
await setVaultSecretPair('myproject/staging/db_login', 'admin', 's3cr3t');
const pair = await getVaultSecretPair('myproject/staging/db_login');
// pair.username === 'admin', pair.password === 's3cr3t'
```

### CLI

```bash
locke vault get myproject/staging/api_key
locke vault set myproject/staging/db_login --username admin --password s3cr3t
locke vault get myproject/staging/db_login --field both   # admin:s3cr3t
```

## Build

```bash
npm run build
```

## Testing

```bash
npm test
```
