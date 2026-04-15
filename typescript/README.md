# Locke — TypeScript

Unified credentials framework — encrypted config, OS keystore, Vaultwarden integration.

## Install

```bash
npm install
```

## Usage

### Library

```typescript
import { loadConfig, resolveCredential, getVaultSecret } from 'locke';

// Load and decrypt config → flat env vars
const env = await loadConfig('.locke/config.encrypted.json');
// env.MONGO_URI, env.SENTRY_DSN, etc.

// Resolve a single credential
const cred = await resolveCredential('LOCKE_ENCRYPTION_KEY');

// Get a vault secret
const secret = await getVaultSecret('myproject/staging/api_key');
```

## Build

```bash
npm run build
```

## Testing

```bash
npm test
```
