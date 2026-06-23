/**
 * Locke error types.
 *
 * All errors avoid including secret values in messages.
 */

export class LockeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class CredentialNotFoundError extends LockeError {
  constructor(
    public readonly credentialName: string,
    public readonly backendsSearched: string[],
  ) {
    super(
      `Credential '${credentialName}' not found in backends: ${backendsSearched.join(", ")}`,
    );
  }
}

export class DecryptionError extends LockeError {
  constructor(
    public readonly filePath: string,
    detail = "",
  ) {
    const msg = detail
      ? `Decryption failed for '${filePath}': ${detail}`
      : `Decryption failed for '${filePath}'`;
    super(msg);
  }
}

export class InvalidKeyError extends LockeError {
  constructor(
    public readonly expectedBytes: number,
    public readonly actualBytes: number,
  ) {
    super(`Invalid key: expected ${expectedBytes} bytes, got ${actualBytes}`);
  }
}

export class InvalidConfigError extends LockeError {
  constructor(detail: string) {
    super(`Invalid config: ${detail}`);
  }
}

export class CollisionError extends LockeError {
  constructor(
    public readonly key: string,
    public readonly pathA: string,
    public readonly pathB: string,
  ) {
    super(`Key collision: '${key}' produced by both '${pathA}' and '${pathB}'`);
  }
}

export class VaultAuthError extends LockeError {
  constructor(
    public readonly vaultUrl: string,
    public readonly detail = "",
  ) {
    const msg = detail
      ? `Vault authentication failed for '${vaultUrl}': ${detail}`
      : `Vault authentication failed for '${vaultUrl}'`;
    super(msg);
  }
}

export class SecretNotFoundError extends LockeError {
  constructor(public readonly secretPath: string) {
    super(`Vault secret not found: '${secretPath}'`);
  }
}

export class KeystoreUnavailableError extends LockeError {
  constructor(
    public readonly platform: string,
    public readonly service: string,
  ) {
    super(`Keystore unavailable on ${platform}: ${service}`);
  }
}

export class BiometricDeniedError extends LockeError {
  constructor(public readonly reason: string = "denied") {
    super(`Biometric verification ${reason}`);
  }
}

export class BiometricUnavailableError extends LockeError {
  constructor(public readonly detail: string = "") {
    const msg = detail
      ? `Biometric authentication not available: ${detail}`
      : "Biometric authentication not available";
    super(msg);
  }
}
