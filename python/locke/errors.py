"""Locke error types.

All errors avoid including secret values in messages.
"""


class LockeError(Exception):
    """Base error for all Locke operations."""


class CredentialNotFoundError(LockeError):
    """No backend has the requested credential (production) or all backends exhausted."""

    def __init__(self, name: str, backends_searched: list[str]) -> None:
        self.name = name
        self.backends_searched = backends_searched
        super().__init__(
            f"Credential '{name}' not found in backends: {', '.join(backends_searched)}"
        )


class DecryptionError(LockeError):
    """Auth tag mismatch or corrupt ciphertext."""

    def __init__(self, file_path: str, detail: str = "") -> None:
        self.file_path = file_path
        msg = f"Decryption failed for '{file_path}'"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class InvalidKeyError(LockeError):
    """Key is wrong length or unrecognized encoding."""

    def __init__(self, expected_bytes: int, actual_bytes: int) -> None:
        self.expected_bytes = expected_bytes
        self.actual_bytes = actual_bytes
        super().__init__(
            f"Invalid key: expected {expected_bytes} bytes, got {actual_bytes}"
        )


class InvalidConfigError(LockeError):
    """Malformed encrypted config structure."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"Invalid config: {detail}")


class CollisionError(LockeError):
    """Flattening produced duplicate key from different source paths."""

    def __init__(self, key: str, path_a: str, path_b: str) -> None:
        self.key = key
        self.path_a = path_a
        self.path_b = path_b
        super().__init__(
            f"Key collision: '{key}' produced by both '{path_a}' and '{path_b}'"
        )


class VaultAuthError(LockeError):
    """Vaultwarden authentication failed."""

    def __init__(self, vault_url: str, detail: str = "") -> None:
        self.vault_url = vault_url
        self.detail = detail
        msg = f"Vault authentication failed for '{vault_url}'"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class SecretNotFoundError(LockeError):
    """Vault secret path doesn't exist."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Vault secret not found: '{path}'")


class KeystoreUnavailableError(LockeError):
    """OS keystore service not running or unavailable."""

    def __init__(self, platform: str, service: str) -> None:
        self.platform = platform
        self.service = service
        super().__init__(f"Keystore unavailable on {platform}: {service}")


class BiometricDeniedError(LockeError):
    """Biometric verification was denied or cancelled by the user."""

    def __init__(self, reason: str = "denied") -> None:
        self.reason = reason
        super().__init__(f"Biometric verification {reason}")


class BiometricUnavailableError(LockeError):
    """Biometric authentication is not available on this device."""

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        msg = "Biometric authentication not available"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
