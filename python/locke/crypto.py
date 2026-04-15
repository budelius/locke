"""AES-256-GCM encryption/decryption with PBKDF2-SHA256 KDF.

Handles hex/base64 key encoding auto-detection for backward compatibility.
"""

import base64
import hashlib
import json
import logging
import os
import re
import warnings

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from locke.errors import DecryptionError, InvalidConfigError, InvalidKeyError

logger = logging.getLogger(__name__)

REQUIRED_KEY_LENGTH = 32  # bytes
KDF_ITERATIONS = 100_000
IV_LENGTH = 12  # bytes
AUTH_TAG_LENGTH = 16  # bytes
CURRENT_VERSION = 2

# 64 hex characters = 32 bytes
_HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Even-length hex string (any length)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _decode_field(value: str) -> bytes:
    """Auto-detect hex vs base64 encoding for encrypted config fields.

    Older Locke configs wrote hex-encoded fields; current configs use base64.
    Both are accepted.
    """
    if _HEX_RE.match(value) and len(value) % 2 == 0:
        return bytes.fromhex(value)
    return base64.b64decode(value)


def decode_key(key_input: str) -> bytes:
    """Auto-detect and decode an encryption key from hex or base64 encoding.

    - If the input is exactly 64 hex characters, decode as hex (32 bytes).
    - Otherwise, attempt base64 decode and verify it produces 32 bytes.
    - Raises InvalidKeyError if neither decoding yields 32 bytes.
    """
    if _HEX_64_RE.match(key_input):
        key_bytes = bytes.fromhex(key_input)
        logger.debug("Key detected as hex-encoded (64 chars)")
        return key_bytes

    try:
        key_bytes = base64.b64decode(key_input)
        if len(key_bytes) == REQUIRED_KEY_LENGTH:
            logger.debug("Key detected as base64-encoded")
            return key_bytes
    except Exception:
        pass

    if isinstance(key_input, bytes) and len(key_input) == REQUIRED_KEY_LENGTH:
        return key_input

    raise InvalidKeyError(
        expected_bytes=REQUIRED_KEY_LENGTH,
        actual_bytes=len(key_input),
    )


def _derive_key(passphrase: bytes, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a 32-byte AES key from passphrase using PBKDF2-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt, iterations, dklen=REQUIRED_KEY_LENGTH)


def _key_to_passphrase_bytes(key: str | bytes) -> bytes:
    """Convert a key to passphrase bytes for PBKDF2.

    The key string is passed as-is (UTF-8 encoded) to PBKDF2 — NOT hex-decoded
    first. All three language implementations (Python, TypeScript, Rust) agree
    on this, which is verified by the cross-language test vectors.
    """
    if isinstance(key, str):
        return key.encode("utf-8")
    return key


def decrypt_config(encrypted: dict, key: str | bytes) -> dict:
    """Decrypt an encrypted config structure.

    Args:
        encrypted: The parsed encrypted config JSON (version 2 format).
        key: Encryption key (passphrase string or raw bytes).

    Returns:
        The decrypted plaintext config as a dict.

    Raises:
        DecryptionError: Auth tag mismatch or corrupt ciphertext.
        InvalidConfigError: Malformed encrypted config structure.
    """
    # Validate structure
    required_fields = ["algorithm", "kdf", "salt", "iv", "authTag", "ciphertext"]
    for field in required_fields:
        if field not in encrypted:
            raise InvalidConfigError(f"missing field '{field}'")

    version = encrypted.get("version")
    if version != CURRENT_VERSION:
        warnings.warn(
            f"Encrypted config version {version} (expected {CURRENT_VERSION}). "
            "Attempting best-effort decryption.",
            stacklevel=2,
        )

    if encrypted.get("algorithm") != "aes-256-gcm":
        raise InvalidConfigError(f"unsupported algorithm '{encrypted.get('algorithm')}'")

    if encrypted.get("kdf") != "pbkdf2":
        raise InvalidConfigError(f"unsupported KDF '{encrypted.get('kdf')}'")

    key_bytes = _key_to_passphrase_bytes(key)

    # Decode fields (auto-detect hex vs base64 for backward compat)
    salt = _decode_field(encrypted["salt"])
    iv = _decode_field(encrypted["iv"])
    auth_tag = _decode_field(encrypted["authTag"])
    ciphertext = _decode_field(encrypted["ciphertext"])

    iterations = encrypted.get("kdfIterations", KDF_ITERATIONS)

    # Derive AES key from passphrase + salt
    derived_key = _derive_key(key_bytes, salt, iterations)

    # AES-256-GCM decryption — ciphertext with appended auth tag
    aesgcm = AESGCM(derived_key)
    try:
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    except Exception as exc:
        raise DecryptionError("<encrypted config>", "authentication tag verification failed") from exc

    try:
        return json.loads(plaintext_bytes)
    except json.JSONDecodeError as exc:
        raise DecryptionError("<encrypted config>", "decrypted content is not valid JSON") from exc


def encrypt_config(plaintext: dict, key: str | bytes) -> dict:
    """Encrypt a plaintext config to version 2 format.

    Args:
        plaintext: The config dict to encrypt.
        key: Encryption key (passphrase string or raw bytes).

    Returns:
        Version 2 encrypted config structure.
    """
    key_bytes = _key_to_passphrase_bytes(key)

    # Generate random salt and IV
    salt = os.urandom(32)
    iv = os.urandom(IV_LENGTH)

    # Derive AES key
    derived_key = _derive_key(key_bytes, salt, KDF_ITERATIONS)

    # Encrypt
    aesgcm = AESGCM(derived_key)
    plaintext_bytes = json.dumps(plaintext, separators=(",", ":"), sort_keys=True).encode()
    ct_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)

    # Split ciphertext and auth tag (last 16 bytes)
    ciphertext = ct_with_tag[:-AUTH_TAG_LENGTH]
    auth_tag = ct_with_tag[-AUTH_TAG_LENGTH:]

    return {
        "version": CURRENT_VERSION,
        "algorithm": "aes-256-gcm",
        "kdf": "pbkdf2",
        "kdfIterations": KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "authTag": base64.b64encode(auth_tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
