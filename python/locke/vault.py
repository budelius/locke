"""Vaultwarden/Bitwarden API client.

Connects to Vaultwarden via Bitwarden-compatible API v1.
Authenticates using pipeline-resolved credentials.
Secret path convention: {project}/{tenant_slug}/{secret_name}

Bitwarden encrypts all vault data client-side.  After authentication the
server returns an encrypted symmetric key which must be decrypted locally
using the master key derived from the user's password.  All cipher fields
(name, login password, notes, …) are then decrypted with that symmetric
key.  Encrypted strings use the format ``{type}.{iv}|{ct}|{mac}`` where
type 2 = AES-256-CBC + HMAC-SHA256.
"""

import base64
import hashlib
import hmac as hmac_mod
import logging
import os

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from locke.errors import SecretNotFoundError, VaultAuthError
from locke.pipeline import resolve_credential

logger = logging.getLogger(__name__)

# Vaultwarden connection env vars
VAULT_URL_VAR = "LOCKE_VAULT_URL"
VAULT_USERNAME_VAR = "LOCKE_VAULT_USERNAME"
VAULT_PASSWORD_CREDENTIAL = "LOCKE_VAULT_PASSWORD"


# ---------------------------------------------------------------------------
# Bitwarden client-side crypto helpers
# ---------------------------------------------------------------------------

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) using HMAC-SHA256."""
    hash_len = 32  # SHA-256 output
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _make_master_key(password: str, email: str, kdf_iterations: int = 600_000) -> bytes:
    """Derive the 32-byte master key from password + email."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        email.lower().encode("utf-8"),
        kdf_iterations,
    )


def _stretch_master_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Stretch master key into (enc_key, mac_key) via HKDF-Expand.

    Returns two 32-byte keys used to decrypt the encrypted symmetric key
    returned by the Bitwarden identity endpoint.
    """
    enc_key = _hkdf_expand(master_key, b"enc", 32)
    mac_key = _hkdf_expand(master_key, b"mac", 32)
    return enc_key, mac_key


def _encrypt_string(plaintext: str, enc_key: bytes, mac_key: bytes) -> str:
    """Encrypt a plaintext string into Bitwarden ``2.iv|ct|mac`` format.

    Type 2 = AES-256-CBC + HMAC-SHA256.  This is the inverse of
    :func:`_decrypt_encrypted_string`.
    """
    data = plaintext.encode("utf-8")

    # PKCS7 pad
    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    # Random 16-byte IV
    iv = os.urandom(16)

    # AES-256-CBC encrypt
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    # HMAC-SHA256(mac_key, iv + ct)
    mac = hmac_mod.new(mac_key, iv + ct, hashlib.sha256).digest()

    return "2.{}|{}|{}".format(
        base64.b64encode(iv).decode("ascii"),
        base64.b64encode(ct).decode("ascii"),
        base64.b64encode(mac).decode("ascii"),
    )


def _decrypt_encrypted_string(enc_string: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """Decrypt a Bitwarden encrypted string (``2.iv|ct|mac`` format).

    Type 2 = AES-256-CBC + HMAC-SHA256.
    """
    if not enc_string:
        return b""

    # Parse type prefix
    parts = enc_string.split(".", 1)
    if len(parts) != 2:
        raise ValueError(f"invalid encrypted string format: no type prefix")
    enc_type = int(parts[0])
    if enc_type != 2:
        raise ValueError(f"unsupported encryption type {enc_type} (expected 2)")

    segments = parts[1].split("|")
    if len(segments) != 3:
        raise ValueError(f"expected 3 segments (iv|ct|mac), got {len(segments)}")

    iv = base64.b64decode(segments[0])
    ct = base64.b64decode(segments[1])
    mac = base64.b64decode(segments[2])

    # Verify HMAC-SHA256(mac_key, iv + ct)
    expected_mac = hmac_mod.new(mac_key, iv + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed")

    # Decrypt AES-256-CBC
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _decrypt_symmetric_key(
    encrypted_key: str, master_key: bytes,
) -> tuple[bytes, bytes]:
    """Decrypt the user's symmetric key from the login response ``Key`` field.

    Returns ``(enc_key, mac_key)`` — the 64-byte symmetric key split in half.
    """
    stretched_enc, stretched_mac = _stretch_master_key(master_key)
    raw = _decrypt_encrypted_string(encrypted_key, stretched_enc, stretched_mac)
    if len(raw) != 64:
        raise ValueError(
            f"decrypted symmetric key is {len(raw)} bytes (expected 64)"
        )
    return raw[:32], raw[32:]


def _decrypt_cipher_string(enc_string: str | None, enc_key: bytes, mac_key: bytes) -> str | None:
    """Decrypt an optional Bitwarden cipher field to a UTF-8 string."""
    if not enc_string:
        return None
    try:
        return _decrypt_encrypted_string(enc_string, enc_key, mac_key).decode("utf-8")
    except Exception as exc:
        logger.debug("Failed to decrypt cipher field: %s", exc)
        return None


class VaultClient:
    """Bitwarden-compatible API client for Vaultwarden."""

    def __init__(
        self,
        base_url: str,
        access_token: str,
        enc_key: bytes,
        mac_key: bytes,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {access_token}"}
        self._enc_key = enc_key
        self._mac_key = mac_key

    @classmethod
    def connect(cls) -> "VaultClient":
        """Create an authenticated vault client using pipeline-resolved credentials."""
        base_url = os.environ.get(VAULT_URL_VAR)
        if not base_url:
            raise VaultAuthError(
                "unknown",
                f"environment variable {VAULT_URL_VAR} is not set",
            )

        username = os.environ.get(VAULT_USERNAME_VAR)
        if not username:
            raise VaultAuthError(
                base_url,
                f"environment variable {VAULT_USERNAME_VAR} is not set",
            )

        password_cred = resolve_credential(VAULT_PASSWORD_CREDENTIAL)

        # Authenticate via Bitwarden Identity API
        token, encrypted_key = cls._authenticate(
            base_url, username, password_cred.value,
        )

        # Derive master key and decrypt the symmetric key
        master_key = _make_master_key(password_cred.value, username)
        enc_key, mac_key = _decrypt_symmetric_key(encrypted_key, master_key)

        return cls(base_url, token, enc_key, mac_key)

    @staticmethod
    def _hash_password(password: str, email: str) -> str:
        """Pre-hash master password the way Bitwarden expects.

        Bitwarden identity endpoint requires the password hashed client-side:
        1. PBKDF2-SHA256(password, lowercase(email), 600_000 iterations) → master key
        2. PBKDF2-SHA256(master_key, password, 1 iteration) → hashed password
        3. Base64-encode the result
        """
        master_key = _make_master_key(password, email)
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            master_key,
            password.encode("utf-8"),
            1,
        )
        return base64.b64encode(hashed).decode("ascii")

    @staticmethod
    def _authenticate(
        base_url: str, username: str, password: str,
    ) -> tuple[str, str]:
        """Authenticate with Bitwarden/Vaultwarden identity endpoint.

        Returns ``(access_token, encrypted_key)`` where *encrypted_key* is the
        user's encrypted symmetric key (``Key`` field in the response).
        """
        identity_url = f"{base_url}/identity/connect/token"
        hashed_password = VaultClient._hash_password(password, username)

        try:
            response = httpx.post(
                identity_url,
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": hashed_password,
                    "scope": "api offline_access",
                    "client_id": "cli",
                    "deviceType": "9",
                    "deviceIdentifier": "locke-client",
                    "deviceName": "locke",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            access_token = data["access_token"]
            encrypted_key = data.get("Key", "")
            if not encrypted_key:
                raise VaultAuthError(
                    base_url,
                    "server did not return an encrypted symmetric key (Key field)",
                )
            return access_token, encrypted_key
        except VaultAuthError:
            raise
        except httpx.ConnectError as exc:
            raise VaultAuthError(
                base_url, f"cannot reach server ({exc})"
            ) from exc
        except httpx.TimeoutException as exc:
            raise VaultAuthError(
                base_url, "connection timed out"
            ) from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 400:
                detail = "invalid credentials (wrong username or password)"
            elif status == 401:
                detail = "unauthorized (bad password or expired token)"
            elif status == 404:
                detail = f"identity endpoint not found at {identity_url}"
            else:
                detail = f"HTTP {status}"
            raise VaultAuthError(base_url, detail) from exc
        except Exception as exc:
            raise VaultAuthError(
                base_url, str(exc)
            ) from exc

    def _encrypt(self, plaintext: str | None) -> str | None:
        """Encrypt a plaintext string using this client's symmetric key.

        Returns a ``2.iv|ct|mac`` Bitwarden encrypted string, or *None*
        if *plaintext* is ``None`` or empty.
        """
        if not plaintext:
            return None
        return _encrypt_string(plaintext, self._enc_key, self._mac_key)

    def _decrypt(self, enc_string: str | None) -> str | None:
        """Decrypt a Bitwarden encrypted field using this client's symmetric key."""
        return _decrypt_cipher_string(enc_string, self._enc_key, self._mac_key)

    def get_secret(self, path: str) -> str:
        """Retrieve a secret by path ({project}/{tenant}/{name}).

        Searches vault ciphers by name matching the path convention.
        Cipher names and values are decrypted client-side.
        """
        # Sync vault to get latest ciphers
        try:
            response = httpx.get(
                f"{self._base_url}/api/sync",
                headers=self._headers,
                timeout=30,
            )
            response.raise_for_status()
            sync_data = response.json()
        except httpx.HTTPStatusError as exc:
            raise VaultAuthError(
                self._base_url,
                f"sync failed with HTTP {exc.response.status_code} (token may be expired)",
            ) from exc
        except Exception as exc:
            raise VaultAuthError(
                self._base_url, f"sync failed: {exc}"
            ) from exc

        # Search ciphers for matching name (decrypt each name to compare)
        ciphers = sync_data.get("ciphers", [])
        for cipher in ciphers:
            name = self._decrypt(cipher.get("name"))
            if name != path:
                continue

            # For login items, return the decrypted password
            login = cipher.get("login")
            if login:
                password = self._decrypt(login.get("password"))
                if password:
                    return password

            # For secure note items, return the decrypted notes
            notes = self._decrypt(cipher.get("notes"))
            if notes:
                return notes

        raise SecretNotFoundError(path)


def get_vault_secret(path: str) -> str:
    """Retrieve a secret from Vaultwarden by path.

    This is the high-level convenience function.
    Path format: {project}/{tenant_slug}/{secret_name}
    """
    client = VaultClient.connect()
    return client.get_secret(path)
