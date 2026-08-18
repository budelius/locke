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
from typing import NamedTuple

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from locke.env import is_production
from locke.errors import SecretNotFoundError, VaultAuthError
from locke.pipeline import _resolve_from_dotenv, resolve_credential
from locke.settings import get_setting, settings_path

logger = logging.getLogger(__name__)

# Vaultwarden connection env vars
VAULT_URL_VAR = "LOCKE_VAULT_URL"
VAULT_USERNAME_VAR = "LOCKE_VAULT_USERNAME"
VAULT_PASSWORD_CREDENTIAL = "LOCKE_VAULT_PASSWORD"

# Locke-owned placeholder convention for intentionally unfilled vault secrets.
PLACEHOLDER_VALUE = "FILL_ME"
PLACEHOLDER_VALUES = frozenset({PLACEHOLDER_VALUE})


def is_placeholder(value: str | None) -> bool:
    """Return True when *value* is a Locke vault placeholder."""
    return value is not None and value.strip() in PLACEHOLDER_VALUES


class CredentialPair(NamedTuple):
    """A username + password retrieved from a single vault entry.

    Bitwarden login ciphers natively carry both a ``username`` and a
    ``password`` field. Storing a credential as one entry (rather than two
    separate secrets) keeps the pair together and lets callers fetch both in
    a single round-trip via :meth:`VaultClient.get_secret_pair`.

    ``username`` is ``None`` when the entry has no username set; ``password``
    is the empty string when only a username is stored.
    """

    username: str | None
    password: str


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
        raise ValueError("invalid encrypted string format: no type prefix")
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
    except Exception as exc:  # noqa: BLE001 -- server-supplied ciphertext, any codec error is "undecryptable"
        logger.debug("Failed to decrypt cipher field: %s", exc)
        return None


def _unset_message(var_name: str, settings_key: str) -> str:
    """Explain every place the setting could have come from, and how to fix it."""
    return (
        f"{var_name} is not set: no environment variable, no .env in the current "
        f"directory, and no '{settings_key}' in {settings_path()}. "
        f"Set it once for every directory with: locke config set {settings_key} <value>"
    )


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
        # path -> plaintext value, populated on first sync().
        self._secrets: dict[str, str] | None = None
        # path -> {"username", "uri", "notes"}, populated on first sync().
        self._metadata: dict[str, dict[str, str | None]] | None = None

    @staticmethod
    def _connection_setting(var_name: str) -> str | None:
        """Resolve a vault connection setting (URL / username).

        Precedence: process environment > ./.env (dev/staging only) > the
        user-level settings file. The .env step keeps `locke vault …` working
        from a project directory without exporting anything; the settings file
        makes it work from *any* directory, including a git worktree that has
        no .env of its own. The master password is NOT read here — it always
        goes through resolve_credential() (keystore-first).
        """
        value = os.environ.get(var_name)
        if value:
            return value
        if not is_production():
            value = _resolve_from_dotenv(var_name)
            if value:
                return value
        return get_setting(var_name)

    @classmethod
    def connect(cls) -> "VaultClient":
        """Create an authenticated vault client using pipeline-resolved credentials."""
        base_url = cls._connection_setting(VAULT_URL_VAR)
        if not base_url:
            raise VaultAuthError("unknown", _unset_message(VAULT_URL_VAR, "vault_url"))

        username = cls._connection_setting(VAULT_USERNAME_VAR)
        if not username:
            raise VaultAuthError(
                base_url, _unset_message(VAULT_USERNAME_VAR, "vault_email")
            )

        password_cred = resolve_credential(VAULT_PASSWORD_CREDENTIAL)

        return cls.connect_with(base_url, username, password_cred.value)

    @classmethod
    def connect_with(
        cls, base_url: str, username: str, password: str,
    ) -> "VaultClient":
        """Create an authenticated vault client using explicit credentials.

        Use this when you need to authenticate against the same Vaultwarden
        with a different account than the one Locke's credential pipeline
        would resolve (e.g. a second vault user whose password is itself
        stored in the first user's vault). ``connect()`` always reads the
        master password through ``resolve_credential()``, which prefers the
        OS keystore over env vars — this method skips that lookup entirely.
        """
        if not base_url:
            raise VaultAuthError(
                "unknown", "empty base_url passed to connect_with()",
            )
        if not username:
            raise VaultAuthError(
                base_url, "empty username passed to connect_with()",
            )

        # Authenticate via Bitwarden Identity API
        token, encrypted_key = cls._authenticate(base_url, username, password)

        # Derive master key and decrypt the symmetric key
        master_key = _make_master_key(password, username)
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

    def _sync_data(self) -> dict:
        """Return raw ``/api/sync`` data from Vaultwarden."""
        try:
            response = httpx.get(
                f"{self._base_url}/api/sync",
                headers=self._headers,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            raise VaultAuthError(
                self._base_url,
                f"sync failed with HTTP {exc.response.status_code} (token may be expired)",
            ) from exc
        except Exception as exc:
            raise VaultAuthError(
                self._base_url, f"sync failed: {exc}"
            ) from exc

    def _cipher_index(self) -> dict:
        """Return decrypted lookup maps for ciphers and folders."""
        sync_data = self._sync_data()

        names: dict[str, str] = {}
        values: dict[str, str] = {}
        metadata: dict[str, dict[str, str | None]] = {}
        for cipher in sync_data.get("ciphers", []):
            name = self._decrypt(cipher.get("name"))
            if not name:
                continue
            names[name] = cipher["id"]
            login = cipher.get("login") or {}
            username = self._decrypt(login.get("username"))
            uri = None
            uris = login.get("uris") or []
            if uris:
                uri = self._decrypt(uris[0].get("uri"))
            notes = self._decrypt(cipher.get("notes"))
            value = self._decrypt(login.get("password")) or notes
            if value is not None:
                if is_placeholder(value):
                    logger.warning("Vault secret %s is still a placeholder", name)
                values[name] = value
            metadata[name] = {"username": username, "uri": uri, "notes": notes}

        folders: dict[str, str] = {}
        for folder in sync_data.get("folders", []):
            name = self._decrypt(folder.get("name"))
            if name:
                folders[name] = folder["id"]

        return {"names": names, "folders": folders, "values": values, "metadata": metadata}

    def sync(self, force_refresh: bool = False) -> dict[str, str]:
        """Fetch and decrypt every cipher in one ``/api/sync`` round-trip.

        Bulk-decrypts all logins/notes into a ``{plaintext_name: value}``
        dict, caches it on the instance, and returns it. Subsequent calls
        return the cached dict unless *force_refresh* is set.

        Use this instead of repeated :meth:`get_secret` calls when fetching
        many secrets — Vaultwarden rate-limits ``/identity/connect/token``
        and ``/api/sync``, and a single decrypted snapshot is enough to
        serve every lookup for the lifetime of this client.

        ``value`` is the cipher's ``login.password`` for login items and
        ``notes`` for secure-note items. Ciphers with neither (or whose
        name fails to decrypt) are skipped.
        """
        if self._secrets is not None and not force_refresh:
            return self._secrets

        index = self._cipher_index()
        self._secrets = index["values"]
        self._metadata = index["metadata"]
        return self._secrets

    def list_secrets(self, prefix: str = "") -> dict[str, str]:
        """Return cached secrets whose plaintext name starts with *prefix*.

        Calls :meth:`sync` if the cache is empty. Pass an empty string to
        get every secret in the vault.
        """
        if self._secrets is None:
            self.sync()
        if not prefix:
            return dict(self._secrets)
        return {k: v for k, v in self._secrets.items() if k.startswith(prefix)}

    def _resolve_folder_id(self, folder_name: str | None, index: dict) -> str | None:
        """Return an existing or newly-created folder id."""
        if not folder_name:
            return None
        folder_id = index["folders"].get(folder_name)
        if folder_id:
            return folder_id

        response = httpx.post(
            f"{self._base_url}/api/folders",
            headers=self._headers,
            json={"name": self._encrypt(folder_name)},
            timeout=30,
        )
        response.raise_for_status()
        folder_id = response.json()["id"]
        index["folders"][folder_name] = folder_id
        return folder_id

    def _build_cipher_payload(
        self,
        path: str,
        value: str,
        folder_id: str | None,
        username: str | None = None,
        uri: str | None = None,
        notes: str | None = None,
    ) -> dict:
        """Build an encrypted Bitwarden login cipher payload.

        Kept on the library client so programmatic writes use the same JSON
        shape as ``locke vault import``.
        """
        encrypted_uri = self._encrypt(uri)
        uris = [{"match": None, "uri": encrypted_uri}] if encrypted_uri else []
        return {
            "type": 1,
            "name": self._encrypt(path),
            "folderId": folder_id,
            "login": {
                "username": self._encrypt(username),
                "password": self._encrypt(value),
                "uris": uris,
            },
            "notes": self._encrypt(notes),
            "favorite": False,
            "reprompt": 0,
        }

    def _cipher_payload(
        self,
        path: str,
        value: str,
        folder_id: str | None,
        username: str | None = None,
        uri: str | None = None,
        notes: str | None = None,
    ) -> dict:
        """Backward-compatible alias for _build_cipher_payload()."""
        return self._build_cipher_payload(path, value, folder_id, username, uri, notes)

    def set_secret(
        self,
        path: str,
        value: str | None = None,
        *,
        folder: str | None = None,
        username: str | None = None,
        uri: str | None = None,
        notes: str | None = None,
    ) -> str:
        """Create or update a Vaultwarden secret by path.

        ``path`` is the plaintext cipher name (for example
        ``"myproject/staging/api_key"``). By default the folder is derived
        from the path prefix before the final slash; pass ``folder=None`` for
        that behavior or ``folder=""`` to leave the item unfiled.

        Returns ``"created"`` or ``"updated"``.
        """
        if not path:
            raise ValueError("path must not be empty")
        if value is None or value == "":
            value = PLACEHOLDER_VALUE
            logger.warning("Vault secret %s written with placeholder value", path)
        elif is_placeholder(value):
            logger.warning("Vault secret %s written with placeholder value", path)

        index = self._cipher_index()
        folder_name = path.rpartition("/")[0] if folder is None else folder
        folder_id = self._resolve_folder_id(folder_name, index)
        cipher_id = index["names"].get(path)

        if cipher_id:
            current = index.get("metadata", {}).get(path, {})
            payload = self._build_cipher_payload(
                path,
                value,
                folder_id,
                username=username if username is not None else current.get("username"),
                uri=uri if uri is not None else current.get("uri"),
                notes=notes if notes is not None else current.get("notes"),
            )
            response = httpx.put(
                f"{self._base_url}/api/ciphers/{cipher_id}",
                headers=self._headers,
                json=payload,
                timeout=30,
            )
            action = "updated"
        else:
            payload = self._build_cipher_payload(path, value, folder_id, username, uri, notes)
            response = httpx.post(
                f"{self._base_url}/api/ciphers",
                headers=self._headers,
                json=payload,
                timeout=30,
            )
            action = "created"

        response.raise_for_status()
        if self._secrets is not None:
            self._secrets[path] = value
        if self._metadata is not None:
            current = self._metadata.get(path, {})
            self._metadata[path] = {
                "username": username if username is not None else current.get("username"),
                "uri": uri if uri is not None else current.get("uri"),
                "notes": notes if notes is not None else current.get("notes"),
            }
        return action

    def get_secret(self, path: str) -> str:
        """Retrieve a secret by path (``{project}/{tenant}/{name}``).

        Reads from the in-memory snapshot populated by :meth:`sync`,
        which is called automatically on first access. To pick up writes
        made by another client during this client's lifetime, call
        ``sync(force_refresh=True)`` first.

        Raises :class:`SecretNotFoundError` if the path is not in the
        vault.
        """
        if self._secrets is None:
            self.sync()
        try:
            value = self._secrets[path]
            if is_placeholder(value):
                logger.warning("Vault secret %s is still a placeholder", path)
            return value
        except KeyError:
            raise SecretNotFoundError(path) from None

    def get_secret_pair(self, path: str) -> CredentialPair:
        """Retrieve a username + password stored in a single vault entry.

        Reads one login cipher and returns both its ``username`` and
        ``password`` fields as a :class:`CredentialPair`. Use this for
        credentials that pair a username with a password (database logins,
        SMTP accounts, …) instead of splitting them across two secrets.

        Reads from the in-memory snapshot populated by :meth:`sync` (called
        automatically on first access). Raises :class:`SecretNotFoundError`
        if no cipher with *path* exists.
        """
        if self._secrets is None or self._metadata is None:
            self.sync()
        meta = self._metadata.get(path)
        if meta is None and path not in self._secrets:
            raise SecretNotFoundError(path)
        password = self._secrets.get(path, "")
        if is_placeholder(password):
            logger.warning("Vault secret %s is still a placeholder", path)
        username = (meta or {}).get("username")
        return CredentialPair(username=username, password=password)

    def set_secret_pair(
        self,
        path: str,
        username: str | None,
        password: str | None = None,
        *,
        folder: str | None = None,
        uri: str | None = None,
        notes: str | None = None,
    ) -> str:
        """Create or update a single vault entry holding a username + password.

        Convenience wrapper around :meth:`set_secret` that writes both the
        ``username`` and ``password`` fields of one login cipher. Returns
        ``"created"`` or ``"updated"``.
        """
        return self.set_secret(
            path,
            password,
            folder=folder,
            username=username,
            uri=uri,
            notes=notes,
        )


def get_vault_secret(path: str) -> str:
    """Retrieve a secret from Vaultwarden by path.

    This is the high-level convenience function.
    Path format: {project}/{tenant_slug}/{secret_name}
    """
    client = VaultClient.connect()
    return client.get_secret(path)


def set_vault_secret(path: str, value: str | None = None, **kwargs) -> str:
    """Create or update a Vaultwarden secret by path.

    Returns ``"created"`` or ``"updated"``. Keyword arguments are forwarded
    to :meth:`VaultClient.set_secret` (``folder``, ``username``, ``uri``,
    ``notes``).
    """
    client = VaultClient.connect()
    return client.set_secret(path, value, **kwargs)


def get_vault_secret_pair(path: str) -> CredentialPair:
    """Retrieve a username + password stored in a single Vaultwarden entry.

    High-level convenience wrapper around
    :meth:`VaultClient.get_secret_pair`. Path format:
    ``{project}/{tenant_slug}/{secret_name}``.
    """
    client = VaultClient.connect()
    return client.get_secret_pair(path)


def set_vault_secret_pair(
    path: str, username: str | None, password: str | None = None, **kwargs
) -> str:
    """Create or update a single Vaultwarden entry holding a username + password.

    Returns ``"created"`` or ``"updated"``. Keyword arguments are forwarded
    to :meth:`VaultClient.set_secret_pair` (``folder``, ``uri``, ``notes``).
    """
    client = VaultClient.connect()
    return client.set_secret_pair(path, username, password, **kwargs)
