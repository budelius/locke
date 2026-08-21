"""Tests for locke.crypto — AES-256-GCM encrypt/decrypt with PBKDF2-SHA256 KDF."""

import json
import warnings

import pytest

from locke.crypto import decode_key, decrypt_config, encrypt_config
from locke.errors import DecryptionError, InvalidConfigError, InvalidKeyError
from tests.conftest import load_test_vectors

VECTORS = load_test_vectors("encrypt-decrypt.json")["vectors"]


def _get_vector(name: str) -> dict:
    return next(v for v in VECTORS if v["name"] == name)


class TestDecodeKey:
    def test_hex_key(self):
        key = "aa" * 32
        result = decode_key(key)
        assert len(result) == 32
        assert result == bytes.fromhex(key)

    def test_base64_key(self):
        import base64
        raw = b"\xaa" * 32
        b64 = base64.b64encode(raw).decode()
        result = decode_key(b64)
        assert len(result) == 32
        assert result == raw

    def test_invalid_key_raises(self):
        with pytest.raises(InvalidKeyError):
            decode_key("tooshort")


class TestDecryptConfig:
    def test_basic_decrypt_hex_key(self):
        vec = _get_vector("basic-decrypt-hex-key")
        result = decrypt_config(vec["encrypted_config"], vec["key_hex"])
        expected = json.loads(vec["plaintext_json"])
        assert result == expected

    def test_unknown_version_warns(self):
        vec = _get_vector("unknown-version-best-effort")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = decrypt_config(vec["encrypted_config"], vec["key_hex"])
            assert len(w) == 1
            assert "version 99" in str(w[0].message)
        expected = json.loads(vec["plaintext_json"])
        assert result == expected

    def test_wrong_key_raises(self):
        vec = _get_vector("wrong-key-fails")
        with pytest.raises(DecryptionError):
            decrypt_config(vec["encrypted_config"], vec["key_hex"])

    def test_missing_field_raises(self):
        with pytest.raises(InvalidConfigError, match="missing field"):
            decrypt_config({"version": 2}, "aa" * 32)

    def test_unsupported_algorithm_raises(self):
        config = {
            "version": 2,
            "algorithm": "aes-128-cbc",
            "kdf": "pbkdf2",
            "salt": "dGVzdA==",
            "iv": "dGVzdA==",
            "authTag": "dGVzdA==",
            "ciphertext": "dGVzdA==",
        }
        with pytest.raises(InvalidConfigError, match="unsupported algorithm"):
            decrypt_config(config, "aa" * 32)

    def test_unsupported_kdf_raises(self):
        config = {
            "version": 2,
            "algorithm": "aes-256-gcm",
            "kdf": "scrypt",
            "salt": "dGVzdA==",
            "iv": "dGVzdA==",
            "authTag": "dGVzdA==",
            "ciphertext": "dGVzdA==",
        }
        with pytest.raises(InvalidConfigError, match="unsupported KDF"):
            decrypt_config(config, "aa" * 32)


class TestEncryptConfig:
    def test_round_trip(self):
        vec = _get_vector("round-trip")
        encrypted = encrypt_config(vec["plaintext"], vec["key_hex"])

        assert encrypted["version"] == 2
        assert encrypted["algorithm"] == "aes-256-gcm"
        assert encrypted["kdf"] == "pbkdf2"
        assert encrypted["kdfIterations"] == 100_000

        decrypted = decrypt_config(encrypted, vec["key_hex"])
        assert decrypted == vec["plaintext"]

    def test_encrypt_produces_required_fields(self):
        encrypted = encrypt_config({"key": "value"}, "aa" * 32)
        for field in ("version", "algorithm", "kdf", "kdfIterations", "salt", "iv", "authTag", "ciphertext"):
            assert field in encrypted

    def test_different_encryptions_differ(self):
        """Random salt/IV means two encryptions of the same data differ."""
        plaintext = {"test": "data"}
        key = "aa" * 32
        enc1 = encrypt_config(plaintext, key)
        enc2 = encrypt_config(plaintext, key)
        assert enc1["ciphertext"] != enc2["ciphertext"]
