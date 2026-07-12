"""Tests for Vaultwarden client helpers."""

import logging
from unittest.mock import Mock

import pytest

import locke
from locke.errors import SecretNotFoundError
from locke.vault import (
    PLACEHOLDER_VALUE,
    CredentialPair,
    VaultClient,
    is_placeholder,
)


def test_placeholder_helpers_are_exported():
    assert PLACEHOLDER_VALUE == "FILL_ME"
    assert is_placeholder("FILL_ME")
    assert is_placeholder("  FILL_ME  ")
    assert not is_placeholder("real-secret")
    assert locke.PLACEHOLDER_VALUE == "FILL_ME"
    assert locke.is_placeholder("FILL_ME")


def test_get_secret_warns_for_placeholder(caplog):
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    client._secrets = {"proj/dev/api_key": PLACEHOLDER_VALUE}

    with caplog.at_level(logging.WARNING, logger="locke.vault"):
        assert client.get_secret("proj/dev/api_key") == PLACEHOLDER_VALUE

    assert "still a placeholder" in caplog.text


def test_set_secret_empty_value_writes_placeholder(monkeypatch, caplog):
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    client._secrets = {}
    captured = {}

    monkeypatch.setattr(
        client,
        "_cipher_index",
        lambda: {"names": {}, "folders": {"proj/dev": "folder-id"}, "metadata": {}},
    )
    monkeypatch.setattr(client, "_resolve_folder_id", lambda folder, index: "folder-id")

    def fake_payload(path, value, folder_id, username=None, uri=None, notes=None):
        captured.update({"path": path, "value": value, "folder_id": folder_id})
        return {"payload": True}

    monkeypatch.setattr(client, "_build_cipher_payload", fake_payload)

    response = Mock()
    response.raise_for_status = Mock()
    post = Mock(return_value=response)
    monkeypatch.setattr("locke.vault.httpx.post", post)

    with caplog.at_level(logging.WARNING, logger="locke.vault"):
        action = client.set_secret("proj/dev/api_key", "")

    assert action == "created"
    assert captured == {
        "path": "proj/dev/api_key",
        "value": PLACEHOLDER_VALUE,
        "folder_id": "folder-id",
    }
    assert client._secrets["proj/dev/api_key"] == PLACEHOLDER_VALUE
    assert "written with placeholder" in caplog.text


def test_credential_pair_is_exported():
    assert locke.CredentialPair is CredentialPair
    pair = CredentialPair(username="admin", password="s3cret")
    assert pair.username == "admin"
    assert pair.password == "s3cret"
    # NamedTuple ordering: (username, password)
    assert tuple(pair) == ("admin", "s3cret")


def test_get_secret_pair_returns_both_fields():
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    client._secrets = {"proj/dev/db_login": "s3cret"}
    client._metadata = {
        "proj/dev/db_login": {"username": "admin", "uri": None, "notes": None}
    }

    pair = client.get_secret_pair("proj/dev/db_login")

    assert isinstance(pair, CredentialPair)
    assert pair.username == "admin"
    assert pair.password == "s3cret"


def test_get_secret_pair_missing_username_is_none():
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    client._secrets = {"proj/dev/api_key": "value"}
    client._metadata = {
        "proj/dev/api_key": {"username": None, "uri": None, "notes": None}
    }

    pair = client.get_secret_pair("proj/dev/api_key")

    assert pair.username is None
    assert pair.password == "value"


def test_get_secret_pair_unknown_path_raises():
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    client._secrets = {}
    client._metadata = {}

    with pytest.raises(SecretNotFoundError):
        client.get_secret_pair("proj/dev/missing")


def test_set_secret_pair_writes_username_and_password(monkeypatch):
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    captured = {}

    def fake_set_secret(path, value=None, *, folder=None, username=None, uri=None, notes=None):
        captured.update(
            {"path": path, "value": value, "folder": folder, "username": username,
             "uri": uri, "notes": notes}
        )
        return "created"

    monkeypatch.setattr(client, "set_secret", fake_set_secret)

    action = client.set_secret_pair("proj/dev/db_login", "admin", "s3cret")

    assert action == "created"
    assert captured["path"] == "proj/dev/db_login"
    assert captured["username"] == "admin"
    assert captured["value"] == "s3cret"


def test_set_secret_pair_refreshes_metadata_cache(monkeypatch):
    """set_secret keeps the username discoverable via get_secret_pair afterwards."""
    client = VaultClient("https://vault.example", "token", b"e" * 32, b"m" * 32)
    client._secrets = {}
    client._metadata = {}

    monkeypatch.setattr(
        client,
        "_cipher_index",
        lambda: {"names": {}, "folders": {"proj/dev": "fid"}, "metadata": {}},
    )
    monkeypatch.setattr(client, "_resolve_folder_id", lambda folder, index: "fid")
    monkeypatch.setattr(
        client, "_build_cipher_payload",
        lambda *a, **k: {"payload": True},
    )
    response = Mock()
    response.raise_for_status = Mock()
    monkeypatch.setattr("locke.vault.httpx.post", Mock(return_value=response))

    client.set_secret_pair("proj/dev/db_login", "admin", "s3cret")

    pair = client.get_secret_pair("proj/dev/db_login")
    assert pair.username == "admin"
    assert pair.password == "s3cret"


def test_connection_setting_prefers_environ(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("LOCKE_VAULT_URL=https://from-dotenv.example\n")
    monkeypatch.setenv("LOCKE_VAULT_URL", "https://from-env.example")

    assert VaultClient._connection_setting("LOCKE_VAULT_URL") == "https://from-env.example"


def test_connection_setting_falls_back_to_dotenv(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "LOCKE_VAULT_URL=https://from-dotenv.example\n"
        "LOCKE_VAULT_USERNAME=vault-user\n"
    )
    monkeypatch.delenv("LOCKE_VAULT_URL", raising=False)
    monkeypatch.delenv("LOCKE_VAULT_USERNAME", raising=False)

    assert VaultClient._connection_setting("LOCKE_VAULT_URL") == "https://from-dotenv.example"
    assert VaultClient._connection_setting("LOCKE_VAULT_USERNAME") == "vault-user"


def test_connection_setting_ignores_dotenv_in_production(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("LOCKE_VAULT_URL=https://from-dotenv.example\n")
    monkeypatch.delenv("LOCKE_VAULT_URL", raising=False)
    monkeypatch.setenv("LOCKE_ENV", "production")

    assert VaultClient._connection_setting("LOCKE_VAULT_URL") is None
