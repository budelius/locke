"""Tests for Vaultwarden client helpers."""

import logging
from unittest.mock import Mock

import locke
from locke.vault import PLACEHOLDER_VALUE, VaultClient, is_placeholder


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
