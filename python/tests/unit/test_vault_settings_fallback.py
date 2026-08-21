"""Vault connection settings resolve from the user-level settings file.

Covers the precedence contract: environment variable > ./.env > global config.
"""

import pytest

from locke import settings
from locke.errors import VaultAuthError
from locke.vault import VaultClient


def _global_settings(monkeypatch, tmp_path, body: str) -> None:
    target = tmp_path / "global-config.toml"
    target.write_text(body, encoding="utf-8")
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    settings.clear_cache()


def test_connection_setting_falls_back_to_global_settings(monkeypatch, tmp_path):
    """No env vars and no .env in cwd — the user-level config still resolves."""
    workdir = tmp_path / "worktree"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.delenv("LOCKE_VAULT_URL", raising=False)
    monkeypatch.delenv("LOCKE_VAULT_USERNAME", raising=False)
    _global_settings(
        monkeypatch,
        tmp_path,
        'vault_url = "https://from-global.example"\nvault_email = "ops@example.com"\n',
    )

    assert (
        VaultClient._connection_setting("LOCKE_VAULT_URL")
        == "https://from-global.example"
    )
    assert VaultClient._connection_setting("LOCKE_VAULT_USERNAME") == "ops@example.com"


def test_environ_beats_global_settings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LOCKE_VAULT_URL", "https://from-env.example")
    _global_settings(
        monkeypatch, tmp_path, 'vault_url = "https://from-global.example"\n'
    )

    assert (
        VaultClient._connection_setting("LOCKE_VAULT_URL") == "https://from-env.example"
    )


def test_dotenv_beats_global_settings(monkeypatch, tmp_path):
    workdir = tmp_path / "project"
    workdir.mkdir()
    (workdir / ".env").write_text("LOCKE_VAULT_URL=https://from-dotenv.example\n")
    monkeypatch.chdir(workdir)
    monkeypatch.delenv("LOCKE_VAULT_URL", raising=False)
    _global_settings(
        monkeypatch, tmp_path, 'vault_url = "https://from-global.example"\n'
    )

    assert (
        VaultClient._connection_setting("LOCKE_VAULT_URL")
        == "https://from-dotenv.example"
    )


def test_global_settings_apply_in_production(monkeypatch, tmp_path):
    """Unlike ./.env, the user-level config is deliberate and is honoured in prod."""
    workdir = tmp_path / "prod"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.delenv("LOCKE_VAULT_URL", raising=False)
    monkeypatch.setenv("LOCKE_ENV", "production")
    _global_settings(
        monkeypatch, tmp_path, 'vault_url = "https://from-global.example"\n'
    )

    assert (
        VaultClient._connection_setting("LOCKE_VAULT_URL")
        == "https://from-global.example"
    )


def test_connect_error_names_every_source_and_the_fix(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOCKE_VAULT_URL", raising=False)

    with pytest.raises(VaultAuthError) as excinfo:
        VaultClient.connect()

    message = str(excinfo.value)
    assert "LOCKE_VAULT_URL is not set" in message
    assert ".env" in message
    assert "locke config set vault_url" in message
