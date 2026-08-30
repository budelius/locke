"""Tests for the global (per-user) Locke settings file."""

import logging
import sys
from pathlib import Path

import pytest

from locke import settings


@pytest.fixture(autouse=True)
def _isolate_settings(monkeypatch, tmp_path):
    """Point settings discovery at a temp dir and clear the cache."""
    monkeypatch.delenv(settings.SETTINGS_FILE_VAR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    settings.clear_cache()
    yield
    settings.clear_cache()


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    settings.clear_cache()


# ---------------------------------------------------------------------------
# Path discovery
# ---------------------------------------------------------------------------


def test_explicit_file_var_wins(tmp_path, monkeypatch):
    explicit = tmp_path / "elsewhere" / "locke.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(explicit))
    settings.clear_cache()
    assert settings.settings_path() == explicit


def test_default_path_is_platform_native(tmp_path):
    path = settings.settings_path()
    assert path.name == "config.toml"
    assert path.parent.name == "locke"
    if sys.platform == "win32":
        assert path.parent.parent == tmp_path / "appdata"
    else:
        assert path.parent.parent == tmp_path / "xdg"


def test_existing_xdg_file_is_preferred_over_unwritten_native(tmp_path):
    """A file the operator already created is used even off the native path."""
    xdg_file = tmp_path / "xdg" / "locke" / "config.toml"
    _write(xdg_file, 'vault_url = "https://vault.example"\n')
    assert settings.settings_path() == xdg_file


def test_home_dotconfig_is_searched(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    home_file = tmp_path / "home" / ".config" / "locke" / "config.toml"
    _write(home_file, 'vault_url = "https://vault.example"\n')
    assert settings.settings_path() == home_file


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_missing_file_yields_empty_settings(tmp_path):
    assert settings.load_settings() == {}
    assert settings.get_setting("LOCKE_VAULT_URL") is None


def test_reads_vault_url_and_email(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(
        tmp_path / "config.toml",
        'vault_url = "https://vault.example"\nvault_email = "ops@example.com"\n',
    )
    assert settings.get_setting("LOCKE_VAULT_URL") == "https://vault.example"
    assert settings.get_setting("LOCKE_VAULT_USERNAME") == "ops@example.com"


def test_vault_username_is_an_accepted_alias(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(tmp_path / "config.toml", 'vault_username = "ops@example.com"\n')
    assert settings.get_setting("LOCKE_VAULT_USERNAME") == "ops@example.com"


def test_reads_onepassword_account_and_vault(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(
        tmp_path / "config.toml",
        'onepassword_account = "my.1password.com"\nonepassword_vault = "Mail"\n',
    )
    assert settings.get_setting("LOCKE_ONEPASSWORD_ACCOUNT") == "my.1password.com"
    assert settings.get_setting("LOCKE_ONEPASSWORD_VAULT") == "Mail"


def test_unknown_setting_name_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(tmp_path / "config.toml", 'vault_url = "https://vault.example"\n')
    assert settings.get_setting("LOCKE_NOT_A_SETTING") is None


def test_malformed_toml_is_not_fatal(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(tmp_path / "config.toml", "vault_url = not-a-toml-string\n")
    with caplog.at_level(logging.WARNING, logger="locke.settings"):
        assert settings.load_settings() == {}
    assert "could not be parsed" in caplog.text


def test_non_string_values_are_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(tmp_path / "config.toml", "vault_url = 42\n")
    assert settings.get_setting("LOCKE_VAULT_URL") is None


def test_secret_keys_are_refused(tmp_path, monkeypatch, caplog):
    """The settings file is plaintext — it must never serve a password."""
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    _write(
        tmp_path / "config.toml",
        'vault_url = "https://vault.example"\nvault_password = "hunter2"\n',
    )
    with caplog.at_level(logging.WARNING, logger="locke.settings"):
        loaded = settings.load_settings()
    assert "vault_password" not in loaded
    assert loaded["vault_url"] == "https://vault.example"
    assert "vault_password" in caplog.text
    assert "keystore" in caplog.text


def test_cache_is_invalidated_when_the_file_changes(tmp_path, monkeypatch):
    target = tmp_path / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    _write(target, 'vault_url = "https://one.example"\n')
    assert settings.get_setting("LOCKE_VAULT_URL") == "https://one.example"
    _write(target, 'vault_url = "https://two.example"\n')
    assert settings.get_setting("LOCKE_VAULT_URL") == "https://two.example"


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def test_set_setting_creates_and_updates_the_file(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    settings.clear_cache()

    settings.set_setting("vault_url", "https://vault.example")
    settings.set_setting("vault_email", "ops@example.com")
    settings.set_setting("onepassword_account", "my.1password.com")
    settings.set_setting("onepassword_vault", "Mail")

    assert target.is_file()
    assert settings.get_setting("LOCKE_VAULT_URL") == "https://vault.example"
    assert settings.get_setting("LOCKE_VAULT_USERNAME") == "ops@example.com"
    assert settings.get_setting("LOCKE_ONEPASSWORD_ACCOUNT") == "my.1password.com"
    assert settings.get_setting("LOCKE_ONEPASSWORD_VAULT") == "Mail"

    settings.set_setting("vault_url", "https://other.example")
    assert settings.get_setting("LOCKE_VAULT_URL") == "https://other.example"


def test_set_setting_rejects_unknown_keys(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    settings.clear_cache()
    with pytest.raises(ValueError, match="not a known Locke setting"):
        settings.set_setting("nope", "value")


def test_set_setting_rejects_secret_keys(tmp_path, monkeypatch):
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(tmp_path / "config.toml"))
    settings.clear_cache()
    with pytest.raises(ValueError, match="keystore"):
        settings.set_setting("vault_password", "hunter2")


def test_written_file_round_trips_special_characters(tmp_path, monkeypatch):
    target = tmp_path / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    settings.clear_cache()
    tricky = 'https://vault.example/a"b\\c'
    settings.set_setting("vault_url", tricky)
    assert settings.get_setting("LOCKE_VAULT_URL") == tricky


def test_set_setting_keeps_other_known_keys(tmp_path, monkeypatch):
    """Rewriting keeps every known key already in the file."""
    target = tmp_path / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    _write(target, 'vault_email = "ops@example.com"\n')
    settings.set_setting("vault_url", "https://vault.example")
    assert settings.get_setting("LOCKE_VAULT_USERNAME") == "ops@example.com"
    assert settings.get_setting("LOCKE_VAULT_URL") == "https://vault.example"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes only")
def test_written_file_is_user_only(tmp_path, monkeypatch):
    target = tmp_path / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    settings.clear_cache()
    settings.set_setting("vault_url", "https://vault.example")
    assert target.stat().st_mode & 0o077 == 0


def test_set_setting_preserves_keys_this_build_does_not_know(tmp_path, monkeypatch):
    """A rewrite must not delete settings a newer Locke wrote.

    `set_setting` renders the file from scratch. Emitting only KNOWN_KEYS meant
    an older build silently dropped every key a newer one had added, and the
    loss surfaced later as an unrelated command losing its configuration.
    """
    target = tmp_path / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    _write(target, 'from_a_newer_locke = "keep-me"\n')

    settings.set_setting("vault_url", "https://vault.example")

    settings.clear_cache()
    loaded = settings.load_settings()
    assert loaded["from_a_newer_locke"] == "keep-me"
    assert loaded["vault_url"] == "https://vault.example"


def test_set_setting_still_drops_a_secret_someone_hand_wrote(tmp_path, monkeypatch):
    """Preserving unknown keys must not preserve secrets.

    The file is plaintext, so a password found in it is dropped on rewrite
    rather than faithfully copied forward.
    """
    target = tmp_path / "config.toml"
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    _write(target, 'vault_password = "hunter2"\nfrom_a_newer_locke = "keep-me"\n')

    settings.set_setting("vault_url", "https://vault.example")

    body = target.read_text(encoding="utf-8")
    assert "hunter2" not in body
    assert "keep-me" in body
