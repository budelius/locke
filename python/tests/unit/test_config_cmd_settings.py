"""Tests for `locke config path|show|set`."""

from click.testing import CliRunner

from locke import settings
from locke.cli.main import cli


def _point_at(monkeypatch, target) -> None:
    monkeypatch.setenv(settings.SETTINGS_FILE_VAR, str(target))
    settings.clear_cache()


def test_config_path_prints_the_target(monkeypatch, tmp_path):
    target = tmp_path / "config.toml"
    _point_at(monkeypatch, target)

    result = CliRunner().invoke(cli, ["config", "path"])

    assert result.exit_code == 0
    assert result.output.strip() == str(target)


def test_config_set_then_show_round_trips(monkeypatch, tmp_path):
    target = tmp_path / "config.toml"
    _point_at(monkeypatch, target)

    runner = CliRunner()
    assert runner.invoke(
        cli, ["config", "set", "vault_url", "https://vault.example"]
    ).exit_code == 0
    assert runner.invoke(
        cli, ["config", "set", "vault_email", "ops@example.com"]
    ).exit_code == 0
    assert runner.invoke(
        cli, ["config", "set", "onepassword_account", "my.1password.com"]
    ).exit_code == 0
    assert runner.invoke(
        cli, ["config", "set", "onepassword_vault", "Mail"]
    ).exit_code == 0

    result = runner.invoke(cli, ["config", "show"])

    assert result.exit_code == 0
    assert "vault_url = https://vault.example" in result.output
    assert "vault_email = ops@example.com" in result.output
    assert "onepassword_account = my.1password.com" in result.output
    assert "onepassword_vault = Mail" in result.output


def test_config_set_refuses_a_password(monkeypatch, tmp_path):
    target = tmp_path / "config.toml"
    _point_at(monkeypatch, target)

    result = CliRunner().invoke(cli, ["config", "set", "vault_password", "hunter2"])

    assert result.exit_code == 1
    assert "keystore" in result.output
    assert not target.exists()


def test_config_set_refuses_an_unknown_key(monkeypatch, tmp_path):
    target = tmp_path / "config.toml"
    _point_at(monkeypatch, target)

    result = CliRunner().invoke(cli, ["config", "set", "nope", "value"])

    assert result.exit_code == 1
    assert "not a known Locke setting" in result.output


def test_config_show_without_a_file_is_not_an_error(monkeypatch, tmp_path):
    _point_at(monkeypatch, tmp_path / "absent.toml")

    result = CliRunner().invoke(cli, ["config", "show"])

    assert result.exit_code == 0
    assert "no settings file" in result.output
