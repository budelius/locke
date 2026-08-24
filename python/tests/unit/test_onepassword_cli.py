"""Tests for ``locke onepassword`` commands."""

from unittest.mock import Mock, patch

from click.testing import CliRunner

from locke.cli.main import cli
from locke.onepassword import OnePasswordItem


def test_onepassword_set_prompts_and_never_echoes_password():
    client = Mock()
    client.set_secret_pair.return_value = "created"

    with patch("locke.onepassword.OnePasswordClient.connect", return_value=client):
        result = CliRunner().invoke(
            cli,
            [
                "onepassword",
                "set",
                "obachan/prod/users/user@example.com",
                "--account",
                "account.example",
                "--vault",
                "Mail",
                "--username",
                "user@example.com",
                "--url",
                "https://mail.example.com",
                "--setting",
                "imap_port=993",
            ],
            input="secret-value\n",
        )

    assert result.exit_code == 0, result.output
    assert "secret-value" not in result.output
    assert "created: obachan/prod/users/user@example.com" in result.output
    client.set_secret_pair.assert_called_once_with(
        "obachan/prod/users/user@example.com",
        "user@example.com",
        "secret-value",
        url="https://mail.example.com",
        settings={"imap_port": "993"},
    )


def test_onepassword_set_rejects_duplicate_settings_before_prompt():
    result = CliRunner().invoke(
        cli,
        [
            "onepassword",
            "set",
            "path",
            "--setting",
            "host=one",
            "--setting",
            "host=two",
        ],
    )

    assert result.exit_code == 2
    assert "duplicate --setting key" in result.output


def test_onepassword_get_settings_prints_only_non_secret_metadata():
    client = Mock()
    client.get_item.return_value = OnePasswordItem(
        title="path",
        username="user@example.com",
        password="secret-value",
        url="https://mail.example.com",
        settings={"host": "mail.example.com", "imap_port": "993"},
    )

    with patch("locke.onepassword.OnePasswordClient.connect", return_value=client):
        result = CliRunner().invoke(
            cli,
            ["onepassword", "get", "path", "--field", "settings"],
        )

    assert result.exit_code == 0, result.output
    assert "mail.example.com" in result.output
    assert "secret-value" not in result.output
