"""Tests for project-root genkeys and JSONC conversion commands."""

import json
import os
from pathlib import Path

from click.testing import CliRunner

from locke.cli.project_tools import genkeys, strip_jsonc_command


def test_genkeys_reads_project_root_dotenv_from_nested_directory(monkeypatch):
    runner = CliRunner()

    with runner.isolated_filesystem():
        root = Path.cwd()
        (root / ".env").write_text(
            "LOCKE_INPUT_DIR=shared-configs\n"
            "LOCKE_OUTPUT_DIR=.locke\n"
            "LOCKE_KEY_NAME=PROJECT_CONFIG_KEY\n",
            encoding="utf-8",
        )
        configs = root / "shared-configs"
        configs.mkdir()
        (configs / "config.development.jsonc").write_text(
            '{\n  // retained configuration\n  "api": {"url": "https://example.test",},\n}\n',
            encoding="utf-8",
        )
        nested = root / "src" / "worker"
        nested.mkdir(parents=True)
        os.chdir(nested)
        monkeypatch.setenv("PROJECT_CONFIG_KEY", "test-passphrase")

        try:
            result = runner.invoke(genkeys, ["--key-source", "env"])
        finally:
            os.chdir(root)

        assert result.exit_code == 0, result.output
        encrypted_path = root / ".locke" / "config.encrypted.development.json"
        assert encrypted_path.is_file()
        encrypted = json.loads(encrypted_path.read_text(encoding="utf-8"))
        assert encrypted["version"] == 2
        assert "Encrypted 1 config(s)." in result.output


def test_genkeys_requires_input_dir_setting():
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path(".env").write_text("LOCKE_KEY_NAME=PROJECT_CONFIG_KEY\n", encoding="utf-8")
        result = runner.invoke(genkeys)

    assert result.exit_code != 0
    assert "LOCKE_INPUT_DIR is not set" in result.output


def test_strip_jsonc_command_writes_strict_json():
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("input.jsonc").write_text(
            '{\n  // comment\n  "url": "https://example.test",\n}\n',
            encoding="utf-8",
        )

        result = runner.invoke(
            strip_jsonc_command, ["input.jsonc", "generated/output.json"]
        )

        assert result.exit_code == 0, result.output
        assert json.loads(Path("generated/output.json").read_text(encoding="utf-8")) == {
            "url": "https://example.test"
        }
