"""Tests for locke init registry updates."""

import json
from pathlib import Path

from click.testing import CliRunner

from locke.cli.init_cmd import init


def test_init_adds_vault_classified_env_keys_to_registry():
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path(".env").write_text(
            "SERVICE_API_KEY=secret\n"
            "APP_URL=https://localhost:3000\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            init,
            ["--project", "myapp", "--tenant", "dev", "--non-interactive"],
        )

        assert result.exit_code == 0

        locke_json = json.loads(Path(".locke/locke.json").read_text(encoding="utf-8"))
        assert (
            locke_json["keys"]["vault"]["myapp/dev/service_api_key"]
            == "Per-developer secret -> SERVICE_API_KEY"
        )

        refs = json.loads(Path(".locke/vault-references.json").read_text(encoding="utf-8"))
        assert {
            "path": "myapp/dev/service_api_key",
            "original_key": "SERVICE_API_KEY",
            "description": "Per-developer secret -> SERVICE_API_KEY",
        } in refs["secrets"]
